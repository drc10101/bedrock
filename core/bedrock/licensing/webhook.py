"""
Bedrock License Webhook Server — Receives Stripe events and issues license keys.

This is a standalone server meant to run alongside (or behind) the Bedrock API.
It listens for Stripe webhook events and:
1. Verifies the webhook signature
2. On checkout.session.completed: issues a Bedrock license key
3. Sends the license key to the customer via email

Environment variables:
- BEDROCK_STRIPE_SECRET_KEY: Stripe secret key
- BEDROCK_STRIPE_WEBHOOK_SECRET: Stripe webhook signing secret
- BEDROCK_SIGNING_KEY: HMAC key for signing Bedrock license keys
- WEBHOOK_PORT: Port to listen on (default 8444)
- SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS: Email delivery config

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import json
import os
import smtplib
import ssl
import time
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, HTTPServer

from bedrock.licensing.checkout import (
    LicenseDelivery,
    handle_checkout_completed,
    verify_webhook_signature,
)


class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler for Stripe webhook events."""

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[webhook] {time.strftime('%Y-%m-%d %H:%M:%S')} {fmt % args}")

    def do_POST(self) -> None:
        if self.path != "/webhook/stripe":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
            return

        # Read raw body
        content_length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(content_length)
        sig_header = self.headers.get("Stripe-Signature", "")

        # Verify and parse the event
        try:
            event = verify_webhook_signature(payload, sig_header)
        except ValueError as e:
            self.log_message("Webhook signature verification failed: %s", str(e))
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid signature"}).encode())
            return
        except Exception as e:
            self.log_message("Webhook parsing error: %s", str(e))
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid payload"}).encode())
            return

        event_type = event.get("type", "")

        # Handle checkout completion
        if event_type == "checkout.session.completed":
            try:
                delivery = handle_checkout_completed(event)
                self.log_message(
                    "License issued: tier=%s email=%s key=%s...%s",
                    delivery.tier,
                    delivery.customer_email,
                    delivery.license_key[:8],
                    delivery.license_key[-8:],
                )

                # Send license key via email
                try:
                    send_license_email(delivery)
                    self.log_message("License email sent to %s", delivery.customer_email)
                except Exception as email_err:
                    # Log but don't fail the webhook — key was issued
                    self.log_message("Email delivery failed: %s", str(email_err))

                self.send_response(200)
                self.end_headers()
                resp = {
                    "status": "issued",
                    "tier": delivery.tier,
                    "email": delivery.customer_email,
                    "expires_at": delivery.expires_at,
                }
                self.wfile.write(json.dumps(resp).encode())
                return

            except Exception as e:
                self.log_message("License issuance failed: %s", str(e))
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": "License issuance failed"}).encode())
                return

        # Acknowledge other event types
        self.log_message("Unhandled event type: %s", event_type)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ignored", "type": event_type}).encode())


def send_license_email(delivery: LicenseDelivery) -> None:
    """Send a license key delivery email.

    Uses SMTP credentials from environment variables:
    - SMTP_HOST: SMTP server hostname
    - SMTP_PORT: SMTP server port (default 587)
    - SMTP_USER: SMTP username
    - SMTP_PASS: SMTP password
    - LICENSE_FROM_EMAIL: Sender email (default: licensing@infill.systems)
    """
    smtp_host = os.environ.get("SMTP_HOST", "mail.infill.systems")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "licensing@infill.systems")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    from_email = os.environ.get("LICENSE_FROM_EMAIL", "licensing@infill.systems")

    # Build email
    tier_display = {
        "developer": "Developer",
        "trial": "Trial",
        "starter": "Starter",
        "business": "Business",
        "enterprise": "Enterprise",
    }.get(delivery.tier, delivery.tier.title())

    expires_str = ""
    if delivery.expires_at:
        from datetime import datetime

        expires_str = datetime.fromtimestamp(delivery.expires_at).strftime("%Y-%m-%d")

    body = f"""Bedrock {tier_display} License — {delivery.issued_to}

Your Bedrock {tier_display} license has been issued.

License Key: {delivery.license_key}

Tier: {tier_display}
Nodes: {delivery.max_nodes}
Expires: {expires_str or "Never"}

To activate, save your license key to /etc/bedrock/license.key
or set the BEDROCK_LICENSE_KEY environment variable.

  export BEDROCK_LICENSE_KEY={delivery.license_key}

Documentation: https://bedrock.dev/docs
Support: support@infill.systems

— InFill Systems, LLC
"""

    msg = MIMEText(body)
    msg["Subject"] = f"Your Bedrock {tier_display} License Key"
    msg["From"] = from_email
    msg["To"] = delivery.customer_email

    # Send via SMTP with STARTTLS
    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls(context=context)
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.send_message(msg)


def create_webhook_server(host: str = "0.0.0.0", port: int = 8444) -> HTTPServer:
    """Create the webhook server.

    Args:
        host: Bind address.
        port: Bind port (default 8444 to avoid conflict with API server on 8443).

    Returns:
        Configured HTTPServer instance.
    """
    server = HTTPServer((host, port), WebhookHandler)
    return server


def run_webhook_server(host: str = "0.0.0.0", port: int | None = None) -> None:
    """Run the Stripe webhook server.

    Reads WEBHOOK_PORT from environment (default 8444).
    """
    if port is None:
        port = int(os.environ.get("WEBHOOK_PORT", "8444"))

    server = create_webhook_server(host, port)
    print(f"Bedrock License Webhook Server running on http://{host}:{port}")
    print(f"Webhook endpoint: http://{host}:{port}/webhook/stripe")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down webhook server...")
        server.server_close()


if __name__ == "__main__":
    run_webhook_server()
