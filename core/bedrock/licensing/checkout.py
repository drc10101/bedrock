"""
Bedrock Stripe Integration — Checkout Sessions and Webhook Handler.

Handles:
- Creating Stripe Checkout Sessions for paid license tiers
- Receiving Stripe webhooks (checkout.session.completed) to issue license keys
- Delivering license keys to customers via email confirmation

Environment variables:
- BEDROCK_STRIPE_SECRET_KEY: Stripe secret key (sk_live_... or sk_test_...)
- BEDROCK_STRIPE_WEBHOOK_SECRET: Stripe webhook signing secret (whsec_...)
- BEDROCK_SIGNING_KEY: HMAC key for signing Bedrock license keys
- BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL: Price ID for $99/yr individual dev license
- BEDROCK_STRIPE_PRICE_DEV_TEAM: Price ID for $499/yr team dev license
- BEDROCK_STRIPE_PRODUCT_ID: Stripe product ID for Bedrock

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import stripe


class CheckoutTier(Enum):
    """Map Stripe price IDs to Bedrock license tiers."""

    DEVELOPER_INDIVIDUAL = "developer_individual"
    DEVELOPER_TEAM = "developer_team"


@dataclass
class CheckoutResult:
    """Result of creating a checkout session."""

    session_id: str
    session_url: str
    tier: CheckoutTier
    price_id: str
    customer_email: str | None = None


@dataclass
class LicenseDelivery:
    """License key issued after successful payment."""

    license_key: str
    tier: str
    issued_to: str
    customer_email: str
    expires_at: float | None
    max_nodes: int
    features: list = field(default_factory=list)
    issued_at: float = field(default_factory=time.time)


def configure_stripe() -> None:
    """Configure the Stripe SDK from environment variables."""
    secret_key = os.environ.get("BEDROCK_STRIPE_SECRET_KEY")
    if not secret_key:
        raise ValueError("BEDROCK_STRIPE_SECRET_KEY environment variable is required")
    stripe.api_key = secret_key


def create_checkout_session(
    tier: CheckoutTier,
    customer_email: str | None = None,
    success_url: str = "https://bedrock.dev/license/success?session_id={CHECKOUT_SESSION_ID}",
    cancel_url: str = "https://bedrock.dev/license/cancel",
    metadata: dict | None = None,
) -> CheckoutResult:
    """Create a Stripe Checkout Session for a Bedrock license purchase.

    Args:
        tier: Which license tier to purchase.
        customer_email: Pre-fill customer email.
        success_url: URL to redirect on success.
        cancel_url: URL to redirect on cancellation.
        metadata: Additional metadata to attach to the session.

    Returns:
        CheckoutResult with session ID and URL.
    """
    configure_stripe()

    # Resolve price ID from environment
    price_map = {
        CheckoutTier.DEVELOPER_INDIVIDUAL: os.environ.get("BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"),
        CheckoutTier.DEVELOPER_TEAM: os.environ.get("BEDROCK_STRIPE_PRICE_DEV_TEAM"),
    }
    price_id = price_map.get(tier)
    if not price_id:
        raise ValueError(
            f"No price ID configured for tier {tier.value}. "
            f"Set the corresponding BEDROCK_STRIPE_PRICE_* environment variable."
        )

    product_id = os.environ.get("BEDROCK_STRIPE_PRODUCT_ID")

    # Build line items
    line_items: list[dict[str, Any]] = [{"price": price_id, "quantity": 1}]

    # Build metadata
    session_metadata: dict[str, str] = {"bedrock_tier": tier.value}
    if metadata:
        session_metadata.update(metadata)
    if product_id:
        session_metadata["product_id"] = product_id

    create_kwargs: dict[str, Any] = {
        "mode": "subscription" if tier == CheckoutTier.DEVELOPER_TEAM else "payment",
        "line_items": line_items,
        "success_url": success_url,
        "cancel_url": cancel_url,
        "metadata": session_metadata,
    }
    if customer_email:
        create_kwargs["customer_email"] = customer_email

    session = stripe.checkout.Session.create(**create_kwargs)

    return CheckoutResult(
        session_id=session.id,
        session_url=session.url or "",
        tier=tier,
        price_id=price_id,
        customer_email=customer_email,
    )


def verify_webhook_signature(payload: bytes, sig_header: str) -> dict[str, Any]:
    """Verify and parse a Stripe webhook event.

    Args:
        payload: Raw request body bytes.
        sig_header: Stripe-Signature header value.

    Returns:
        Parsed event dict if signature is valid.

    Raises:
        ValueError: If signature verification fails.
    """
    webhook_secret = os.environ.get("BEDROCK_STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        raise ValueError("BEDROCK_STRIPE_WEBHOOK_SECRET environment variable is required")

    event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    return dict(event)


def handle_checkout_completed(event: dict) -> LicenseDelivery:
    """Handle a checkout.session.completed webhook event.

    Issues a Bedrock license key and returns delivery details.

    Args:
        event: Verified Stripe webhook event dict.

    Returns:
        LicenseDelivery with the issued license key and details.
    """
    from bedrock.licensing.enforcement import LicenseEnforcer, LicenseTier

    session = event["data"]["object"]
    metadata = session.get("metadata", {})
    tier_str = metadata.get("bedrock_tier", "developer_individual")
    customer_email = session.get("customer_email", "") or session.get("customer_details", {}).get(
        "email", ""
    )

    # Map checkout tier to license tier
    tier_map = {
        "developer_individual": LicenseTier.DEVELOPER,
        "developer_team": LicenseTier.DEVELOPER,
    }
    license_tier = tier_map.get(tier_str, LicenseTier.DEVELOPER)

    # Determine max_devs for team licenses
    max_devs = 5 if tier_str == "developer_individual" else 25

    # Generate the license key
    enforcer = LicenseEnforcer()
    license_key = enforcer.generate_license_key(
        tier=license_tier,
        issued_to=customer_email or "licensee",
        max_devs=max_devs,
        # 1-year expiration from now
        expires_at=time.time() + (365 * 24 * 60 * 60),
    )

    # Validate it immediately
    license_obj = enforcer.validate_license(license_key)

    return LicenseDelivery(
        license_key=license_key,
        tier=license_obj.tier.value,
        issued_to=customer_email or "licensee",
        customer_email=customer_email,
        expires_at=license_obj.expires_at,
        max_nodes=license_obj.max_nodes,
        features=license_obj.features,
    )


def create_pricing_links() -> dict[str, str]:
    """Generate Stripe payment links for all license tiers.

    Returns a dict mapping tier names to Stripe payment links.
    Used by the bedrock.dev landing page to route buyers.
    """
    configure_stripe()

    links: dict[str, str] = {}

    price_config = {
        "developer_individual": os.environ.get("BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"),
        "developer_team": os.environ.get("BEDROCK_STRIPE_PRICE_DEV_TEAM"),
    }

    for tier_name, price_id in price_config.items():
        if not price_id:
            continue
        try:
            session = stripe.checkout.Session.create(
                mode="payment",
                line_items=[{"price": price_id, "quantity": 1}],
                success_url="https://bedrock.dev/license/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url="https://bedrock.dev/license/cancel",
                metadata={"bedrock_tier": tier_name},
            )
            links[tier_name] = session.url or ""
        except stripe.error.StripeError as e:
            links[tier_name] = f"Error: {str(e)}"

    return links
