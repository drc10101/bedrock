"""
Bedrock Stripe Integration — Checkout Sessions and Webhook Handler.

Handles:
- Creating Stripe Checkout Sessions for production license tiers
- Receiving Stripe webhooks (checkout.session.completed) to issue license keys
- Delivering license keys to customers via email confirmation

Developer licenses are free (no Stripe checkout needed).
Production tiers (Starter, Business, Enterprise) go through Stripe.

Environment variables:
- BEDROCK_STRIPE_SECRET_KEY: Stripe secret key (sk_live_... or sk_test_...)
- BEDROCK_STRIPE_WEBHOOK_SECRET: Stripe webhook signing secret (whsec_...)
- BEDROCK_SIGNING_KEY: HMAC key for signing Bedrock license keys
- BEDROCK_STRIPE_PRICE_STARTER: Price ID for $5K/yr Starter license
- BEDROCK_STRIPE_PRICE_BUSINESS: Price ID for $20K/yr Business license
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
    """Map Stripe price IDs to Bedrock production license tiers."""

    STARTER = "starter"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


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
    success_url: str = "https://buildonbedrock.dev/pricing?success",
    cancel_url: str = "https://buildonbedrock.dev/pricing",
    metadata: dict | None = None,
) -> CheckoutResult:
    """Create a Stripe Checkout Session for a Bedrock production license.

    Args:
        tier: Which production license tier to purchase.
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
        CheckoutTier.STARTER: os.environ.get("BEDROCK_STRIPE_PRICE_STARTER"),
        CheckoutTier.BUSINESS: os.environ.get("BEDROCK_STRIPE_PRICE_BUSINESS"),
        CheckoutTier.ENTERPRISE: None,  # Enterprise is custom — handled separately
    }
    price_id = price_map.get(tier)

    if tier == CheckoutTier.ENTERPRISE:
        raise ValueError(
            "Enterprise tier requires custom pricing. "
            "Contact ops@infill.systems for a custom checkout link."
        )

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
        "mode": "subscription",
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
    tier_str = metadata.get("bedrock_tier", "starter")
    customer_email = session.get("customer_email", "") or session.get("customer_details", {}).get(
        "email", ""
    )

    # Map checkout tier to license tier
    tier_map = {
        "starter": LicenseTier.STARTER,
        "business": LicenseTier.BUSINESS,
        "enterprise": LicenseTier.ENTERPRISE,
    }
    license_tier = tier_map.get(tier_str, LicenseTier.STARTER)

    # Generate the license key
    enforcer = LicenseEnforcer()
    license_key = enforcer.generate_license_key(
        tier=license_tier,
        issued_to=customer_email or "licensee",
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
    """Generate Stripe payment links for production license tiers.

    Returns a dict mapping tier names to Stripe payment links.
    Used by the buildonbedrock.dev landing page to route buyers.
    Developer licenses are free — no Stripe link needed.
    """
    configure_stripe()

    links: dict[str, str] = {}

    price_config = {
        "starter": os.environ.get("BEDROCK_STRIPE_PRICE_STARTER"),
        "business": os.environ.get("BEDROCK_STRIPE_PRICE_BUSINESS"),
    }

    for tier_name, price_id in price_config.items():
        if not price_id:
            continue
        try:
            session = stripe.checkout.Session.create(
                mode="subscription",
                line_items=[{"price": price_id, "quantity": 1}],
                success_url="https://buildonbedrock.dev/pricing?success",
                cancel_url="https://buildonbedrock.dev/pricing",
                metadata={"bedrock_tier": tier_name},
            )
            links[tier_name] = session.url or ""
        except stripe.error.StripeError as e:
            links[tier_name] = f"Error: {str(e)}"

    return links