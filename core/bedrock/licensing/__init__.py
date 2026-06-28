"""
Bedrock Licensing.

Two-tier model:
  - Trial (Free, 30 days): full developer features, 3 local nodes, self-signed certs
  - Developer License ($99/$499 annual): dev mode, 3 local nodes, self-signed certs
  - Production Runtime ($5K/$20K/custom annual): per-node CA enforcement

The Identity Fabric CA enforces the node count limit. No phone-home required.
License keys are offline-validated signed payloads.

Key management:
  - LicenseKeygen: generates signing keys, issues/validates/rotates licenses
  - SigningKey: represents a signing key with metadata, revocation support
"""

from bedrock.licensing.checkout import (
    CheckoutResult,
    CheckoutTier,
    LicenseDelivery,
    configure_stripe,
    create_checkout_session,
)
from bedrock.licensing.enforcement import (
    NODE_LIMITS,
    STRIPE_PRICES,
    STRIPE_PRODUCT_ID,
    TIER_FEATURES,
    TIER_PRICING,
    License,
    LicenseEnforcer,
    LicenseExpiredError,
    LicenseLimitError,
    LicenseTier,
    LicenseValidationError,
)
from bedrock.licensing.keygen import (
    LicenseKeygen,
    SigningKey,
)

__all__ = [
    "LicenseEnforcer",
    "License",
    "LicenseTier",
    "LicenseValidationError",
    "LicenseExpiredError",
    "LicenseLimitError",
    "NODE_LIMITS",
    "TIER_PRICING",
    "TIER_FEATURES",
    "STRIPE_PRODUCT_ID",
    "STRIPE_PRICES",
    "LicenseKeygen",
    "SigningKey",
    "CheckoutTier",
    "CheckoutResult",
    "LicenseDelivery",
    "create_checkout_session",
    "configure_stripe",
]
