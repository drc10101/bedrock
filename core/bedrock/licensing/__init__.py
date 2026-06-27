"""
Bedrock Licensing.

Two-tier model:
  - Developer License ($99/$499 annual): dev mode, 3 local nodes, self-signed certs
  - Production Runtime ($5K/$20K/custom annual): per-node CA enforcement

The Identity Fabric CA enforces the node count limit. No phone-home required.
License keys are offline-validated signed payloads.

Key management:
  - LicenseKeygen: generates signing keys, issues/validates/rotates licenses
  - SigningKey: represents a signing key with metadata, revocation support
"""

from bedrock.licensing.enforcement import (
    LicenseEnforcer,
    License,
    LicenseTier,
    LicenseValidationError,
    LicenseExpiredError,
    LicenseLimitError,
    NODE_LIMITS,
    TIER_PRICING,
    TIER_FEATURES,
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
    "LicenseKeygen",
    "SigningKey",
]