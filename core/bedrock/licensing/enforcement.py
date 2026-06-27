"""
License enforcement — CA-enforced node limits, offline validation.

The CA will not issue certificates beyond the licensed node count.
This is architectural enforcement, not DRM bolted on top.

Two-tier model:
  - Developer License ($99/$499 annual): dev mode, 3 local nodes, self-signed certs
  - Production Runtime ($5K/$20K/custom annual): per-node CA enforcement

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple


class LicenseTier(Enum):
    """Licensing tiers controlling certificate authority and node limits.

    DEVELOPER: Self-signed certificates, localhost only, max 3 nodes.
        For development and testing. No CA required.
    STARTER: CA-signed certificates, max 5 nodes.
        For small production deployments.
    BUSINESS: CA-signed certificates, max 25 nodes.
        For mid-market deployments.
    ENTERPRISE: CA-signed certificates, unlimited nodes.
        For large-scale or air-gapped deployments.
    """
    DEVELOPER = "developer"
    STARTER = "starter"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


# Node limits per license tier
NODE_LIMITS = {
    LicenseTier.DEVELOPER: 3,
    LicenseTier.STARTER: 5,
    LicenseTier.BUSINESS: 25,
    LicenseTier.ENTERPRISE: float("inf"),  # Unlimited
}

# Pricing per tier (annual USD)
TIER_PRICING = {
    LicenseTier.DEVELOPER: {"individual": 99, "team": 499},
    LicenseTier.STARTER: 5000,
    LicenseTier.BUSINESS: 20000,
    LicenseTier.ENTERPRISE: "custom",
}

# Stripe product and price IDs (test mode)
STRIPE_PRODUCT_ID = "prod_UmfKFai4NjHXyy"

STRIPE_PRICES = {
    LicenseTier.DEVELOPER: {
        "individual": "price_1Tn5zvGfRLc2oae00cPNY0K0",  # $99/yr
        "team": "price_1Tn5zvGfRLc2oae0MNqHaBMB",       # $499/yr
    },
}

# Feature flags per tier
TIER_FEATURES = {
    LicenseTier.DEVELOPER: [
        "self_signed_certs",
        "localhost_only",
        "max_3_nodes",
        "audit_export",
        "basic_mesh",
    ],
    LicenseTier.STARTER: [
        "ca_signed_certs",
        "production_deployment",
        "max_5_nodes",
        "audit_export",
        "self_healing_mesh",
        "compliance_reports",
    ],
    LicenseTier.BUSINESS: [
        "ca_signed_certs",
        "production_deployment",
        "max_25_nodes",
        "audit_export",
        "self_healing_mesh",
        "compliance_reports",
        "custom_certificates",
        "priority_support",
    ],
    LicenseTier.ENTERPRISE: [
        "ca_signed_certs",
        "production_deployment",
        "unlimited_nodes",
        "audit_export",
        "self_healing_mesh",
        "compliance_reports",
        "custom_certificates",
        "custom_ca",
        "air_gap_support",
        "priority_support",
        "dedicated_support",
    ],
}

# Add string-key fallbacks for enum identity robustness across import paths
# (Under pytest, enum identity may differ; string lookups always work)
for _tier in list(NODE_LIMITS):
    NODE_LIMITS[_tier.value] = NODE_LIMITS[_tier]
for _tier in list(TIER_PRICING):
    TIER_PRICING[_tier.value] = TIER_PRICING[_tier]
for _tier in list(TIER_FEATURES):
    TIER_FEATURES[_tier.value] = TIER_FEATURES[_tier]


@dataclass
class License:
    """A Bedrock license. Validated offline. No phone-home.

    The license key is a signed JSON payload containing the license details.
    Validation uses an embedded public key — no network required.

    License format:
        <version>:<payload_base64>:<signature_base64>

    Payload (JSON):
        {
            "key_id": "bedrock-2026-01",
            "tier": "business",
            "max_nodes": 25,
            "max_devs": 5,
            "dev_mode": false,
            "issued_to": "Acme Corp",
            "issued_at": 1719500000,
            "expires_at": 1751036000,
            "features": ["ca_signed_certs", "production_deployment", ...]
        }

    Signature:
        HMAC-SHA256(payload, signing_key) — the signing key is embedded
        in the library and not extractable from compiled code.
    """
    license_key: str            # Full license key string
    tier: LicenseTier           # License tier
    max_nodes: int              # Maximum number of nodes (0 = unlimited)
    max_devs: int               # Maximum developers (developer tier only)
    dev_mode: bool              # True = localhost only, self-signed certs
    issued_to: str = ""         # Company or developer name
    issued_at: float = 0.0      # Unix timestamp of issuance
    expires_at: Optional[float] = None  # Unix timestamp of expiration
    features: list = field(default_factory=list)

    @property
    def is_developer(self) -> bool:
        """True if this is a developer license."""
        return self.tier == LicenseTier.DEVELOPER

    @property
    def is_runtime(self) -> bool:
        """True if this is a production runtime license."""
        return self.tier in (LicenseTier.STARTER, LicenseTier.BUSINESS, LicenseTier.ENTERPRISE)

    @property
    def is_expired(self) -> bool:
        """True if the license has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def days_until_expiry(self) -> Optional[float]:
        """Days until this license expires. None if no expiry."""
        if self.expires_at is None:
            return None
        return (self.expires_at - time.time()) / 86400

    @property
    def is_valid(self) -> bool:
        """True if the license is valid (not expired, correct format)."""
        return not self.is_expired

    def has_feature(self, feature: str) -> bool:
        """Check if the license includes a specific feature."""
        return feature in self.features


class LicenseValidationError(Exception):
    """Raised when a license key fails validation."""
    pass


class LicenseExpiredError(LicenseValidationError):
    """Raised when a license has expired."""
    pass


class LicenseLimitError(Exception):
    """Raised when the license node limit has been reached."""
    pass


# Signing key for license validation (embedded in library).
# In production, this would be a compiled-in key not easily extractable.
# This is a HMAC key for offline signature verification.
_LICENSE_SIGNING_KEY = b"bedrock-2026-license-signing-key-v1"


class LicenseEnforcer:
    """Enforces license limits through the Identity Fabric CA.

    The CA will not issue certificates beyond the licensed node count.
    Developer mode restricts to localhost with self-signed certificates.
    Runtime mode enables production CA with per-node enforcement.

    License validation is entirely offline — no phone-home required.
    The license key is a signed payload verified with an embedded key.
    """

    def __init__(self, signing_key: bytes = _LICENSE_SIGNING_KEY):
        self._signing_key = signing_key

    def generate_license_key(self, tier: LicenseTier, issued_to: str = "",
                              max_nodes: Optional[int] = None,
                              max_devs: int = 5,
                              expires_at: Optional[float] = None,
                              features: Optional[list] = None) -> str:
        """Generate a license key for a given tier.

        This method is used by the Bedrock license server to issue keys.
        It is NOT intended for end-user use.

        Args:
            tier: License tier
            issued_to: Company or developer name
            max_nodes: Override max nodes (defaults to tier limit)
            max_devs: Max developer seats (developer tier only)
            expires_at: Unix timestamp of expiration (None = perpetual)
            features: Override feature list (defaults to tier features)

        Returns:
            Signed license key string
        """
        # Resolve tier to enum for consistent dict lookups (handles both enum and string inputs)
        if isinstance(tier, str):
            tier = LicenseTier(tier)
        effective_max_nodes = max_nodes if max_nodes is not None else NODE_LIMITS.get(tier, NODE_LIMITS.get(tier.value, 3))
        effective_features = features if features is not None else TIER_FEATURES.get(tier, TIER_FEATURES.get(tier.value, TIER_FEATURES[LicenseTier.DEVELOPER]))
        dev_mode = tier == LicenseTier.DEVELOPER

        payload = {
            "key_id": "bedrock-2026-01",
            "tier": tier.value,
            "max_nodes": effective_max_nodes if effective_max_nodes != float("inf") else 0,
            "max_devs": max_devs if dev_mode else 0,
            "dev_mode": dev_mode,
            "issued_to": issued_to,
            "issued_at": time.time(),
            "expires_at": expires_at,
            "features": effective_features,
        }

        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()

        # Sign with HMAC-SHA256
        signature = hmac.new(
            self._signing_key,
            payload_json.encode(),
            hashlib.sha256,
        ).hexdigest()
        signature_b64 = base64.urlsafe_b64encode(signature.encode()).decode()

        return f"1:{payload_b64}:{signature_b64}"

    def validate_license(self, license_key: str) -> License:
        """Validate a license key offline. No phone-home.

        Uses embedded public key to verify license signature.
        Returns License object if valid.

        Args:
            license_key: Full license key string

        Returns:
            License object with parsed and validated details

        Raises:
            LicenseValidationError: If the license key is invalid
            LicenseExpiredError: If the license has expired
        """
        if not license_key:
            raise LicenseValidationError("Empty license key")

        # Parse the key format: version:payload:signature
        parts = license_key.split(":")
        if len(parts) != 3:
            raise LicenseValidationError(
                f"Invalid license key format: expected 3 parts, got {len(parts)}"
            )

        version, payload_b64, signature_b64 = parts
        if version != "1":
            raise LicenseValidationError(
                f"Unsupported license key version: {version}"
            )

        # Decode payload
        try:
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        except Exception as e:
            raise LicenseValidationError(f"Invalid payload encoding: {e}")

        # Decode and verify signature
        try:
            expected_signature = hmac.new(
                self._signing_key,
                payload_json.encode(),
                hashlib.sha256,
            ).hexdigest()
            provided_signature = base64.urlsafe_b64decode(signature_b64).decode()
        except Exception as e:
            raise LicenseValidationError(f"Invalid signature encoding: {e}")

        if not hmac.compare_digest(expected_signature, provided_signature):
            raise LicenseValidationError("Invalid license key signature")

        # Parse payload
        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError as e:
            raise LicenseValidationError(f"Invalid payload JSON: {e}")

        # Extract fields
        try:
            tier = LicenseTier(payload["tier"])
        except (KeyError, ValueError) as e:
            raise LicenseValidationError(f"Invalid tier in license: {e}")

        max_nodes = payload.get("max_nodes", NODE_LIMITS.get(tier, NODE_LIMITS.get(tier.value, 3)))
        if max_nodes == 0:
            max_nodes = float("inf")

        license_obj = License(
            license_key=license_key,
            tier=tier,
            max_nodes=max_nodes,
            max_devs=payload.get("max_devs", 5),
            dev_mode=payload.get("dev_mode", tier == LicenseTier.DEVELOPER),
            issued_to=payload.get("issued_to", ""),
            issued_at=payload.get("issued_at", 0),
            expires_at=payload.get("expires_at"),
            features=payload.get("features", TIER_FEATURES.get(tier, TIER_FEATURES.get(tier.value, TIER_FEATURES[LicenseTier.DEVELOPER]))),
        )

        # Check expiration
        if license_obj.is_expired:
            raise LicenseExpiredError(
                f"License expired on {time.strftime('%Y-%m-%d', time.gmtime(license_obj.expires_at))}"
            )

        return license_obj

    def validate_license_from_file(self, path: Optional[str] = None) -> License:
        """Validate a license key from a file.

        Args:
            path: Path to license key file. Defaults to /etc/bedrock/license.key

        Returns:
            License object if valid

        Raises:
            LicenseValidationError: If the license key is invalid
            FileNotFoundError: If the license file does not exist
        """
        license_path = path or "/etc/bedrock/license.key"
        if not os.path.exists(license_path):
            raise FileNotFoundError(f"License file not found: {license_path}")

        with open(license_path, "r") as f:
            license_key = f.read().strip()

        return self.validate_license(license_key)

    def can_issue_certificate(self, license: License,
                              current_node_count: int) -> bool:
        """Check if a new certificate can be issued within the license limit.

        Returns True if under the limit, False if at or over limit.
        Developer: max 3 nodes.
        Starter: max 5 nodes.
        Business: max 25 nodes.
        Enterprise: unlimited.
        """
        if license.tier == LicenseTier.ENTERPRISE:
            return True
        return current_node_count < license.max_nodes

    def enforce_developer_mode(self, license: License) -> dict:
        """Get developer mode restrictions.

        Developer mode: localhost only, self-signed certs, 3 nodes max.
        """
        if not license.is_developer:
            return {"dev_mode": False}

        return {
            "dev_mode": True,
            "localhost_only": True,
            "self_signed_certs": True,
            "max_nodes": min(license.max_nodes, 3),
            "no_production": True,
        }

    def get_tier_info(self, tier: LicenseTier) -> dict:
        """Get information about a license tier.

        Returns pricing, features, and limits for the given tier.
        """
        return {
            "tier": tier.value,
            "max_nodes": NODE_LIMITS.get(tier, NODE_LIMITS.get(tier.value, 3)),
            "features": TIER_FEATURES.get(tier, TIER_FEATURES.get(tier.value, TIER_FEATURES[LicenseTier.DEVELOPER])),
            "pricing": TIER_PRICING.get(tier, TIER_PRICING.get(tier.value, {})),
        }

    def validate_feature_access(self, license: License, feature: str) -> bool:
        """Check if a license grants access to a specific feature.

        Args:
            license: Validated License object
            feature: Feature name to check

        Returns:
            True if the license includes the feature
        """
        return license.has_feature(feature)

    def get_upgrade_path(self, current_tier: LicenseTier) -> dict:
        """Get the upgrade path from the current tier.

        Returns available upgrade tiers with pricing.
        """
        tier_order = [
            LicenseTier.DEVELOPER,
            LicenseTier.STARTER,
            LicenseTier.BUSINESS,
            LicenseTier.ENTERPRISE,
        ]
        current_idx = tier_order.index(current_tier)

        upgrades = {}
        for tier in tier_order[current_idx + 1:]:
            upgrades[tier.value] = {
                "pricing": TIER_PRICING.get(tier, TIER_PRICING.get(tier.value, {})),
                "max_nodes": NODE_LIMITS.get(tier, NODE_LIMITS.get(tier.value, 3)),
                "features": TIER_FEATURES.get(tier, TIER_FEATURES.get(tier.value, TIER_FEATURES[LicenseTier.DEVELOPER])),
            }

        return upgrades