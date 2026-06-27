"""
License enforcement — CA-enforced node limits, offline validation.

The CA will not issue certificates beyond the licensed node count.
This is architectural enforcement, not DRM bolted on top.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class LicenseTier(Enum):
    DEVELOPER = "developer"    # $99/yr individual, $499/yr team of 5
    STARTER = "starter"        # $5,000/yr, 5 nodes
    BUSINESS = "business"      # $20,000/yr, 25 nodes
    ENTERPRISE = "enterprise"  # Custom, unlimited nodes


@dataclass
class License:
    """A Bedrock license. Validated offline. No phone-home."""
    license_key: str            # Encrypted license key (offline validation)
    tier: LicenseTier
    max_nodes: int              # Maximum number of nodes (0 = unlimited)
    max_devs: int               # Maximum developers (developer tier only)
    dev_mode: bool              # True = localhost only, self-signed certs
    expires_at: Optional[str] = None  # ISO 8601 expiration date
    issued_to: str = ""         # Company or developer name
    features: list = None       # Included features/add-ons

    def __post_init__(self):
        if self.features is None:
            self.features = []

    @property
    def is_developer(self) -> bool:
        return self.tier == LicenseTier.DEVELOPER

    @property
    def is_runtime(self) -> bool:
        return self.tier in (LicenseTier.STARTER, LicenseTier.BUSINESS, LicenseTier.ENTERPRISE)


class LicenseEnforcer:
    """Enforces license limits through the Identity Fabric CA.

    The CA will not issue certificates beyond the licensed node count.
    Developer mode restricts to localhost with self-signed certificates.
    Runtime mode enables production CA with per-node enforcement.
    """

    def validate_license(self, license_key: str) -> Optional[License]:
        """Validate a license key offline. No phone-home.

        Uses embedded public key to verify license signature.
        Returns License object if valid, None if invalid.
        """
        raise NotImplementedError("B-308: Licensing & Enforcement System")

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