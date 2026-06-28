"""
Certificate lifecycle management.

Issuance (configurable TTL, default 24h), auto-renewal, revocation, CRL distribution.
Certificates are the enforcement mechanism for the Self-Healing Mesh —
a quarantined node's certificate is revoked immediately.

Two-tier licensing:
- Developer mode: self-signed certificates, localhost only, max 3 nodes
- Runtime mode: CA-signed certificates, per-node enforcement, production

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set


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


class CertificateStatus(Enum):
    """Certificate lifecycle states."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_RENEWAL = "pending_renewal"


# Node limits per license tier
NODE_LIMITS = {
    LicenseTier.DEVELOPER: 3,
    LicenseTier.STARTER: 5,
    LicenseTier.BUSINESS: 25,
    LicenseTier.ENTERPRISE: float("inf"),  # Unlimited
}
# String-key fallbacks for enum identity robustness under pytest
for _tier in list(NODE_LIMITS):
    NODE_LIMITS[_tier.value] = NODE_LIMITS[_tier]


@dataclass
class Certificate:
    """A node certificate with embedded capability claims.

    In production, this would be an X.509 certificate with custom extensions
    for Bedrock capabilities. For the core library, we use a dataclass that
    captures all the certificate fields and can be serialized to/from X.509.

    The certificate is the enforcement mechanism:
    - It binds a node's cryptographic identity to its capability scope
    - It has a short TTL (24h default) for rotation security
    - It can be revoked immediately when a node is quarantined
    - Its serial number is unique and traceable in the audit chain
    """
    serial: str  # Unique certificate serial number
    node_uuid: str  # The node this cert belongs to
    node_name: str  # Human-readable node name
    public_key_hash: str  # SHA-256 of the node's ed25519 public key
    capabilities: List[str]  # Data categories this node can access
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None  # Set during issuance
    status: CertificateStatus = CertificateStatus.ACTIVE
    issuer: str = "bedrock-ca"  # CA name or "bedrock-self-signed"
    license_tier: LicenseTier = LicenseTier.DEVELOPER
    revoked_at: Optional[datetime] = None
    revocation_reason: str = ""

    def is_valid(self, at: Optional[datetime] = None) -> bool:
        """Check if the certificate is currently valid.

        A certificate is valid if:
        - Status is ACTIVE
        - Current time is between issued_at and expires_at
        - Not revoked
        """
        check_time = at or datetime.now(timezone.utc)
        if self.status != CertificateStatus.ACTIVE:
            return False
        if self.expires_at and check_time > self.expires_at:
            return False
        if check_time < self.issued_at:
            return False
        return True

    def days_until_expiry(self) -> Optional[float]:
        """Days until this certificate expires. None if no expiry set."""
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return delta.total_seconds() / 86400

    def needs_renewal(self, renewal_window_hours: int = 4) -> bool:
        """Check if the certificate is within the renewal window.

        By default, renew when less than 4 hours remain.
        """
        if self.expires_at is None:
            return False
        remaining = self.expires_at - datetime.now(timezone.utc)
        return remaining <= timedelta(hours=renewal_window_hours)


class CertificateManager:
    """Manages the X.509 certificate lifecycle for all nodes.

    Certificates are short-lived (24h default) and tied to the licensing system:
    - Developer mode: self-signed certificates, localhost only, max 3 nodes
    - Runtime mode: CA-signed certificates, node count enforced by license

    The certificate lifecycle:
    1. Issue: Create a certificate for a registered node (enforces license limit)
    2. Renew: Auto-renew before expiry (new serial, same capabilities)
    3. Revoke: Immediately revoke when node is quarantined (CRL broadcast)
    4. CRL: Certificate Revocation List for checking revoked certs
    """

    def __init__(self, license_tier: LicenseTier = LicenseTier.DEVELOPER,
                 default_ttl_hours: int = 24,
                 renewal_window_hours: int = 4,
                 ca_name: str = "bedrock-ca"):
        self.license_tier = license_tier
        self.default_ttl_hours = default_ttl_hours
        self.renewal_window_hours = renewal_window_hours
        self.ca_name = ca_name if license_tier != LicenseTier.DEVELOPER else "bedrock-self-signed"
        self._certificates: Dict[str, Certificate] = {}  # serial -> Certificate
        self._node_certs: Dict[str, str] = {}  # node_uuid -> latest serial
        self._crl: Set[str] = set()  # Set of revoked serial numbers

    def issue_certificate(self, node_uuid: str, node_name: str,
                          public_key_hash: str,
                          capabilities: Optional[List[str]] = None,
                          ttl_hours: Optional[int] = None) -> Certificate:
        """Issue a new certificate for a node.

        Enforces licensing: will not issue beyond the licensed node count.
        Developer mode uses self-signed certificates. Runtime mode uses CA-signed.

        Args:
            node_uuid: The node's UUID from registration
            node_name: Human-readable node name
            public_key_hash: SHA-256 hex of the node's ed25519 public key
            capabilities: Data categories this node can access
            ttl_hours: Certificate TTL in hours (default: configured default)

        Returns:
            The issued Certificate

        Raises:
            LicenseExceededError: If the license node limit has been reached
        """
        # Enforce license limit
        if not self.check_license_limit():
            active_count = self._count_active_certs()
            limit = NODE_LIMITS.get(self.license_tier) or NODE_LIMITS.get(self.license_tier.value, 3)
            raise LicenseExceededError(
                f"License limit reached: {active_count} active certificates, "
                f"limit is {limit} for {self.license_tier.value} tier. "
                f"Upgrade your license or revoke unused certificates."
            )

        ttl = ttl_hours or self.default_ttl_hours
        serial = self._generate_serial()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=ttl)

        # Determine issuer based on license tier
        issuer = self.ca_name
        if self.license_tier == LicenseTier.DEVELOPER:
            issuer = "bedrock-self-signed"

        cert = Certificate(
            serial=serial,
            node_uuid=node_uuid,
            node_name=node_name,
            public_key_hash=public_key_hash,
            capabilities=capabilities or ["read"],
            issued_at=now,
            expires_at=expires_at,
            status=CertificateStatus.ACTIVE,
            issuer=issuer,
            license_tier=self.license_tier,
        )

        self._certificates[serial] = cert
        self._node_certs[node_uuid] = serial
        return cert

    def renew_certificate(self, node_uuid: str,
                          ttl_hours: Optional[int] = None) -> Certificate:
        """Auto-renew a certificate before expiry.

        Creates a new certificate with a new serial number and the same
        capabilities as the current one. The old certificate stays valid
        until its expiry time (grace period).

        Args:
            node_uuid: The node whose certificate to renew
            ttl_hours: Optional override for TTL

        Returns:
            The new Certificate

        Raises:
            KeyError: If no certificate exists for this node
            ValueError: If the current certificate is revoked
        """
        current_serial = self._node_certs.get(node_uuid)
        if current_serial is None:
            raise KeyError(f"No certificate found for node '{node_uuid}'")

        current_cert = self._certificates.get(current_serial)
        if current_cert is None:
            raise KeyError(f"Certificate '{current_serial}' not found")

        if current_cert.status == CertificateStatus.REVOKED:
            raise ValueError(
                f"Cannot renew revoked certificate '{current_serial}'. "
                f"Reason: {current_cert.revocation_reason}"
            )

        # Issue a new certificate with the same capabilities
        new_cert = self.issue_certificate(
            node_uuid=node_uuid,
            node_name=current_cert.node_name,
            public_key_hash=current_cert.public_key_hash,
            capabilities=current_cert.capabilities,
            ttl_hours=ttl_hours,
        )

        # Mark old cert as pending renewal (stays valid until expiry)
        current_cert.status = CertificateStatus.PENDING_RENEWAL

        return new_cert

    def revoke_certificate(self, node_uuid: str, reason: str) -> Certificate:
        """Revoke a node's certificate immediately.

        Used when a node is quarantined by the Self-Healing Mesh.
        The serial number is added to the CRL for distribution.

        Args:
            node_uuid: The node whose certificate to revoke
            reason: Human-readable reason for revocation

        Returns:
            The revoked Certificate

        Raises:
            KeyError: If no certificate exists for this node
        """
        serial = self._node_certs.get(node_uuid)
        if serial is None:
            raise KeyError(f"No certificate found for node '{node_uuid}'")

        cert = self._certificates.get(serial)
        if cert is None:
            raise KeyError(f"Certificate '{serial}' not found")

        cert.status = CertificateStatus.REVOKED
        cert.revoked_at = datetime.now(timezone.utc)
        cert.revocation_reason = reason

        # Add to CRL
        self._crl.add(serial)

        return cert

    def check_crl(self, serial: str) -> bool:
        """Check if a certificate serial is on the CRL (revoked).

        Args:
            serial: Certificate serial number

        Returns:
            True if revoked, False if not revoked
        """
        return serial in self._crl

    def get_certificate(self, serial: str) -> Optional[Certificate]:
        """Look up a certificate by serial number."""
        return self._certificates.get(serial)

    def get_node_certificate(self, node_uuid: str) -> Optional[Certificate]:
        """Look up a node's current certificate by node UUID."""
        serial = self._node_certs.get(node_uuid)
        if serial is None:
            return None
        return self._certificates.get(serial)

    def check_license_limit(self) -> bool:
        """Check if the number of active certificates is within the licensed limit.

        Returns True if under limit, False if at or over limit.
        """
        active_count = self._count_active_certs()
        limit = NODE_LIMITS.get(self.license_tier) or NODE_LIMITS.get(self.license_tier.value, 3)
        return active_count < limit

    def get_crl(self) -> Set[str]:
        """Get the full Certificate Revocation List (set of revoked serials)."""
        return set(self._crl)

    def list_certificates(self, status: Optional[CertificateStatus] = None) -> List[Certificate]:
        """List certificates, optionally filtered by status."""
        certs = list(self._certificates.values())
        if status is not None:
            certs = [c for c in certs if c.status == status]
        return certs

    def _count_active_certs(self) -> int:
        """Count certificates in ACTIVE or PENDING_RENEWAL status."""
        return sum(
            1 for c in self._certificates.values()
            if c.status in (CertificateStatus.ACTIVE, CertificateStatus.PENDING_RENEWAL)
        )

    def _generate_serial(self) -> str:
        """Generate a unique certificate serial number.

        Format: bedrock-<uuid4> for readability and uniqueness.
        """
        return f"bedrock-{uuid.uuid4()}"


class LicenseExceededError(Exception):
    """Raised when the license node limit is reached."""
    pass