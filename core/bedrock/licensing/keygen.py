"""
License key management — key generation, signing, rotation, and revocation.

The keygen system produces master signing keys that license keys are signed with.
Keys can be rotated (new master key, re-sign existing licenses) and revoked.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from bedrock.licensing.enforcement import (
    LicenseEnforcer,
    LicenseTier,
    NODE_LIMITS,
    TIER_FEATURES,
)


@dataclass
class SigningKey:
    """A signing key used for license key generation and validation.

    Keys are identified by key_id and can be rotated or revoked.
    The key material is stored as bytes and never written to logs.
    """
    key_id: str
    key_material: bytes
    created_at: float = 0.0
    algorithm: str = "HMAC-SHA256"
    revoked: bool = False
    revocation_reason: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()
        if isinstance(self.key_material, str):
            self.key_material = self.key_material.encode("utf-8")

    @property
    def is_active(self) -> bool:
        """True if this key is active (not revoked)."""
        return not self.revoked

    def revoke(self, reason: str = "") -> None:
        """Revoke this signing key. Licenses signed with it will fail validation."""
        self.revoked = True
        self.revocation_reason = reason

    def to_dict(self) -> dict:
        """Serialize key metadata (excludes key_material for security)."""
        return {
            "key_id": self.key_id,
            "key_material_b64": base64.urlsafe_b64encode(self.key_material).decode(),
            "created_at": self.created_at,
            "algorithm": self.algorithm,
            "revoked": self.revoked,
            "revocation_reason": self.revocation_reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SigningKey":
        """Deserialize a SigningKey from a dict."""
        return cls(
            key_id=data["key_id"],
            key_material=base64.urlsafe_b64decode(data["key_material_b64"]),
            created_at=data.get("created_at", 0),
            algorithm=data.get("algorithm", "HMAC-SHA256"),
            revoked=data.get("revoked", False),
            revocation_reason=data.get("revocation_reason", ""),
        )


class LicenseKeygen:
    """License key generation and management.

    Generates master signing keys, creates signed license keys,
    manages key rotation, and supports key revocation.

    This is the authority-side component — the keygen server that
    Bedrock runs to issue and manage developer licenses.

    Usage:
        keygen = LicenseKeygen()
        key = keygen.generate_signing_key("bedrock-2026-01")
        license_key = keygen.issue_license(
            key=key,
            tier=LicenseTier.DEVELOPER,
            issued_to="Acme Corp",
            expires_days=365,
        )
    """

    def __init__(self):
        self._keys: dict[str, SigningKey] = {}

    def generate_signing_key(
        self,
        key_id: str = "",
        key_material: Optional[bytes] = None,
    ) -> SigningKey:
        """Generate a new signing key for license creation.

        Args:
            key_id: Unique identifier for this key. Auto-generated if empty.
            key_material: Raw key bytes. Random if not provided.

        Returns:
            SigningKey ready for license generation.
        """
        if not key_id:
            key_id = f"bedrock-{int(time.time())}"

        if key_material is None:
            key_material = os.urandom(32)  # 256-bit key

        key = SigningKey(
            key_id=key_id,
            key_material=key_material,
        )
        self._keys[key_id] = key
        return key

    def get_key(self, key_id: str) -> Optional[SigningKey]:
        """Get a signing key by ID."""
        return self._keys.get(key_id)

    def list_keys(self, active_only: bool = True) -> list[SigningKey]:
        """List all signing keys.

        Args:
            active_only: If True, exclude revoked keys.

        Returns:
            List of SigningKey objects.
        """
        keys = list(self._keys.values())
        if active_only:
            return [k for k in keys if k.is_active]
        return keys

    def revoke_key(self, key_id: str, reason: str = "") -> bool:
        """Revoke a signing key.

        All licenses signed with this key will fail validation after revocation.

        Args:
            key_id: Key ID to revoke.
            reason: Reason for revocation.

        Returns:
            True if key was found and revoked, False if key not found.
        """
        key = self._keys.get(key_id)
        if key is None:
            return False
        key.revoke(reason)
        return True

    def rotate_key(self, old_key_id: str, new_key_id: str = "") -> tuple[SigningKey, SigningKey] | None:
        """Rotate a signing key — revoke old, generate new.

        The old key is revoked (not deleted, for audit trail).
        A new key is generated with the same key_id prefix.

        Args:
            old_key_id: Key ID to rotate out.
            new_key_id: Key ID for the new key. Auto-generated if empty.

        Returns:
            Tuple of (old_key, new_key) or None if old_key_id not found.
        """
        old_key = self._keys.get(old_key_id)
        if old_key is None:
            return None

        # Revoke old key
        old_key.revoke("Rotated out")

        # Generate new key
        if not new_key_id:
            # Increment version: bedrock-2026-01 -> bedrock-2026-02
            base = old_key_id.rsplit("-", 1)[0]
            try:
                version = int(old_key_id.rsplit("-", 1)[1])
                new_key_id = f"{base}-{version + 1:02d}"
            except (ValueError, IndexError):
                new_key_id = f"{old_key_id}-v2"

        new_key = self.generate_signing_key(key_id=new_key_id)
        return (old_key, new_key)

    def issue_license(
        self,
        key: SigningKey,
        tier: LicenseTier,
        issued_to: str = "",
        max_nodes: Optional[int] = None,
        max_devs: int = 5,
        expires_days: Optional[int] = None,
        features: Optional[list] = None,
    ) -> str:
        """Issue a signed license key.

        Args:
            key: Signing key to sign with.
            tier: License tier.
            issued_to: Company or developer name.
            max_nodes: Override max nodes (defaults to tier limit).
            max_devs: Max developer seats (developer tier only).
            expires_days: Days until expiration. None = perpetual.
            features: Override feature list (defaults to tier features).

        Returns:
            Signed license key string (format: version:payload:signature)

        Raises:
            ValueError: If the signing key is revoked.
        """
        if key.revoked:
            raise ValueError(f"Cannot issue license with revoked key: {key.key_id}")

        # Calculate expiration
        expires_at = None
        if expires_days is not None:
            expires_at = time.time() + (expires_days * 86400)

        # Resolve tier
        if isinstance(tier, str):
            tier = LicenseTier(tier)

        effective_max_nodes = max_nodes if max_nodes is not None else NODE_LIMITS.get(
            tier, NODE_LIMITS.get(tier.value, 3)
        )
        effective_features = features if features is not None else TIER_FEATURES.get(
            tier, TIER_FEATURES.get(tier.value, TIER_FEATURES[LicenseTier.DEVELOPER])
        )
        dev_mode = tier == LicenseTier.DEVELOPER

        payload = {
            "key_id": key.key_id,
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

        # Sign with the provided key
        signature = hashlib.pbkdf2_hmac(
            "sha256",
            payload_json.encode(),
            key.key_material,
            100000,  # iterations for PBKDF2
        ).hex()
        signature_b64 = base64.urlsafe_b64encode(signature.encode()).decode()

        return f"1:{payload_b64}:{signature_b64}"

    def validate_license(self, license_key: str) -> "License":
        """Validate a license key against all active signing keys.

        Tries each active key until one validates the signature.

        Args:
            license_key: Full license key string.

        Returns:
            License object if valid.

        Raises:
            LicenseValidationError: If no active key validates the signature.
        """
        from bedrock.licensing.enforcement import License, LicenseValidationError, LicenseExpiredError

        if not license_key:
            raise LicenseValidationError("Empty license key")

        parts = license_key.split(":")
        if len(parts) != 3:
            raise LicenseValidationError(
                f"Invalid license key format: expected 3 parts, got {len(parts)}"
            )

        version, payload_b64, signature_b64 = parts
        if version != "1":
            raise LicenseValidationError(f"Unsupported license key version: {version}")

        # Decode payload
        try:
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        except Exception as e:
            raise LicenseValidationError(f"Invalid payload encoding: {e}")

        # Try each active signing key
        last_error = None
        for key in self.list_keys(active_only=True):
            try:
                expected_signature = hashlib.pbkdf2_hmac(
                    "sha256",
                    payload_json.encode(),
                    key.key_material,
                    100000,
                ).hex()
                provided_signature = base64.urlsafe_b64decode(signature_b64).decode()

                if not self._constant_time_compare(expected_signature, provided_signature):
                    last_error = LicenseValidationError(
                        f"Signature does not match key {key.key_id}"
                    )
                    continue

                # Signature matches this key — parse the payload
                try:
                    payload = json.loads(payload_json)
                except json.JSONDecodeError as e:
                    raise LicenseValidationError(f"Invalid payload JSON: {e}")

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

                if license_obj.is_expired:
                    raise LicenseExpiredError(
                        f"License expired on {time.strftime('%Y-%m-%d', time.gmtime(license_obj.expires_at))}"
                    )

                return license_obj

            except LicenseExpiredError:
                raise  # Re-raise expiration errors
            except LicenseValidationError:
                continue

        # No key validated
        if last_error:
            raise last_error
        raise LicenseValidationError("No active signing keys available for validation")

    @staticmethod
    def _constant_time_compare(a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0

    def export_keys(self) -> str:
        """Export all signing keys as JSON for backup.

        WARNING: This contains key material. Store securely.
        """
        keys_data = [k.to_dict() for k in self._keys.values()]
        return json.dumps({"keys": keys_data, "exported_at": time.time()}, indent=2)

    def export_keys_file(self, path: "Path") -> None:
        """Export signing keys to a file.

        Args:
            path: File path to write keys JSON.
        """
        from pathlib import Path as _Path
        path = _Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(self.export_keys())

    @classmethod
    def from_file(cls, path: "Path") -> "LicenseKeygen":
        """Load a LicenseKeygen from a keys file.

        Args:
            path: Path to signing keys JSON file.

        Returns:
            LicenseKeygen with loaded keys.
        """
        from pathlib import Path as _Path
        path = _Path(path)
        with open(path) as f:
            data = f.read()
        keygen = cls()
        keygen.import_keys(data)
        return keygen

    def import_keys(self, json_data: str) -> int:
        """Import signing keys from a JSON backup.

        Args:
            json_data: JSON string from export_keys().

        Returns:
            Number of keys imported.
        """
        data = json.loads(json_data)
        count = 0
        for key_data in data.get("keys", []):
            key = SigningKey.from_dict(key_data)
            self._keys[key.key_id] = key
            count += 1
        return count

    def re_sign_license(self, license_key: str, new_key: SigningKey) -> str:
        """Re-sign an existing license with a new signing key.

        Used during key rotation — the license payload stays the same,
        but the signature is updated to use the new key.

        Args:
            license_key: Existing license key to re-sign.
            new_key: New signing key to sign with.

        Returns:
            Re-signed license key string.

        Raises:
            ValueError: If the new key is revoked.
        """
        if new_key.revoked:
            raise ValueError(f"Cannot re-sign with revoked key: {new_key.key_id}")

        parts = license_key.split(":")
        if len(parts) != 3:
            raise ValueError(f"Invalid license key format: expected 3 parts, got {len(parts)}")

        version, payload_b64, _ = parts
        if version != "1":
            raise ValueError(f"Unsupported license key version: {version}")

        # Decode the payload
        try:
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        except Exception as e:
            raise ValueError(f"Invalid payload encoding: {e}")

        # Update the key_id in the payload to the new signing key
        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid payload JSON: {e}")

        payload["key_id"] = new_key.key_id
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()

        # Sign with new key
        signature = hashlib.pbkdf2_hmac(
            "sha256",
            payload_json.encode(),
            new_key.key_material,
            100000,
        ).hex()
        signature_b64 = base64.urlsafe_b64encode(signature.encode()).decode()

        return f"1:{payload_b64}:{signature_b64}"

    def batch_issue(
        self,
        key: SigningKey,
        tier: LicenseTier,
        count: int,
        issued_to: str = "",
        expires_days: Optional[int] = None,
        prefix: str = "",
    ) -> list[str]:
        """Issue multiple license keys at once.

        Args:
            key: Signing key to sign with.
            tier: License tier.
            count: Number of keys to issue.
            issued_to: Company or developer name.
            expires_days: Days until expiration. None = perpetual.
            prefix: Optional prefix for issued_to (e.g., "Dev Team A - ").

        Returns:
            List of signed license key strings.
        """
        keys = []
        for i in range(count):
            name = f"{prefix}{issued_to}" if prefix else issued_to
            if not name and count > 1:
                name = f"License #{i + 1}"
            license_key = self.issue_license(
                key=key,
                tier=tier,
                issued_to=name,
                expires_days=expires_days,
            )
            keys.append(license_key)
        return keys