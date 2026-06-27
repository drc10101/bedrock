"""
Master key hierarchy and silo key derivation.

Key hierarchy:
  Master Key (256-bit, stored in env var or HSM)
    |
    +-- Silo Key (HKDF-SHA256, per-silo, per-version)
    |     |
    |     +-- Field Key (HKDF-SHA256, per-field-type within silo)
    |
    +-- E2EE Key Pair (ECDH-P256, per session)
    |
    +-- Audit Key (HKDF-SHA256, for audit chain integrity)

Key rotation: new silo keys are derived with incremented version numbers.
Old keys are retained for decryption but new data uses the latest version.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class MasterKey:
    """Master key metadata. The actual key material is never stored in code."""
    key_id: str               # Unique identifier
    created_at: datetime = None
    version: int = 1
    source: str = "env"        # "env", "hsm", "file"

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)


@dataclass
class SiloKey:
    """A derived key for a specific silo and version."""
    silo_name: str             # e.g., "medical", "identity"
    version: int               # Key version (incremented on rotation)
    hkdf_info: str             # e.g., "bedrock:silo:medical:v1"
    created_at: datetime = None
    parent_key_id: str = ""    # Master key that derived this key

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)


class KeyManager:
    """Manages the master key hierarchy and silo key derivation.

    Key derivation uses HKDF-SHA256 with silo-specific info strings.
    This ensures that compromising one silo's key does not reveal
    any other silo's key or the master key.
    """

    def derive_silo_key(self, master_key: bytes, silo_name: str,
                        version: int = 1) -> bytes:
        """Derive a 256-bit key for a specific silo using HKDF-SHA256."""
        raise NotImplementedError("B-103: Key Management")

    def derive_field_key(self, silo_key: bytes, field_type: str) -> bytes:
        """Derive a key for a specific field type within a silo."""
        raise NotImplementedError("B-103: Key Management")

    def rotate_silo_key(self, master_key: bytes, silo_name: str,
                        current_version: int) -> SiloKey:
        """Rotate a silo key by incrementing the version number.

        Old keys are retained for decryption. New data uses the new key.
        """
        raise NotImplementedError("B-103: Key Management")

    def get_active_key_version(self, silo_name: str) -> int:
        """Get the current active key version for a silo."""
        raise NotImplementedError("B-103: Key Management")