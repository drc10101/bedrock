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

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class MasterKey:
    """Master key metadata. The actual key material is never stored in code."""

    key_id: str  # Unique identifier
    created_at: datetime = None
    version: int = 1
    source: str = "env"  # "env", "hsm", "file"

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(UTC)


@dataclass
class SiloKey:
    """A derived key for a specific silo and version."""

    silo_name: str  # e.g., "medical", "identity"
    version: int  # Key version (incremented on rotation)
    hkdf_info: str  # e.g., "bedrock:silo:medical:v1"
    created_at: datetime = None
    parent_key_id: str = ""  # Master key that derived this key

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(UTC)


class KeyManager:
    """Manages the master key hierarchy and silo key derivation.

    Key derivation uses HKDF-SHA256 with silo-specific info strings.
    This ensures that compromising one silo's key does not reveal
    any other silo's key or the master key.

    HKDF info format: bedrock:silo:{silo_name}:v{version}
    This ensures:
    1. Different silos get different keys from the same master key
    2. Different versions of the same silo get different keys
    3. Key rotation is just incrementing the version number
    """

    def __init__(self, config=None):
        self._config = config
        # Cache of derived keys: (master_key_hash, silo_name, version) -> bytes
        # We hash the master key to use as part of the cache key so different
        # master keys never collide.
        self._silo_key_cache: dict[tuple[bytes, str, int], bytes] = {}
        # Track active versions: silo_name -> (master_key_hash, active_version)
        self._active_versions: dict[str, tuple[bytes, int]] = {}
        # Retired keys for decryption: (master_key_hash, silo_name, version) -> bytes
        self._retired_keys: dict[tuple[bytes, str, int], bytes] = {}

    @staticmethod
    def _key_id(master_key: bytes) -> bytes:
        """Hash the master key for use as a cache key identifier."""
        return hashlib.sha256(master_key).digest()

    def derive_silo_key(self, master_key: bytes, silo_name: str, version: int = 1) -> bytes:
        """Derive a 256-bit key for a specific silo using HKDF-SHA256.

        The info string includes the silo name and version, ensuring:
        - Different silos get different keys
        - Different versions of the same silo get different keys
        - The same (silo, version) always produces the same key

        Args:
            master_key: 256-bit master key material
            silo_name: Name of the silo (e.g., "medical", "identity")
            version: Key version (incremented on rotation)

        Returns:
            256-bit derived key for this silo and version
        """
        mk_id = self._key_id(master_key)
        cache_key = (mk_id, silo_name, version)
        if cache_key in self._silo_key_cache:
            return self._silo_key_cache[cache_key]

        info = f"bedrock:silo:{silo_name}:v{version}".encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=None,  # No salt — master key provides entropy
            info=info,
        )
        derived_key = hkdf.derive(master_key)

        self._silo_key_cache[cache_key] = derived_key

        # Track active version (store per-master-key)
        mk_id = self._key_id(master_key)
        entry = self._active_versions.get(silo_name)
        current = entry[1] if entry and entry[0] == mk_id else 0
        if version > current:
            self._active_versions[silo_name] = (mk_id, version)

        return derived_key

    def derive_field_key(self, silo_key: bytes, field_type: str) -> bytes:
        """Derive a key for a specific field type within a silo.

        This allows field-level key separation within a silo.
        Compromising one field's key doesn't reveal other fields.

        Args:
            silo_key: The silo's derived key
            field_type: Type of field (e.g., "ssn", "dob", "diagnosis")

        Returns:
            256-bit derived key for this field type
        """
        info = f"bedrock:field:{field_type}".encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        return hkdf.derive(silo_key)

    def rotate_silo_key(self, master_key: bytes, silo_name: str, current_version: int) -> SiloKey:
        """Rotate a silo key by incrementing the version number.

        Old keys are retained for decryption. New data uses the new key.
        The old version's key is moved to the retired keys cache.

        Args:
            master_key: 256-bit master key material
            silo_name: Name of the silo to rotate
            current_version: Current active version

        Returns:
            SiloKey metadata for the new version
        """
        new_version = current_version + 1
        mk_id = self._key_id(master_key)

        # Retire the current key (keep it for decryption)
        old_cache_key = (mk_id, silo_name, current_version)
        old_key = self._silo_key_cache.get(old_cache_key)
        if old_key:
            self._retired_keys[(mk_id, silo_name, current_version)] = old_key

        # Derive the new key
        self.derive_silo_key(master_key, silo_name, new_version)
        self._active_versions[silo_name] = (mk_id, new_version)

        return SiloKey(
            silo_name=silo_name,
            version=new_version,
            hkdf_info=f"bedrock:silo:{silo_name}:v{new_version}",
            parent_key_id="master",
        )

    def get_active_key_version(self, silo_name: str) -> int:
        """Get the current active key version for a silo.

        Returns 0 if no key has been derived for this silo yet.
        """
        entry = self._active_versions.get(silo_name)
        return entry[1] if entry else 0

    def get_silo_key(self, master_key: bytes, silo_name: str, version: int | None = None) -> bytes:
        """Get a silo key, deriving it if necessary.

        Args:
            master_key: 256-bit master key material
            silo_name: Name of the silo
            version: Key version, or None for active version

        Returns:
            256-bit derived key for this silo and version
        """
        if version is None:
            version = self.get_active_key_version(silo_name)
            if version == 0:
                version = 1  # Default to version 1
        return self.derive_silo_key(master_key, silo_name, version)

    def get_retired_key(
        self, silo_name: str, version: int, master_key: bytes | None = None
    ) -> bytes | None:
        """Get a retired (old version) silo key for decryption.

        Returns None if the key is not in the retired cache.
        """
        if master_key is None:
            return None
        mk_id = self._key_id(master_key)
        return self._retired_keys.get((mk_id, silo_name, version))

    @staticmethod
    def generate_master_key() -> bytes:
        """Generate a new 256-bit master key using OS CSPRNG.

        This should be called once during initial setup and stored securely
        (env var, HSM, or encrypted file). Never store in code.
        """
        return os.urandom(32)
