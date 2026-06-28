"""
Key rotation policy and master key rotation.

Key rotation is fundamental to Bedrock's security model:
- Silo keys are derived from the master key via HKDF
- Rotating the master key invalidates all derived keys
- A grace period allows old master keys to decrypt existing data
- Re-encryption migrates ciphertext from old keys to new keys

Rotation lifecycle:
  1. Generate new master key
  2. New master key becomes active (used for all new encryption)
  3. Old master key is retained in grace period (can still decrypt)
  4. After grace period, old master key is destroyed
  5. Any data still encrypted with old key must be re-encrypted before destruction

Rotation policy:
  - Interval: days between automatic rotations (default 90)
  - Grace period: days old key remains available (default 30)
  - Emergency: immediate rotation with shorter grace period (default 7)
"""

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bedrock.encryption.engine import FieldEncryptor
    from bedrock.key_management.keys import KeyManager


class RotationTrigger(Enum):
    """Why a key rotation was initiated."""

    SCHEDULED = "scheduled"  # Automatic time-based rotation
    MANUAL = "manual"  # Operator-initiated rotation
    EMERGENCY = "emergency"  # Security incident
    COMPLIANCE = "compliance"  # Regulatory requirement


class KeyState(Enum):
    """Lifecycle state of a master key."""

    ACTIVE = "active"  # Current key, used for new encryption
    GRACE = "grace"  # Old key, available for decryption only
    RETIRED = "retired"  # No longer available, data must be re-encrypted
    REVOKED = "revoked"  # Emergency revocation, key is destroyed


@dataclass
class MasterKeyRecord:
    """Metadata for a master key throughout its lifecycle."""

    key_id: str  # Unique identifier (hash of key material)
    version: int  # Monotonically increasing version number
    state: KeyState  # Current lifecycle state
    created_at: datetime  # When the key was created
    activated_at: datetime | None = None  # When it became the active key
    retired_at: datetime | None = None  # When it was retired
    revoked_at: datetime | None = None  # When it was revoked
    trigger: RotationTrigger | None = None  # What caused this key's creation
    predecessor_id: str | None = None  # Key this one replaced


@dataclass
class RotationPolicy:
    """Configuration for automatic key rotation.

    Attributes:
        rotation_interval_days: Days between automatic rotations (default 90)
        grace_period_days: Days old key remains decryptable (default 30)
        emergency_grace_days: Days old key remains decryptable after emergency rotation (default 7)
        max_grace_keys: Maximum number of grace-period keys retained simultaneously (default 3)
        auto_rotate: Whether to automatically rotate on schedule (default True)
    """

    rotation_interval_days: int = 90
    grace_period_days: int = 30
    emergency_grace_days: int = 7
    max_grace_keys: int = 3
    auto_rotate: bool = True


class KeyRotationManager:
    """Manages master key rotation lifecycle.

    Handles:
    - Master key generation and activation
    - Grace period management (old keys stay decryptable)
    - Scheduled and emergency rotation
    - Key retirement and revocation
    - Rotation history and audit trail

    Usage:
        from bedrock.key_management.keys import KeyManager

        km = KeyManager()
        master_key = KeyManager.generate_master_key()
        rotator = KeyRotationManager(km, master_key, RotationPolicy())

        # Rotate the master key
        new_key, record = rotator.rotate_master_key(trigger=RotationTrigger.MANUAL)

        # Re-encrypt data with the new key
        rotator.re_encrypt_silo(silo_name="medical")

        # Check if rotation is due
        if rotator.is_rotation_due():
            rotator.rotate_master_key(trigger=RotationTrigger.SCHEDULED)
    """

    def __init__(
        self, key_manager: "KeyManager", master_key: bytes, policy: RotationPolicy | None = None
    ) -> None:
        self._key_manager = key_manager
        self._active_master_key = master_key
        self._policy = policy or RotationPolicy()
        self._key_history: dict[str, bytes] = {}  # key_id -> key material (grace period)
        self._records: list[MasterKeyRecord] = []
        self._rotation_log: list[dict] = []

        # Register the initial master key
        initial_id = self._key_id(master_key)
        initial_record = MasterKeyRecord(
            key_id=initial_id,
            version=1,
            state=KeyState.ACTIVE,
            created_at=datetime.now(UTC),
            activated_at=datetime.now(UTC),
            trigger=RotationTrigger.MANUAL,
        )
        self._records.append(initial_record)

    @staticmethod
    def _key_id(key: bytes) -> str:
        """Generate a unique ID for a master key (SHA-256 hash, hex)."""
        import hashlib

        return hashlib.sha256(key).hexdigest()[:16]

    @property
    def active_key(self) -> bytes:
        """The current active master key."""
        return self._active_master_key

    @property
    def active_key_id(self) -> str:
        """ID of the current active master key."""
        return self._key_id(self._active_master_key)

    @property
    def active_key_version(self) -> int:
        """Version number of the current active master key."""
        if self._records:
            for r in reversed(self._records):
                if r.state == KeyState.ACTIVE:
                    return r.version
        return 1

    @property
    def policy(self) -> RotationPolicy:
        """Current rotation policy."""
        return self._policy

    def get_grace_keys(self) -> list[tuple[str, bytes]]:
        """Get all keys currently in grace period (available for decryption).

        Returns:
            List of (key_id, key_material) tuples for grace-period keys.
        """
        result = []
        now = datetime.now(UTC)
        for record in self._records:
            if record.state == KeyState.GRACE:
                # Check if grace period has expired
                activated = record.activated_at or record.created_at
                if record.trigger == RotationTrigger.EMERGENCY:
                    grace_days = self._policy.emergency_grace_days
                else:
                    grace_days = self._policy.grace_period_days

                expires = activated + timedelta(days=grace_days)
                if now < expires:
                    key_material = self._key_history.get(record.key_id)
                    if key_material is not None:
                        result.append((record.key_id, key_material))
        return result

    def is_rotation_due(self) -> bool:
        """Check if a scheduled rotation is due based on policy interval.

        Returns:
            True if the active key has been in use longer than the rotation interval.
        """
        if not self._policy.auto_rotate:
            return False

        now = datetime.now(UTC)
        active_record = None
        for r in reversed(self._records):
            if r.state == KeyState.ACTIVE:
                active_record = r
                break

        if active_record is None:
            return True  # No active key — rotate immediately

        activated = active_record.activated_at or active_record.created_at
        rotation_deadline = activated + timedelta(days=self._policy.rotation_interval_days)
        return now >= rotation_deadline

    def rotate_master_key(
        self, trigger: RotationTrigger = RotationTrigger.MANUAL, new_key: bytes | None = None
    ) -> tuple[bytes, MasterKeyRecord]:
        """Rotate the master key.

        Generates a new 256-bit master key (or uses the provided one),
        moves the current active key to grace period, and activates the new key.

        Args:
            trigger: Why the rotation was initiated
            new_key: Optional pre-generated key material. If None, generates one.

        Returns:
            Tuple of (new_key_material, new_key_record)
        """
        if new_key is None:
            new_key = os.urandom(32)  # 256-bit

        now = datetime.now(UTC)
        old_key_id = self._key_id(self._active_master_key)
        new_key_id = self._key_id(new_key)

        # Move current active key to grace period
        old_record = None
        for r in reversed(self._records):
            if r.state == KeyState.ACTIVE:
                old_record = r
                break

        if old_record is not None:
            old_record.state = KeyState.GRACE
            old_record.retired_at = now
            # Store old key material for grace period decryption
            self._key_history[old_record.key_id] = self._active_master_key

        # Create new key record
        new_version = (old_record.version + 1) if old_record else 1
        new_record = MasterKeyRecord(
            key_id=new_key_id,
            version=new_version,
            state=KeyState.ACTIVE,
            created_at=now,
            activated_at=now,
            trigger=trigger,
            predecessor_id=old_key_id,
        )
        self._records.append(new_record)

        # Activate new key
        self._active_master_key = new_key

        # Clear silo key cache — all derived keys must be re-derived from new master
        self._key_manager._silo_key_cache.clear()
        self._key_manager._active_versions.clear()
        # Note: _retired_keys are preserved for old-version silo key lookups

        # Log the rotation
        self._rotation_log.append(
            {
                "timestamp": now.isoformat(),
                "trigger": trigger.value,
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "old_version": old_record.version if old_record else 0,
                "new_version": new_version,
            }
        )

        # Enforce max_grace_keys — retire oldest grace keys beyond limit
        self._enforce_grace_limit()

        return new_key, new_record

    def _enforce_grace_limit(self) -> None:
        """Retire oldest grace keys beyond the max_grace_keys limit."""
        grace_records = [r for r in self._records if r.state == KeyState.GRACE]
        while len(grace_records) > self._policy.max_grace_keys:
            oldest = min(grace_records, key=lambda r: r.activated_at or r.created_at)
            self._retire_key(oldest.key_id)
            grace_records.remove(oldest)

    def _retire_key(self, key_id: str) -> None:
        """Retire a grace-period key, removing its material from memory."""
        for r in self._records:
            if r.key_id == key_id and r.state == KeyState.GRACE:
                r.state = KeyState.RETIRED
                r.retired_at = datetime.now(UTC)
                break
        # Destroy key material
        self._key_history.pop(key_id, None)

    def revoke_key(self, key_id: str) -> None:
        """Emergency revoke a key. Key material is immediately destroyed.

        This should only be used when a key is known to be compromised.
        Any data encrypted with this key that hasn't been re-encrypted
        will become unrecoverable.

        Args:
            key_id: The key to revoke
        """
        for r in self._records:
            if r.key_id == key_id and r.state in (KeyState.ACTIVE, KeyState.GRACE):
                r.state = KeyState.REVOKED
                r.revoked_at = datetime.now(UTC)
                break
        # Immediately destroy key material
        self._key_history.pop(key_id, None)

        if key_id == self.active_key_id:
            # Active key revoked — must rotate immediately
            # This is a critical state; the caller must provide a new key
            raise RuntimeError(
                f"Active key {key_id} has been revoked. "
                "Call rotate_master_key() immediately to establish a new active key."
            )

    def get_decrypt_key(self, silo_name: str, version: int | None = None) -> bytes:
        """Get the appropriate key for decryption.

        If a specific version is requested, derives it from the active key.
        If no version is specified, uses the active key.

        For grace-period keys, the old master key material is used to derive
        the silo key at the requested version.

        Args:
            silo_name: Which silo's key to derive
            version: Optional specific version (for rotated keys)

        Returns:
            The derived silo key for decryption
        """
        if version is not None:
            # Check if we need a grace-period key
            # First try deriving from the active key
            try:
                return bytes(
                    self._key_manager.derive_silo_key(self._active_master_key, silo_name, version)
                )
            except Exception:
                pass

            # Check grace keys
            for _key_id, key_material in self.get_grace_keys():
                try:
                    return bytes(
                        self._key_manager.derive_silo_key(key_material, silo_name, version)
                    )
                except Exception:
                    continue

            raise ValueError(
                f"No key available for silo={silo_name} version={version}. "
                "The key may have been retired or revoked."
            )

        return bytes(self._key_manager.get_silo_key(self._active_master_key, silo_name))

    def re_encrypt_field(
        self,
        field_encryptor: "FieldEncryptor",
        ciphertext: str,
        silo: str,
        record_id: str,
        scope: str,
        old_master_key: bytes | None = None,
    ) -> str:
        """Re-encrypt a single field with the current active key.

        Args:
            field_encryptor: FieldEncryptor instance (must use the current active key)
            ciphertext: Current ciphertext (encrypted with old key)
            silo: Silo name
            record_id: Record ID
            scope: Access scope
            old_master_key: The previous master key used to encrypt the ciphertext.
                If None, attempts to use grace keys.

        Returns:
            New ciphertext encrypted with the current active key
        """
        # If the old master key is provided, use it to create a decryptor
        if old_master_key is not None:
            from bedrock.encryption.engine import FieldEncryptor

            decrypt_fe = FieldEncryptor(self._key_manager, old_master_key)
        else:
            # Try grace keys to find one that decrypts
            from bedrock.encryption.engine import FieldEncryptor

            decrypt_fe = None
            for _key_id, key_material in self.get_grace_keys():
                candidate = FieldEncryptor(self._key_manager, key_material)
                try:
                    plaintext = candidate.decrypt(ciphertext, silo, record_id, scope)
                    # Found the right grace key
                    new_ciphertext = str(field_encryptor.encrypt(plaintext, silo, record_id, scope))
                    return new_ciphertext
                except ValueError:
                    continue
            raise ValueError(
                f"Cannot decrypt ciphertext for silo={silo} record={record_id}. "
                "No available grace key matches."
            )

        # Decrypt with old key, encrypt with new key
        if decrypt_fe is None:
            raise ValueError("No decryptor available for re-encryption")
        plaintext = decrypt_fe.decrypt(ciphertext, silo, record_id, scope)
        new_ciphertext = str(field_encryptor.encrypt(plaintext, silo, record_id, scope))

        return new_ciphertext

    def get_rotation_history(self) -> list[dict]:
        """Get the full rotation audit log.

        Returns:
            List of rotation event dicts with timestamp, trigger, key IDs, versions
        """
        return list(self._rotation_log)

    def get_key_records(self) -> list[MasterKeyRecord]:
        """Get all key lifecycle records.

        Returns:
            List of MasterKeyRecord for all keys ever created
        """
        return list(self._records)

    def retire_expired_keys(self) -> list[str]:
        """Retire all grace-period keys whose grace period has expired.

        Returns:
            List of key IDs that were retired
        """
        retired_ids = []
        now = datetime.now(UTC)

        for record in self._records:
            if record.state != KeyState.GRACE:
                continue

            activated = record.activated_at or record.created_at
            if record.trigger == RotationTrigger.EMERGENCY:
                grace_days = self._policy.emergency_grace_days
            else:
                grace_days = self._policy.grace_period_days

            expires = activated + timedelta(days=grace_days)
            if now >= expires:
                self._retire_key(record.key_id)
                retired_ids.append(record.key_id)

        return retired_ids
