"""Tests for Key Management — HKDF key derivation, hierarchy, rotation."""

import pytest
from bedrock.key_management.keys import KeyManager, MasterKey, SiloKey


class TestKeyManager:
    """Test HKDF key derivation and rotation."""

    def setup_method(self):
        """Create a fresh KeyManager and master key for each test."""
        self.km = KeyManager()
        self.master_key = KeyManager.generate_master_key()

    def test_generate_master_key_length(self):
        key = KeyManager.generate_master_key()
        assert len(key) == 32  # 256 bits

    def test_generate_master_key_randomness(self):
        """Two generated keys should never be the same."""
        key1 = KeyManager.generate_master_key()
        key2 = KeyManager.generate_master_key()
        assert key1 != key2

    def test_derive_silo_key_deterministic(self):
        """Same master key + same silo = same derived key."""
        key1 = self.km.derive_silo_key(self.master_key, "medical", version=1)
        key2 = self.km.derive_silo_key(self.master_key, "medical", version=1)
        assert key1 == key2
        assert len(key1) == 32

    def test_derive_silo_key_different_silos(self):
        """Different silos get different keys from the same master key."""
        key_med = self.km.derive_silo_key(self.master_key, "medical", version=1)
        key_id = self.km.derive_silo_key(self.master_key, "identity", version=1)
        assert key_med != key_id

    def test_derive_silo_key_different_versions(self):
        """Different versions of the same silo get different keys."""
        key_v1 = self.km.derive_silo_key(self.master_key, "medical", version=1)
        key_v2 = self.km.derive_silo_key(self.master_key, "medical", version=2)
        assert key_v1 != key_v2

    def test_derive_silo_key_different_masters(self):
        """Different master keys produce different derived keys."""
        km2 = KeyManager()  # Separate KeyManager to avoid cache
        master2 = KeyManager.generate_master_key()
        key1 = self.km.derive_silo_key(self.master_key, "medical", version=1)
        key2 = km2.derive_silo_key(master2, "medical", version=1)
        assert key1 != key2

    def test_derive_silo_key_different_masters_same_manager(self):
        """Same KeyManager with different master keys produces different derived keys."""
        master2 = KeyManager.generate_master_key()
        key1 = self.km.derive_silo_key(self.master_key, "medical", version=1)
        key2 = self.km.derive_silo_key(master2, "medical", version=1)
        assert key1 != key2

    def test_derive_field_key(self):
        """Field keys are derived from silo keys."""
        silo_key = self.km.derive_silo_key(self.master_key, "medical", version=1)
        field_key_ssn = self.km.derive_field_key(silo_key, "ssn")
        field_key_dob = self.km.derive_field_key(silo_key, "dob")
        assert field_key_ssn != field_key_dob
        assert len(field_key_ssn) == 32

    def test_derive_field_key_deterministic(self):
        """Same silo key + same field = same derived key."""
        silo_key = self.km.derive_silo_key(self.master_key, "medical", version=1)
        fk1 = self.km.derive_field_key(silo_key, "ssn")
        fk2 = self.km.derive_field_key(silo_key, "ssn")
        assert fk1 == fk2

    def test_rotate_silo_key(self):
        """Rotating a key increments the version."""
        # First derivation
        self.km.derive_silo_key(self.master_key, "medical", version=1)
        assert self.km.get_active_key_version("medical") == 1

        # Rotate
        result = self.km.rotate_silo_key(self.master_key, "medical", current_version=1)
        assert result.version == 2
        assert result.silo_name == "medical"
        assert self.km.get_active_key_version("medical") == 2

    def test_rotate_preserves_old_key(self):
        """Old key is still derivable after rotation."""
        key_v1 = self.km.derive_silo_key(self.master_key, "medical", version=1)
        self.km.rotate_silo_key(self.master_key, "medical", current_version=1)
        key_v1_after = self.km.derive_silo_key(self.master_key, "medical", version=1)
        assert key_v1 == key_v1_after  # Same key material

    def test_rotate_new_key_differs(self):
        """New version key differs from old."""
        key_v1 = self.km.derive_silo_key(self.master_key, "medical", version=1)
        self.km.rotate_silo_key(self.master_key, "medical", current_version=1)
        key_v2 = self.km.derive_silo_key(self.master_key, "medical", version=2)
        assert key_v1 != key_v2

    def test_get_silo_key_default_version(self):
        """get_silo_key with no version returns active version."""
        self.km.derive_silo_key(self.master_key, "medical", version=1)
        key_default = self.km.get_silo_key(self.master_key, "medical")
        key_v1 = self.km.derive_silo_key(self.master_key, "medical", version=1)
        assert key_default == key_v1

    def test_get_silo_key_no_prior_version(self):
        """get_silo_key with no prior derivation defaults to v1."""
        key = self.km.get_silo_key(self.master_key, "new_silo")
        assert len(key) == 32

    def test_get_active_key_version_unknown_silo(self):
        """Unknown silo returns 0."""
        assert self.km.get_active_key_version("nonexistent") == 0

    def test_master_key_metadata(self):
        mk = MasterKey(key_id="test-key-1")
        assert mk.key_id == "test-key-1"
        assert mk.version == 1
        assert mk.source == "env"
        assert mk.created_at is not None

    def test_silo_key_metadata(self):
        sk = SiloKey(silo_name="medical", version=2,
                     hkdf_info="bedrock:silo:medical:v2")
        assert sk.silo_name == "medical"
        assert sk.version == 2
        assert sk.hkdf_info == "bedrock:silo:medical:v2"
        assert sk.created_at is not None