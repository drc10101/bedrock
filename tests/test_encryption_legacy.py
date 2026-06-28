"""Tests for LegacyDecryptor and simplified encryption API.

Verifies that Bedrock can decrypt InFill-encrypted data and that
encrypt_simple/decrypt_auto work as drop-in replacements.
"""

import base64
import secrets

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from bedrock.encryption.engine import EncryptionEngine, FieldEncryptor
from bedrock.encryption.legacy import LegacyDecryptor, _is_bedrock_v2, is_infill_legacy
from bedrock.encryption.version import CiphertextFormat
from bedrock.key_management.keys import KeyManager


# ---------------------------------------------------------------------------
# Helpers: replicate InFill's exact encryption logic
# ---------------------------------------------------------------------------

_INFILL_HKDF_INFO = b"infill-field-encryption-aes256gcm"
_INFILL_V2_PREFIX = "v2:"


def _derive_infill_aes256_key(base_key: bytes) -> bytes:
    """Derive AES-256 key exactly like InFill's _derive_aes256_key()."""
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=_INFILL_HKDF_INFO,
    )
    return hkdf.derive(base_key)


def infill_encrypt_field(plaintext: str, base_key: bytes) -> str:
    """Encrypt exactly like InFill's security.encrypt_field()."""
    aes256_key = _derive_infill_aes256_key(base_key)
    aesgcm = AESGCM(aes256_key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    combined = nonce + ct
    encoded = base64.b64encode(combined).decode("ascii")
    return f"{_INFILL_V2_PREFIX}{encoded}"


def infill_encrypt_fernet(plaintext: str, base_key: bytes) -> str:
    """Encrypt exactly like InFill's legacy Fernet path."""
    f = Fernet(base_key)
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def base_key():
    """Generate a Fernet-compatible base key (same format as .encryption_key)."""
    return Fernet.generate_key()


@pytest.fixture
def master_key():
    """Generate a Bedrock master key."""
    return KeyManager.generate_master_key()


@pytest.fixture
def km():
    """KeyManager instance."""
    return KeyManager()


@pytest.fixture
def encryptor(km, master_key):
    """FieldEncryptor instance."""
    return FieldEncryptor(km, master_key)


@pytest.fixture
def legacy_decryptor(base_key):
    """LegacyDecryptor with InFill's base key."""
    return LegacyDecryptor(base_key)


# ---------------------------------------------------------------------------
# LegacyDecryptor tests
# ---------------------------------------------------------------------------

class TestLegacyDecryptor:
    """Test decryption of InFill's v2 and Fernet ciphertext formats."""

    def test_decrypt_infill_v2(self, base_key, legacy_decryptor):
        """LegacyDecryptor can decrypt InFill v2 (AES-256-GCM, no AAD)."""
        plaintext = "123-45-6789"
        ciphertext = infill_encrypt_field(plaintext, base_key)
        result = legacy_decryptor.decrypt(ciphertext)
        assert result == plaintext

    def test_decrypt_infill_v2_empty_string(self, base_key, legacy_decryptor):
        """LegacyDecryptor handles empty string in InFill v2 format."""
        ciphertext = infill_encrypt_field("", base_key)
        result = legacy_decryptor.decrypt(ciphertext)
        assert result == ""

    def test_decrypt_infill_v2_unicode(self, base_key, legacy_decryptor):
        """LegacyDecryptor handles unicode in InFill v2 format."""
        plaintext = "Patient: José García — 心脏病"
        ciphertext = infill_encrypt_field(plaintext, base_key)
        result = legacy_decryptor.decrypt(ciphertext)
        assert result == plaintext

    def test_decrypt_fernet(self, base_key, legacy_decryptor):
        """LegacyDecryptor can decrypt legacy Fernet ciphertext."""
        plaintext = "old-patient-data"
        ciphertext = infill_encrypt_fernet(plaintext, base_key)
        result = legacy_decryptor.decrypt(ciphertext)
        assert result == plaintext

    def test_decrypt_fernet_empty_string(self, base_key, legacy_decryptor):
        """LegacyDecryptor handles empty string in Fernet format."""
        ciphertext = infill_encrypt_fernet("", base_key)
        result = legacy_decryptor.decrypt(ciphertext)
        assert result == ""

    def test_is_legacy_infill_v2(self, base_key):
        """InFill v2 ciphertext is detected as legacy (no AAD)."""
        ciphertext = infill_encrypt_field("test", base_key)
        assert is_infill_legacy(ciphertext) is True

    def test_is_legacy_fernet(self, base_key):
        """Fernet ciphertext is detected as legacy."""
        ciphertext = infill_encrypt_fernet("test", base_key)
        assert is_infill_legacy(ciphertext) is True

    def test_is_not_legacy_bedrock_v2(self, encryptor):
        """Bedrock v2 ciphertext (with AAD) is NOT detected as legacy."""
        ciphertext = encryptor.encrypt("test", silo="identity", record_id="id1", scope="read")
        assert is_infill_legacy(ciphertext) is False

    def test_infill_v2_different_data_produces_different_ct(self, base_key):
        """Different plaintext produces different ciphertext."""
        ct1 = infill_encrypt_field("data-A", base_key)
        ct2 = infill_encrypt_field("data-B", base_key)
        assert ct1 != ct2

    def test_infill_v2_same_data_different_nonce(self, base_key):
        """Same plaintext encrypted twice produces different ciphertext (random nonce)."""
        ct1 = infill_encrypt_field("same-data", base_key)
        ct2 = infill_encrypt_field("same-data", base_key)
        assert ct1 != ct2

    def test_wrong_key_fails(self):
        """Decrypting with wrong key raises Exception."""
        key1 = Fernet.generate_key()
        key2 = Fernet.generate_key()
        ciphertext = infill_encrypt_field("secret", key1)
        wrong_decryptor = LegacyDecryptor(key2)
        with pytest.raises(Exception):
            wrong_decryptor.decrypt(ciphertext)


# ---------------------------------------------------------------------------
# Bedrock v2 format detection tests
# ---------------------------------------------------------------------------

class TestFormatDetection:
    """Test distinguishing Bedrock v2 from InFill v2 ciphertext."""

    def test_bedrock_v2_detected(self, encryptor):
        """Bedrock v2 ciphertext is correctly identified."""
        ct = encryptor.encrypt("test", silo="identity", record_id="id1", scope="read")
        assert _is_bedrock_v2(ct) is True

    def test_infill_v2_not_detected_as_bedrock(self, base_key):
        """InFill v2 ciphertext is NOT identified as Bedrock v2."""
        ct = infill_encrypt_field("test", base_key)
        assert _is_bedrock_v2(ct) is False

    def test_format_detect_returns_v2_for_both(self, base_key, encryptor):
        """CiphertextFormat.detect returns V2_GCM for both formats."""
        infill_ct = infill_encrypt_field("test", base_key)
        bedrock_ct = encryptor.encrypt("test", silo="identity", record_id="id1", scope="read")
        assert CiphertextFormat.detect(infill_ct) == CiphertextFormat.V2_GCM
        assert CiphertextFormat.detect(bedrock_ct) == CiphertextFormat.V2_GCM


# ---------------------------------------------------------------------------
# encrypt_simple / decrypt_auto tests
# ---------------------------------------------------------------------------

class TestSimplifiedAPI:
    """Test encrypt_simple() and decrypt_auto() on FieldEncryptor."""

    def test_encrypt_simple_roundtrip(self, encryptor):
        """encrypt_simple produces ciphertext that decrypt_auto handles."""
        plaintext = "SSN-123-45-6789"
        ct = encryptor.encrypt_simple(plaintext)
        pt = encryptor.decrypt_auto(ct)
        assert pt == plaintext

    def test_encrypt_simple_with_custom_silo(self, encryptor):
        """encrypt_simple with custom silo uses that silo for AAD."""
        ct = encryptor.encrypt_simple("data", silo="medical", record_id="patient-1", scope="write")
        pt = encryptor.decrypt_auto(ct, silo="medical", record_id="patient-1", scope="write")
        assert pt == "data"

    def test_encrypt_simple_aad_mismatch_fails(self, encryptor):
        """encrypt_simple ciphertext still enforces AAD validation."""
        ct = encryptor.encrypt_simple("secret", silo="identity", record_id="id1", scope="read")
        with pytest.raises(ValueError, match="AAD context mismatch"):
            encryptor.decrypt_auto(ct, silo="medical", record_id="id1", scope="read")

    def test_decrypt_auto_bedrock_v2(self, encryptor):
        """decrypt_auto handles Bedrock v2 ciphertext."""
        ct = encryptor.encrypt("test", silo="identity", record_id="id1", scope="read")
        pt = encryptor.decrypt_auto(ct, silo="identity", record_id="id1", scope="read")
        assert pt == "test"

    def test_decrypt_auto_infill_v2(self, encryptor, base_key):
        """decrypt_auto handles InFill v2 ciphertext with legacy_key."""
        ct = infill_encrypt_field("legacy-data", base_key)
        pt = encryptor.decrypt_auto(ct, legacy_key=base_key)
        assert pt == "legacy-data"

    def test_decrypt_auto_fernet(self, encryptor, base_key):
        """decrypt_auto handles Fernet ciphertext with legacy_key."""
        ct = infill_encrypt_fernet("old-data", base_key)
        pt = encryptor.decrypt_auto(ct, legacy_key=base_key)
        assert pt == "old-data"

    def test_decrypt_auto_infill_v2_without_legacy_key_raises(self, encryptor, base_key):
        """decrypt_auto raises ValueError for InFill v2 without legacy_key."""
        ct = infill_encrypt_field("data", base_key)
        with pytest.raises(ValueError, match="legacy_key"):
            encryptor.decrypt_auto(ct)

    def test_decrypt_auto_fernet_without_legacy_key_raises(self, encryptor, base_key):
        """decrypt_auto raises ValueError for Fernet without legacy_key."""
        ct = infill_encrypt_fernet("data", base_key)
        with pytest.raises(ValueError, match="legacy_key"):
            encryptor.decrypt_auto(ct)


# ---------------------------------------------------------------------------
# Migration scenario tests
# ---------------------------------------------------------------------------

class TestMigrationScenario:
    """Test the full InFill migration path: legacy decrypt → re-encrypt → Bedrock."""

    def test_migrate_infill_v2_to_bedrock(self, encryptor, base_key):
        """Decrypt InFill v2 data, re-encrypt with Bedrock, verify roundtrip."""
        # 1. InFill-encrypted data (no AAD)
        original = "patient-ssn-123-45-6789"
        infill_ct = infill_encrypt_field(original, base_key)

        # 2. Decrypt via legacy path
        plaintext = encryptor.decrypt_auto(infill_ct, legacy_key=base_key)
        assert plaintext == original

        # 3. Re-encrypt with Bedrock (with AAD)
        bedrock_ct = encryptor.encrypt_simple(plaintext, silo="identity", record_id="patient-1")

        # 4. Decrypt with Bedrock (no legacy_key needed)
        result = encryptor.decrypt_auto(
            bedrock_ct, silo="identity", record_id="patient-1"
        )
        assert result == original

        # 5. Verify Bedrock v2 is NOT legacy
        assert is_infill_legacy(bedrock_ct) is False

    def test_migrate_fernet_to_bedrock(self, encryptor, base_key):
        """Decrypt Fernet data, re-encrypt with Bedrock, verify roundtrip."""
        # 1. Old Fernet-encrypted data
        original = "old-insurance-number"
        fernet_ct = infill_encrypt_fernet(original, base_key)

        # 2. Decrypt via legacy path
        plaintext = encryptor.decrypt_auto(fernet_ct, legacy_key=base_key)
        assert plaintext == original

        # 3. Re-encrypt with Bedrock
        bedrock_ct = encryptor.encrypt_simple(plaintext, silo="identity", record_id="ins-1")

        # 4. Decrypt with Bedrock
        result = encryptor.decrypt_auto(
            bedrock_ct, silo="identity", record_id="ins-1"
        )
        assert result == original

    def test_lazy_migration_on_read(self, encryptor, base_key):
        """Simulate lazy migration: decrypt old, encrypt new, store new."""
        data_items = ["SSN-111", "DOB-1980-01-01", "Address-123 Main St"]
        migrated = {}

        for i, plaintext in enumerate(data_items):
            # Old data encrypted with InFill
            old_ct = infill_encrypt_field(plaintext, base_key)

            # Read: decrypt old
            decrypted = encryptor.decrypt_auto(old_ct, legacy_key=base_key)
            assert decrypted == plaintext

            # Write: re-encrypt with Bedrock
            new_ct = encryptor.encrypt_simple(decrypted, silo="identity", record_id=f"record-{i}")

            # Verify new ciphertext is not legacy
            assert is_infill_legacy(new_ct) is False

            # Store migrated
            migrated[f"record-{i}"] = new_ct

        # Verify all migrated data decrypts correctly
        for i, plaintext in enumerate(data_items):
            ct = migrated[f"record-{i}"]
            pt = encryptor.decrypt_auto(ct, silo="identity", record_id=f"record-{i}")
            assert pt == plaintext