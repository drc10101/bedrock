"""Tests for Encryption Engine — field-level encryption and E2EE."""

import pytest
from bedrock.encryption.engine import EncryptionEngine, FieldEncryptor, E2EEDeliverer
from bedrock.encryption.aad import AAD, build_aad
from bedrock.encryption.version import CiphertextFormat
from bedrock.key_management.keys import KeyManager


class TestFieldEncryptor:
    """Test field-level AES-256-GCM encryption with AAD binding."""

    def setup_method(self):
        self.km = KeyManager()
        self.master_key = KeyManager.generate_master_key()
        self.encryptor = FieldEncryptor(self.km, self.master_key)

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt returns original plaintext."""
        plaintext = "123-45-6789"
        ct = self.encryptor.encrypt(plaintext, silo="identity", record_id="crimson-arctic-fox", scope="read")
        pt = self.encryptor.decrypt(ct, silo="identity", record_id="crimson-arctic-fox", scope="read")
        assert pt == plaintext

    def test_encrypt_produces_v2_prefix(self):
        """Encrypted output starts with v2: prefix."""
        ct = self.encryptor.encrypt("test", silo="identity", record_id="id1", scope="read")
        assert ct.startswith("v2:")

    def test_different_silos_different_ciphertexts(self):
        """Same plaintext encrypted under different silo keys produces different ciphertexts."""
        ct_med = self.encryptor.encrypt("test", silo="medical", record_id="id1", scope="read")
        ct_id = self.encryptor.encrypt("test", silo="identity", record_id="id1", scope="read")
        assert ct_med != ct_id

    def test_same_plaintext_different_ciphertexts(self):
        """Encrypting the same plaintext twice produces different ciphertexts (random nonce)."""
        ct1 = self.encryptor.encrypt("test", silo="identity", record_id="id1", scope="read")
        ct2 = self.encryptor.encrypt("test", silo="identity", record_id="id1", scope="read")
        assert ct1 != ct2  # Different nonces

    def test_aad_mismatch_wrong_silo(self):
        """Decrypting with wrong silo fails (AAD context mismatch)."""
        ct = self.encryptor.encrypt("secret", silo="medical", record_id="id1", scope="read")
        with pytest.raises(ValueError, match="AAD context mismatch"):
            self.encryptor.decrypt(ct, silo="identity", record_id="id1", scope="read")

    def test_aad_mismatch_wrong_record(self):
        """Decrypting with wrong record_id fails (record swapping prevention)."""
        ct = self.encryptor.encrypt("secret", silo="identity", record_id="record-A", scope="read")
        with pytest.raises(ValueError, match="AAD context mismatch"):
            self.encryptor.decrypt(ct, silo="identity", record_id="record-B", scope="read")

    def test_aad_mismatch_wrong_scope(self):
        """Decrypting with wrong scope fails (scope escalation prevention)."""
        ct = self.encryptor.encrypt("secret", silo="identity", record_id="id1", scope="read")
        with pytest.raises(ValueError, match="AAD context mismatch"):
            self.encryptor.decrypt(ct, silo="identity", record_id="id1", scope="write")

    def test_empty_string(self):
        """Encrypt and decrypt empty string."""
        ct = self.encryptor.encrypt("", silo="identity", record_id="id1", scope="read")
        pt = self.encryptor.decrypt(ct, silo="identity", record_id="id1", scope="read")
        assert pt == ""

    def test_long_string(self):
        """Encrypt and decrypt a long string."""
        plaintext = "A" * 10000
        ct = self.encryptor.encrypt(plaintext, silo="identity", record_id="id1", scope="read")
        pt = self.encryptor.decrypt(ct, silo="identity", record_id="id1", scope="read")
        assert pt == plaintext

    def test_unicode_string(self):
        """Encrypt and decrypt unicode characters."""
        plaintext = "Patient: José García — diagnosed with 心脏病"
        ct = self.encryptor.encrypt(plaintext, silo="medical", record_id="id1", scope="read")
        pt = self.encryptor.decrypt(ct, silo="medical", record_id="id1", scope="read")
        assert pt == plaintext

    def test_encrypt_with_custom_operation(self):
        """Encrypt with custom operation type."""
        ct = self.encryptor.encrypt("audit entry", silo="audit", record_id="id1", scope="write", operation="audit")
        pt = self.encryptor.decrypt(ct, silo="audit", record_id="id1", scope="write", operation="audit")
        assert pt == "audit entry"

    def test_ciphertext_not_plaintext(self):
        """Ciphertext should not contain the plaintext."""
        plaintext = "sensitive-ssn-data"
        ct = self.encryptor.encrypt(plaintext, silo="identity", record_id="id1", scope="read")
        assert plaintext not in ct

    def test_decrypt_with_key_version(self):
        """Decrypt with an explicit key version after rotation."""
        # Encrypt with version 1
        self.km.derive_silo_key(self.master_key, "medical", version=1)
        ct = self.encryptor.encrypt("secret", silo="medical", record_id="id1", scope="read")

        # Rotate to version 2
        self.km.rotate_silo_key(self.master_key, "medical", current_version=1)

        # Decrypt with explicit version 1 (the key used for encryption)
        pt = self.encryptor.decrypt(ct, silo="medical", record_id="id1", scope="read", key_version=1)
        assert pt == "secret"

    def test_embedded_aad_preserves_timestamp(self):
        """The AAD timestamp is frozen at encryption time and preserved in ciphertext."""
        import time
        ct = self.encryptor.encrypt("data", silo="identity", record_id="id1", scope="read")
        time.sleep(0.01)  # Small delay so a new timestamp would differ
        # Decrypt should still work because AAD is embedded, not regenerated
        pt = self.encryptor.decrypt(ct, silo="identity", record_id="id1", scope="read")
        assert pt == "data"


class TestE2EEDeliverer:
    """Test end-to-end encrypted delivery using ECDH-P256."""

    def setup_method(self):
        self.deliverer = E2EEDeliverer()
        # Generate two key pairs: Alice and Bob
        self.alice_priv, self.alice_pub = E2EEDeliverer.generate_key_pair()
        self.bob_priv, self.bob_pub = E2EEDeliverer.generate_key_pair()

    def test_generate_key_pair_length(self):
        """Generated key pairs have proper DER encoding."""
        assert len(self.alice_priv) > 0
        assert len(self.alice_pub) > 0
        assert len(self.bob_priv) > 0
        assert len(self.bob_pub) > 0

    def test_generate_key_pair_unique(self):
        """Each generated key pair is unique."""
        priv1, pub1 = E2EEDeliverer.generate_key_pair()
        priv2, pub2 = E2EEDeliverer.generate_key_pair()
        assert priv1 != priv2
        assert pub1 != pub2

    def test_encrypt_decrypt_roundtrip(self):
        """Alice encrypts for Bob, Bob decrypts."""
        ct = self.deliverer.encrypt_for_recipient("Hello Bob!", self.bob_pub)
        pt = self.deliverer.decrypt_from_sender(ct, recipient_private_key=self.bob_priv)
        assert pt == "Hello Bob!"

    def test_e2ee_produces_v2_prefix(self):
        """E2EE ciphertext starts with v2: prefix."""
        ct = self.deliverer.encrypt_for_recipient("test", self.bob_pub)
        assert ct.startswith("v2:")

    def test_e2ee_different_nonces(self):
        """Same plaintext produces different ciphertexts (random nonce + ephemeral key)."""
        ct1 = self.deliverer.encrypt_for_recipient("test", self.bob_pub)
        ct2 = self.deliverer.encrypt_for_recipient("test", self.bob_pub)
        assert ct1 != ct2

    def test_e2ee_wrong_recipient_fails(self):
        """Bob's private key cannot decrypt a message encrypted for Alice."""
        ct = self.deliverer.encrypt_for_recipient("secret for Alice", self.alice_pub)
        with pytest.raises(ValueError, match="E2EE decryption failed|wrong key"):
            self.deliverer.decrypt_from_sender(ct, recipient_private_key=self.bob_priv)

    def test_e2ee_aad_silo_mismatch(self):
        """Decrypting with wrong silo fails."""
        ct = self.deliverer.encrypt_for_recipient(
            "secret", self.bob_pub,
            aad=build_aad(operation="e2ee", silo="medical", record_id="id1", scope="read"),
        )
        with pytest.raises(ValueError, match="AAD silo mismatch"):
            self.deliverer.decrypt_from_sender(ct, recipient_private_key=self.bob_priv, silo="identity")

    def test_e2ee_unicode(self):
        """E2EE handles unicode correctly."""
        message = "Confidential: 请查看附件 — diagnóstico cardíaco"
        ct = self.deliverer.encrypt_for_recipient(message, self.bob_pub)
        pt = self.deliverer.decrypt_from_sender(ct, recipient_private_key=self.bob_priv)
        assert pt == message

    def test_e2ee_long_message(self):
        """E2EE handles long messages."""
        message = "X" * 50000
        ct = self.deliverer.encrypt_for_recipient(message, self.bob_pub)
        pt = self.deliverer.decrypt_from_sender(ct, recipient_private_key=self.bob_priv)
        assert pt == message

    def test_e2ee_with_explicit_aad(self):
        """E2EE with explicit AAD object."""
        aad = build_aad(operation="e2ee", silo="identity", record_id="record-42", scope="read")
        ct = self.deliverer.encrypt_for_recipient("classified", self.bob_pub, aad=aad)
        pt = self.deliverer.decrypt_from_sender(ct, recipient_private_key=self.bob_priv)
        assert pt == "classified"


class TestEncryptionEngine:
    """Test the top-level EncryptionEngine combining field and E2EE."""

    def setup_method(self):
        self.km = KeyManager()
        self.master_key = KeyManager.generate_master_key()
        self.engine = EncryptionEngine(self.km, self.master_key)

    def test_field_encrypt_decrypt(self):
        """Field encryption roundtrip through the engine."""
        ct = self.engine.field.encrypt("SSN-123-45-6789", silo="identity", record_id="id1", scope="read")
        pt = self.engine.field.decrypt(ct, silo="identity", record_id="id1", scope="read")
        assert pt == "SSN-123-45-6789"

    def test_e2ee_encrypt_decrypt(self):
        """E2EE roundtrip through the engine."""
        bob_priv, bob_pub = E2EEDeliverer.generate_key_pair()
        message = "Confidential medical record"
        ct = self.engine.e2ee.encrypt_for_recipient(message, bob_pub)
        pt = self.engine.e2ee.decrypt_from_sender(ct, recipient_private_key=bob_priv)
        assert pt == message

    def test_cross_silo_isolation(self):
        """Data encrypted for one silo cannot be decrypted with another silo's key."""
        ct_med = self.engine.field.encrypt("data", silo="medical", record_id="id1", scope="read")
        with pytest.raises(ValueError, match="AAD context mismatch"):
            self.engine.field.decrypt(ct_med, silo="identity", record_id="id1", scope="read")