"""
Bedrock Encryption Engine — Core encryption operations.

Field-level AES-256-GCM with HKDF-derived per-silo keys.
E2EE delivery using ECDH-P256 key agreement.

The encryption engine is the heart of Bedrock. Every piece of data
at rest is encrypted with per-silo keys derived from the master key,
and every piece of data in transit is encrypted for the recipient's
public key. The AAD binds ciphertext to its context, making it
impossible to swap records, escalate scopes, or replay operations.

Wire format (v2):
  Field: v2:base64(aad_len[2B] || aad_json_b64 || iv[12B] || ct || tag)
  E2EE:  v2:base64(aad_len[2B] || aad_json_b64 || eph_len[2B] || eph_pubkey || iv[12B] || ct || tag)

The AAD is embedded in the ciphertext so the decrypt side can extract
the exact same AAD that was used during encryption. This prevents
timestamp mismatches and makes the wire format self-contained.
"""

import base64
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from bedrock.encryption.aad import AAD, build_aad
from bedrock.encryption.legacy import LegacyDecryptor, _is_bedrock_v2
from bedrock.encryption.version import CiphertextFormat
from bedrock.key_management.keys import KeyManager


class FieldEncryptor:
    """Encrypts and decrypts individual data fields using per-silo keys.

    Each silo gets its own key derived via HKDF from the master key.
    AAD binds the ciphertext to its context (operation, silo, record, scope, timestamp).

    The AAD used during encryption is embedded in the ciphertext wire format,
    so decryption can extract and verify the exact same AAD — no timestamp
    mismatches, no caller burden.
    """

    def __init__(self, key_manager: KeyManager, master_key: bytes):
        self._key_manager = key_manager
        self._master_key = master_key

    def encrypt(
        self, plaintext: str, silo: str, record_id: str, scope: str, operation: str = "field"
    ) -> str:
        """Encrypt a field value with AAD binding.

        Args:
            plaintext: The data to encrypt
            silo: Which silo this data belongs to (determines the key)
            record_id: The anonymous ID of the record
            scope: Access scope (read, write, consent)
            operation: Operation type (field, e2ee, audit)

        Returns:
            Ciphertext with version prefix: v2:base64(aad_len || aad_b64 || iv || ct || tag)
        """
        # Build AAD with timestamp frozen at encryption time
        aad = build_aad(
            operation=operation,
            silo=silo,
            record_id=record_id,
            scope=scope,
        )
        aad_string = aad.to_string()
        aad_bytes = aad_string.encode("utf-8")

        # Get silo key (active version)
        silo_key = self._key_manager.get_silo_key(self._master_key, silo)

        # Generate nonce
        nonce = os.urandom(12)  # 96 bits for GCM

        # Encrypt
        aesgcm = AESGCM(silo_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad_bytes)

        # Wire format: aad_len[2B] || aad_json || iv[12B] || ct+tag
        aad_encoded = aad_string.encode("utf-8")
        packed = struct.pack(">H", len(aad_encoded)) + aad_encoded + nonce + ciphertext_with_tag

        # Encode with version prefix
        encoded = base64.urlsafe_b64encode(packed).decode().rstrip("=")
        return f"{CiphertextFormat.V2_GCM.value}{encoded}"

    def decrypt(
        self,
        ciphertext: str,
        silo: str,
        record_id: str,
        scope: str,
        operation: str = "field",
        key_version: int | None = None,
    ) -> str:
        """Decrypt a field value. Validates AAD matches expected context.

        The AAD is embedded in the ciphertext, so we extract it and verify
        it matches the caller's expected context (silo, record_id, scope, operation).

        Args:
            ciphertext: Encrypted data with version prefix
            silo: Expected silo name (must match encryption context)
            record_id: Expected record ID (must match encryption context)
            scope: Expected scope (must match encryption context)
            operation: Expected operation type (must match encryption context)
            key_version: Specific key version for decryption (for rotated keys)

        Returns:
            Decrypted plaintext string

        Raises:
            ValueError: If AAD context doesn't match (tamper detection)
            ValueError: If ciphertext format is unrecognized
        """
        fmt = CiphertextFormat.detect(ciphertext)

        if fmt == CiphertextFormat.V2_GCM:
            return self._decrypt_v2(ciphertext, silo, record_id, scope, operation, key_version)

        raise ValueError(f"Unsupported ciphertext format: {fmt}")

    def _decrypt_v2(
        self,
        ciphertext: str,
        silo: str,
        record_id: str,
        scope: str,
        operation: str,
        key_version: int | None = None,
    ) -> str:
        """Decrypt v2 (AES-256-GCM) ciphertext with embedded AAD."""
        # Strip version prefix
        encoded = ciphertext[len(CiphertextFormat.V2_GCM.value) :]

        # Restore base64 padding
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding

        packed = base64.urlsafe_b64decode(encoded)

        # Unpack: aad_len[2B] || aad_json || iv[12B] || ct+tag
        offset = 0
        aad_len = struct.unpack(">H", packed[offset : offset + 2])[0]
        offset += 2

        aad_string = packed[offset : offset + aad_len].decode("utf-8")
        offset += aad_len

        nonce = packed[offset : offset + 12]
        offset += 12

        ciphertext_and_tag = packed[offset:]

        # Parse and validate AAD
        stored_aad = AAD.from_string(aad_string)

        # Verify context matches
        expected_aad = AAD(
            operation=operation,
            silo=silo,
            record_id=record_id,
            scope=scope,
            timestamp=stored_aad.timestamp,  # Use stored timestamp
        )
        if (
            stored_aad.operation != expected_aad.operation
            or stored_aad.silo != expected_aad.silo
            or stored_aad.record_id != expected_aad.record_id
            or stored_aad.scope != expected_aad.scope
        ):
            raise ValueError(
                f"Decryption failed: AAD context mismatch. "
                f"Stored: op={stored_aad.operation} silo={stored_aad.silo} "
                f"rid={stored_aad.record_id} scope={stored_aad.scope}. "
                f"Expected: op={expected_aad.operation} silo={expected_aad.silo} "
                f"rid={expected_aad.record_id} scope={expected_aad.scope}. "
                f"This may indicate tampering, scope escalation, or record swapping."
            )

        aad_bytes = aad_string.encode("utf-8")

        # Get silo key (specific version or active)
        if key_version is not None:
            silo_key = self._key_manager.derive_silo_key(self._master_key, silo, key_version)
        else:
            silo_key = self._key_manager.get_silo_key(self._master_key, silo)

        # Decrypt
        aesgcm = AESGCM(silo_key)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, aad_bytes)
        except Exception as e:
            raise ValueError("Decryption failed: wrong key or corrupted ciphertext.") from e

        return plaintext_bytes.decode("utf-8")

    # ------------------------------------------------------------------
    # Simplified API for InFill integration
    # ------------------------------------------------------------------

    def encrypt_simple(
        self, plaintext: str, silo: str = "infill", record_id: str = "field", scope: str = "read"
    ) -> str:
        """Encrypt with sensible defaults — drop-in for InFill's encrypt_field().

        Uses AAD binding with the provided silo/record_id/scope (defaults to
        "infill"/"field"/"read"). All new ciphertext uses the Bedrock v2 wire
        format with embedded AAD.

        Args:
            plaintext: The data to encrypt.
            silo: Silo name for key derivation and AAD (default: "infill").
            record_id: Record identifier for AAD (default: "field").
            scope: Access scope for AAD (default: "read").

        Returns:
            Bedrock v2 ciphertext with embedded AAD.
        """
        return self.encrypt(plaintext, silo=silo, record_id=record_id, scope=scope)

    def decrypt_auto(
        self,
        ciphertext: str,
        silo: str = "infill",
        record_id: str = "field",
        scope: str = "read",
        legacy_key: bytes | None = None,
    ) -> str:
        """Auto-detect ciphertext format and decrypt.

        Handles three formats:
        1. Bedrock v2 (with embedded AAD) — extracts AAD from ciphertext,
           validates against provided silo/record_id/scope.
        2. InFill v2 (no AAD) — decrypted via LegacyDecryptor using
           the legacy_key (InFill's .encryption_key bytes).
        3. Fernet (gAAAA...) — decrypted via LegacyDecryptor.

        Args:
            ciphertext: Encrypted string in any supported format.
            silo: Expected silo for Bedrock v2 AAD validation.
            record_id: Expected record_id for Bedrock v2 AAD validation.
            scope: Expected scope for Bedrock v2 AAD validation.
            legacy_key: InFill's .encryption_key bytes (required for
                InFill v2 or Fernet ciphertext). If None and the
                ciphertext is legacy, raises ValueError.

        Returns:
            Decrypted plaintext string.

        Raises:
            ValueError: If ciphertext format is unsupported or AAD mismatch.
        """
        fmt = CiphertextFormat.detect(ciphertext)

        if fmt == CiphertextFormat.V2_GCM:
            # Distinguish Bedrock v2 (with AAD) from InFill v2 (no AAD)
            if _is_bedrock_v2(ciphertext):
                return self.decrypt(ciphertext, silo=silo, record_id=record_id, scope=scope)
            else:
                # InFill v2 — needs legacy key
                if legacy_key is None:
                    raise ValueError(
                        "InFill v2 ciphertext requires legacy_key "
                        "(the .encryption_key bytes from InFill)"
                    )
                decryptor = LegacyDecryptor(legacy_key)
                return decryptor.decrypt(ciphertext)

        if fmt == CiphertextFormat.V1_FERNET:
            if legacy_key is None:
                raise ValueError(
                    "Fernet ciphertext requires legacy_key "
                    "(the .encryption_key bytes from InFill)"
                )
            decryptor = LegacyDecryptor(legacy_key)
            return decryptor.decrypt(ciphertext)

        raise ValueError(f"Unsupported ciphertext format: {fmt}")


class E2EEDeliverer:
    """Encrypts data for end-to-end delivery using ECDH-P256.

    The sender encrypts for the recipient's public key.
    No intermediary can decrypt — only the holder of the recipient's private key.

    ECDH key agreement:
    1. Sender generates an ephemeral ECDH key pair
    2. Sender derives a shared secret: ephemeral_private + recipient_public
    3. Shared secret is used to derive an AES-256-GCM key via HKDF
    4. Data is encrypted with that key + AAD binding
    5. Ciphertext includes the ephemeral public key and AAD for the recipient

    Recipient decryption:
    1. Extract AAD and ephemeral public key from ciphertext
    2. Derive same shared secret: recipient_private + ephemeral_public
    3. Derive same AES-256-GCM key via HKDF
    4. Decrypt with that key + AAD
    """

    def __init__(self, config: object | None = None) -> None:
        self._config = config

    def encrypt_for_recipient(
        self,
        plaintext: str,
        recipient_public_key: bytes,
        sender_private_key: bytes | None = None,
        aad: AAD | None = None,
        silo: str = "",
        record_id: str = "",
        scope: str = "e2ee",
    ) -> str:
        """Encrypt data for a specific recipient's public key.

        Args:
            plaintext: Data to encrypt
            recipient_public_key: Recipient's secp256r1 public key (DER encoded)
            sender_private_key: Optional sender's private key for persistent key agreement
            aad: Optional AAD object (built from silo/record_id/scope if not provided)
            silo: Silo name for AAD
            record_id: Record ID for AAD
            scope: Scope for AAD

        Returns:
            v2:base64(aad_len || aad_b64 || eph_len || eph_pubkey || iv || ct || tag)
        """
        # Build AAD if not provided
        if aad is None:
            aad = build_aad(
                operation="e2ee",
                silo=silo,
                record_id=record_id,
                scope=scope,
            )
        aad_string = aad.to_string()
        aad_bytes = aad_string.encode("utf-8")

        # Load recipient's public key
        recipient_pub_raw = serialization.load_der_public_key(recipient_public_key)
        if not isinstance(recipient_pub_raw, EllipticCurvePublicKey):
            raise TypeError("Recipient public key must be an elliptic curve key for ECDH")
        recipient_pub = recipient_pub_raw

        # Generate ephemeral key pair (or use provided sender key)
        if sender_private_key is not None:
            ephemeral_priv_raw = serialization.load_der_private_key(
                sender_private_key, password=None
            )
            if not isinstance(ephemeral_priv_raw, EllipticCurvePrivateKey):
                raise TypeError("Sender private key must be an elliptic curve key for ECDH")
            ephemeral_priv = ephemeral_priv_raw
        else:
            ephemeral_priv = generate_private_key(SECP256R1())
        ephemeral_pub = ephemeral_priv.public_key()

        # ECDH key agreement
        shared_key = ephemeral_priv.exchange(ECDH(), recipient_pub)

        # Derive AES-256-GCM key from shared secret via HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"bedrock:e2ee:key",
        )
        aes_key = hkdf.derive(shared_key)

        # Generate nonce
        nonce = os.urandom(12)

        # Encrypt
        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad_bytes)

        # Serialize ephemeral public key
        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Wire format: aad_len[2B] || aad_json || eph_len[2B] || eph_pubkey || iv[12B] || ct+tag
        aad_encoded = aad_string.encode("utf-8")
        packed = (
            struct.pack(">H", len(aad_encoded))
            + aad_encoded
            + struct.pack(">H", len(ephemeral_pub_bytes))
            + ephemeral_pub_bytes
            + nonce
            + ciphertext_with_tag
        )

        encoded = base64.urlsafe_b64encode(packed).decode().rstrip("=")
        return f"{CiphertextFormat.V2_GCM.value}{encoded}"

    def decrypt_from_sender(
        self,
        ciphertext: str,
        sender_public_key: bytes | None = None,
        recipient_private_key: bytes | None = None,
        aad: AAD | None = None,
        silo: str = "",
        record_id: str = "",
        scope: str = "e2ee",
    ) -> str:
        """Decrypt data received from a specific sender.

        The sender's ephemeral public key and AAD are embedded in the ciphertext,
        so sender_public_key is not needed and aad is extracted from the ciphertext.

        Args:
            ciphertext: Encrypted data with version prefix
            sender_public_key: Ignored (extracted from ciphertext)
            recipient_private_key: Recipient's secp256r1 private key (DER encoded)
            aad: Ignored (extracted from ciphertext for verification)
            silo: Expected silo name (verified against embedded AAD)
            record_id: Expected record ID (verified against embedded AAD)
            scope: Expected scope (verified against embedded AAD)

        Returns:
            Decrypted plaintext string
        """
        if recipient_private_key is None:
            raise ValueError("recipient_private_key is required for E2EE decryption")

        # Strip version prefix
        encoded = ciphertext[len(CiphertextFormat.V2_GCM.value) :]

        # Restore base64 padding
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding

        packed = base64.urlsafe_b64decode(encoded)

        # Unpack: aad_len[2B] || aad_json || eph_len[2B] || eph_pubkey || iv[12B] || ct+tag
        offset = 0
        aad_len = struct.unpack(">H", packed[offset : offset + 2])[0]
        offset += 2

        aad_string = packed[offset : offset + aad_len].decode("utf-8")
        offset += aad_len

        eph_len = struct.unpack(">H", packed[offset : offset + 2])[0]
        offset += 2

        ephemeral_pub_bytes = packed[offset : offset + eph_len]
        offset += eph_len

        nonce = packed[offset : offset + 12]
        offset += 12

        ciphertext_and_tag = packed[offset:]

        # Parse AAD from ciphertext
        stored_aad = AAD.from_string(aad_string)

        # Verify context matches expected values (if provided)
        if silo and stored_aad.silo != silo:
            raise ValueError(
                f"E2EE decryption failed: AAD silo mismatch. "
                f"Stored={stored_aad.silo}, Expected={silo}."
            )
        if record_id and stored_aad.record_id != record_id:
            raise ValueError(
                f"E2EE decryption failed: AAD record_id mismatch. "
                f"Stored={stored_aad.record_id}, Expected={record_id}."
            )
        if scope != "e2ee" and stored_aad.scope != scope:
            raise ValueError(
                f"E2EE decryption failed: AAD scope mismatch. "
                f"Stored={stored_aad.scope}, Expected={scope}."
            )

        aad_bytes = aad_string.encode("utf-8")

        # Load keys
        ephemeral_pub_raw = serialization.load_der_public_key(ephemeral_pub_bytes)
        if not isinstance(ephemeral_pub_raw, EllipticCurvePublicKey):
            raise TypeError("Ephemeral public key must be an elliptic curve key for ECDH")
        ephemeral_pub = ephemeral_pub_raw
        recipient_priv_raw = serialization.load_der_private_key(
            recipient_private_key, password=None
        )
        if not isinstance(recipient_priv_raw, EllipticCurvePrivateKey):
            raise TypeError("Recipient private key must be an elliptic curve key for ECDH")
        recipient_priv = recipient_priv_raw

        # ECDH key agreement (same shared secret)
        shared_key = recipient_priv.exchange(ECDH(), ephemeral_pub)

        # Derive same AES-256-GCM key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"bedrock:e2ee:key",
        )
        aes_key = hkdf.derive(shared_key)

        # Decrypt
        aesgcm = AESGCM(aes_key)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, aad_bytes)
        except Exception as e:
            raise ValueError("E2EE decryption failed: wrong key or corrupted ciphertext.") from e

        return plaintext_bytes.decode("utf-8")

    @staticmethod
    def generate_key_pair() -> tuple[bytes, bytes]:
        """Generate a new ECDH-P256 key pair for E2EE.

        Returns:
            (private_key_der, public_key_der) tuple
        """
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()

        private_der = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_der, public_der


class EncryptionEngine:
    """Top-level encryption engine combining field-level and E2EE operations.

    Usage:
        # Initialize with a master key
        master_key = KeyManager.generate_master_key()
        key_mgr = KeyManager()
        engine = EncryptionEngine(key_mgr, master_key)

        # Field-level encryption
        ct = engine.field.encrypt("SSN data", silo="identity", record_id="crimson-arctic-fox", scope="read")
        pt = engine.field.decrypt(ct, silo="identity", record_id="crimson-arctic-fox", scope="read")

        # E2EE encryption
        priv_b, pub_b = E2EEDeliverer.generate_key_pair()
        ct = engine.e2ee.encrypt_for_recipient("secret message", pub_b)
        pt = engine.e2ee.decrypt_from_sender(ct, recipient_private_key=priv_b)
    """

    def __init__(
        self, key_manager: KeyManager, master_key: bytes, config: object | None = None
    ) -> None:
        self._key_manager = key_manager
        self._master_key = master_key
        self._config = config
        self.field = FieldEncryptor(key_manager, master_key)
        self.e2ee = E2EEDeliverer(config)
