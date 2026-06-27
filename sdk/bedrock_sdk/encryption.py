"""
Encryption SDK module — Field-level encrypt/decrypt, E2EE delivery, key management.

Wraps bedrock.encryption and bedrock.key_management with developer-friendly defaults.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

from typing import Optional, Tuple

from bedrock.encryption.engine import FieldEncryptor, E2EEDeliverer, KeyManager


class EncryptionModule:
    """SDK module for encryption operations.

    Provides a simplified API for:
    - Field-level encryption with silo-bound AAD
    - End-to-end encrypted (E2EE) message delivery
    - Key management (master key generation, rotation)
    """

    def __init__(
        self,
        encryptor: FieldEncryptor,
        e2ee: E2EEDeliverer,
        key_manager: KeyManager,
        master_key: str = "",
    ):
        self._encryptor = encryptor
        self._e2ee = e2ee
        self._key_manager = key_manager
        self._master_key = master_key

    def encrypt(
        self,
        plaintext: str,
        silo: str,
        record_id: str,
        scope: str = "read",
        operation: str = "field",
    ) -> str:
        """Encrypt a field value with silo-bound AAD.

        The ciphertext embeds AAD (silo, record_id, scope, operation)
        so any decryption with mismatched context fails. This prevents
        data from being moved between silos undetected.

        Args:
            plaintext: The value to encrypt.
            silo: Data silo identifier (e.g., "medical", "identity").
            record_id: Record identifier for AAD binding.
            scope: Access scope (default: "read").
            operation: Operation type (default: "field").

        Returns:
            Base64-encoded ciphertext string.
        """
        return self._encryptor.encrypt(
            plaintext=plaintext,
            silo=silo,
            record_id=record_id,
            scope=scope,
            operation=operation,
        )

    def decrypt(
        self,
        ciphertext: str,
        silo: str,
        record_id: str,
        scope: str = "read",
        operation: str = "field",
    ) -> str:
        """Decrypt a field value, validating AAD context.

        Decryption fails if the silo, record_id, scope, or operation
        don't match the values used during encryption. This is the
        core enforcement mechanism for data separation.

        Args:
            ciphertext: The encrypted value to decrypt.
            silo: Data silo identifier (must match encryption).
            record_id: Record identifier (must match encryption).
            scope: Access scope (must match encryption).
            operation: Operation type (must match encryption).

        Returns:
            The decrypted plaintext string.

        Raises:
            ValueError: If AAD context doesn't match (wrong silo, etc.)
        """
        return self._encryptor.decrypt(
            ciphertext=ciphertext,
            silo=silo,
            record_id=record_id,
            scope=scope,
            operation=operation,
        )

    def e2ee_encrypt(
        self,
        plaintext: str,
        recipient_public_key: bytes,
        sender_private_key: Optional[bytes] = None,
        silo: str = "",
        record_id: str = "",
    ) -> str:
        """Encrypt a message for a specific recipient (E2EE).

        Uses ECDH to derive a shared secret from the recipient's
        public key. Only the holder of the corresponding private key
        can decrypt.

        Args:
            plaintext: The message to encrypt.
            recipient_public_key: The recipient's public key.
            sender_private_key: Optional sender private key for authentication.
            silo: Silo identifier for AAD binding.
            record_id: Record identifier for AAD binding.

        Returns:
            Base64-encoded E2EE ciphertext.
        """
        return self._e2ee.encrypt_for_recipient(
            plaintext=plaintext,
            recipient_public_key=recipient_public_key,
            sender_private_key=sender_private_key,
            silo=silo,
            record_id=record_id,
        )

    def e2ee_decrypt(
        self,
        ciphertext: str,
        recipient_private_key: bytes,
        sender_public_key: Optional[bytes] = None,
        silo: str = "",
        record_id: str = "",
    ) -> str:
        """Decrypt an E2EE message using the recipient's private key.

        Args:
            ciphertext: The E2EE ciphertext to decrypt.
            recipient_private_key: The recipient's private key.
            sender_public_key: Optional sender public key for verification.
            silo: Silo identifier for AAD binding.
            record_id: Record identifier for AAD binding.

        Returns:
            The decrypted plaintext string.
        """
        return self._e2ee.decrypt_from_sender(
            ciphertext=ciphertext,
            sender_public_key=sender_public_key,
            recipient_private_key=recipient_private_key,
            silo=silo,
            record_id=record_id,
        )

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Generate an ECDH key pair for E2EE operations.

        Returns:
            Tuple of (private_key, public_key) as bytes.
        """
        return E2EEDeliverer.generate_key_pair()

    def rotate_master_key(self) -> str:
        """Generate a new master key for key rotation.

        Key rotation creates a new master key. All new encryptions
        use the new key. Old ciphertext remains decryptable with
        the previous key until it's retired.

        Returns:
            The new master key as a hex string.
        """
        new_key = self._key_manager.generate_master_key()
        return new_key.hex()