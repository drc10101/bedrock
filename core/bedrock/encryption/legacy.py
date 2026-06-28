"""
Bedrock Legacy Decryption — InFill compatibility layer.

Decrypts ciphertext produced by InFill's security.py encryption:
- v2:base64(nonce+ct+tag) — InFill's AES-256-GCM (no AAD, no silo binding)
- gAAAA... — Legacy Fernet (AES-128-CBC + HMAC-SHA256)

InFill's v2 format:
  v2:base64(nonce[12B] || ciphertext || tag)

This differs from Bedrock's v2 format which embeds AAD:
  v2:base64(aad_len[2B] || aad_json || iv[12B] || ciphertext || tag)

The legacy decryptor distinguishes them by checking for the AAD length
header. Bedrock v2 ciphertext always starts with a 2-byte big-endian length
prefix for the AAD JSON. InFill v2 ciphertext starts directly with the 12-byte
nonce. We can tell them apart by trying to unpack the first 2 bytes as a
length and checking if it points to valid AAD JSON.

Migration path:
  1. InFill decrypts existing data via LegacyDecryptor (v2 or Fernet)
  2. InFill re-encrypts via FieldEncryptor.encrypt_simple() (Bedrock v2 with AAD)
  3. Over time, all data migrates to Bedrock v2 format
  4. LegacyDecryptor can be removed once migration is complete

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import base64
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# InFill's HKDF info string — must match security.py exactly
_INFILL_HKDF_INFO = b"infill-field-encryption-aes256gcm"

# InFill's v2 prefix — must match security.py exactly
_INFILL_V2_PREFIX = "v2:"


class LegacyDecryptor:
    """Decrypts InFill's legacy ciphertext formats.

    Handles two InFill-specific formats:
    - v2:base64(nonce+ct+tag) — InFill AES-256-GCM (no AAD)
    - gAAAA... — Fernet (AES-128-CBC + HMAC-SHA256)

    This decryptor uses the same key derivation as InFill's security.py:
    the base key (stored in .encryption_key) is used directly as the Fernet
    key, and an HKDF-SHA256 derived key is used for AES-256-GCM.

    Args:
        base_key: The raw bytes from InFill's .encryption_key file.
                  This is the same key that was used to derive both the
                  Fernet key and the AES-256-GCM key in InFill.
    """

    def __init__(self, base_key: bytes):
        self._base_key = base_key
        self._aesgcm_key: bytes | None = None
        self._fernet = None

    def _derive_aes256_key(self) -> bytes:
        """Derive AES-256 key from base key via HKDF-SHA256.

        Uses the same HKDF info string as InFill's security.py
        so the derived key is identical.
        """
        if self._aesgcm_key is None:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=_INFILL_HKDF_INFO,
            )
            self._aesgcm_key = hkdf.derive(self._base_key)
        return self._aesgcm_key

    def _get_fernet(self):
        """Get Fernet cipher instance for legacy decryption."""
        if self._fernet is None:
            from cryptography.fernet import Fernet

            self._fernet = Fernet(self._base_key)
        return self._fernet

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt an InFill ciphertext (v2 or Fernet format).

        Args:
            ciphertext: Encrypted string, either v2:base64(...) or Fernet gAAAA...

        Returns:
            Decrypted plaintext string.

        Raises:
            ValueError: If the ciphertext format is unrecognized or decryption fails.
        """
        if ciphertext.startswith(_INFILL_V2_PREFIX):
            return self._decrypt_infill_v2(ciphertext)
        else:
            return self._decrypt_fernet(ciphertext)

    def _decrypt_infill_v2(self, ciphertext: str) -> str:
        """Decrypt InFill v2 format: v2:base64(nonce+ct+tag)."""
        encoded = ciphertext[len(_INFILL_V2_PREFIX) :]
        combined = base64.b64decode(encoded)
        nonce = combined[:12]
        ct = combined[12:]
        aesgcm = AESGCM(self._derive_aes256_key())
        plaintext_bytes = aesgcm.decrypt(nonce, ct, None)
        return plaintext_bytes.decode("utf-8")

    def _decrypt_fernet(self, ciphertext: str) -> str:
        """Decrypt legacy Fernet format: gAAAA..."""
        f = self._get_fernet()
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")

    def is_legacy(self, ciphertext: str) -> bool:
        """Check if ciphertext is a legacy format (not Bedrock v2 with AAD).

        Returns True for:
        - InFill v2 (no AAD)
        - Fernet (no prefix)

        Returns False for:
        - Bedrock v2 (with AAD embedded)
        """
        if not ciphertext.startswith(_INFILL_V2_PREFIX):
            # Fernet format — definitely legacy
            return True
        # Starts with v2: — check if it's InFill v2 (no AAD) or Bedrock v2 (with AAD)
        return not _is_bedrock_v2(ciphertext)


def _is_bedrock_v2(ciphertext: str) -> bool:
    """Check if a v2:-prefixed ciphertext is Bedrock format (with AAD).

    Bedrock v2 wire format: v2:base64url(aad_len[2B] || aad_string || iv[12B] || ct+tag)
    where aad_string starts with "bedrock:".

    InFill v2 wire format: v2:base64(nonce[12B] || ct+tag)
    where nonce is random bytes.

    Detection strategy: decode the base64url payload, read the first 2 bytes
    as a big-endian uint16 (aad_len), and check if the bytes at offset 2
    start with "bedrock:". This is unambiguous because:
    - Bedrock: aad_len is ~100-300, and packed[2:2+aad_len] starts with "bedrock:"
    - InFill: first 2 bytes are random nonce (could be any value), but the
      probability of random nonce bytes producing a valid aad_len AND
      the next bytes spelling "bedrock:" is negligible (~2^-64).
    """
    encoded = ciphertext[len(_INFILL_V2_PREFIX) :]
    # Restore base64 padding (urlsafe, matching Bedrock's encode)
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    try:
        packed = base64.urlsafe_b64decode(encoded)
    except Exception:
        return False
    if len(packed) < 14:
        # Too short to be either format meaningfully
        return False
    aad_len = struct.unpack(">H", packed[:2])[0]
    # Bedrock AAD strings start with "bedrock:" and are typically 50-300 bytes
    if 10 < aad_len < 512 and len(packed) >= 2 + aad_len:
        aad_start = packed[2 : 2 + aad_len]
        if aad_start.startswith(b"bedrock:"):
            return True
    return False


def is_infill_legacy(ciphertext: str) -> bool:
    """Public API: check if ciphertext is InFill legacy format.

    Returns True for InFill v2 (no AAD) and Fernet formats.
    Returns False for Bedrock v2 (with AAD).
    """
    decryptor = LegacyDecryptor.__new__(LegacyDecryptor)
    return decryptor.is_legacy(ciphertext)
