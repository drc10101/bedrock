"""
Ciphertext version format.

v2: prefix format for algorithm versioning with backward-compatible legacy decryption.
"""

from enum import Enum


class CiphertextFormat(Enum):
    """Version prefix for encrypted data.

    v1: Legacy Fernet format (backward compatibility with InFill)
    v2: Current AES-256-GCM with HKDF-derived keys and AAD binding
    """
    V1_FERNET = "v1:"
    V2_GCM = "v2:"

    @classmethod
    def detect(cls, ciphertext: str) -> "CiphertextFormat":
        """Detect ciphertext format from prefix."""
        if ciphertext.startswith(cls.V1_FERNET.value):
            return cls.V1_FERNET
        if ciphertext.startswith(cls.V2_GCM.value):
            return cls.V2_GCM
        # No prefix = legacy Fernet (InFill v1)
        return cls.V1_FERNET