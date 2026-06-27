"""
Bedrock Encryption Engine.

Generalizes InFill's ECDH+HKDF+GCM stack into a standalone module.
Provides field-level encryption, E2EE delivery, and AAD construction.

Trade Secret — InFill Systems, LLC.
"""

from bedrock.encryption.engine import (
    EncryptionEngine,
    FieldEncryptor,
    E2EEDeliverer,
)
from bedrock.encryption.aad import AAD, build_aad
from bedrock.encryption.version import CiphertextFormat

__all__ = [
    "EncryptionEngine",
    "FieldEncryptor",
    "E2EEDeliverer",
    "AAD",
    "build_aad",
    "CiphertextFormat",
]