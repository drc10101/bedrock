"""
Bedrock Encryption Engine.

Generalizes InFill's ECDH+HKDF+GCM stack into a standalone module.
Provides field-level encryption, E2EE delivery, and AAD construction.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from bedrock.encryption.aad import AAD, build_aad
from bedrock.encryption.engine import (
    E2EEDeliverer,
    EncryptionEngine,
    FieldEncryptor,
)
from bedrock.encryption.legacy import LegacyDecryptor, is_infill_legacy
from bedrock.encryption.version import CiphertextFormat

__all__ = [
    "EncryptionEngine",
    "FieldEncryptor",
    "E2EEDeliverer",
    "LegacyDecryptor",
    "AAD",
    "build_aad",
    "CiphertextFormat",
    "is_infill_legacy",
]
