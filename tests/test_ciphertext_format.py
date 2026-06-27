"""Tests for Ciphertext Format versioning."""

from bedrock.encryption.version import CiphertextFormat


class TestCiphertextFormat:
    """Test ciphertext version detection."""

    def test_detect_v2_format(self):
        ct = "v2:AQIDBAUG..."
        assert CiphertextFormat.detect(ct) == CiphertextFormat.V2_GCM

    def test_detect_v1_format(self):
        ct = "v1:gAAAAABm..."
        assert CiphertextFormat.detect(ct) == CiphertextFormat.V1_FERNET

    def test_detect_legacy_no_prefix(self):
        ct = "gAAAAABm..."
        assert CiphertextFormat.detect(ct) == CiphertextFormat.V1_FERNET

    def test_v2_prefix_value(self):
        assert CiphertextFormat.V2_GCM.value == "v2:"

    def test_v1_prefix_value(self):
        assert CiphertextFormat.V1_FERNET.value == "v1:"