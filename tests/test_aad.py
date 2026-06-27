"""Tests for AAD (Additional Authenticated Data)."""

import base64
import json
from bedrock.encryption.aad import AAD, build_aad


class TestAAD:
    """Test AAD construction, serialization, and parsing."""

    def test_build_aad(self):
        aad = build_aad(
            operation="field",
            silo="medical",
            record_id="crimson-arctic-fox",
            scope="read",
        )
        assert aad.operation == "field"
        assert aad.silo == "medical"
        assert aad.record_id == "crimson-arctic-fox"
        assert aad.scope == "read"
        assert aad.timestamp is not None

    def test_aad_to_string_format(self):
        aad = AAD(
            operation="e2ee",
            silo="identity",
            record_id="slate-mountain-owl",
            scope="consent",
            timestamp="2026-01-15T10:30:00+00:00",
        )
        result = aad.to_string()
        # Should start with "bedrock:" prefix
        assert result.startswith("bedrock:")
        # Should be valid base64url after prefix
        encoded = result[len("bedrock:"):]
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding
        decoded = json.loads(base64.urlsafe_b64decode(encoded))
        assert decoded["op"] == "e2ee"
        assert decoded["si"] == "identity"
        assert decoded["rid"] == "slate-mountain-owl"
        assert decoded["sc"] == "consent"

    def test_aad_from_string(self):
        # Build a known AAD, serialize, then parse
        original = AAD(
            operation="field",
            silo="medical",
            record_id="crimson-arctic-fox",
            scope="read",
            timestamp="2026-01-15T10:30:00+00:00",
        )
        aad_str = original.to_string()
        parsed = AAD.from_string(aad_str)
        assert parsed.operation == "field"
        assert parsed.silo == "medical"
        assert parsed.record_id == "crimson-arctic-fox"
        assert parsed.scope == "read"
        assert parsed.timestamp == "2026-01-15T10:30:00+00:00"

    def test_aad_from_string_invalid(self):
        import pytest
        with pytest.raises(ValueError, match="Invalid AAD format"):
            AAD.from_string("not-bedrock:garbage")

    def test_aad_from_string_no_prefix(self):
        import pytest
        with pytest.raises(ValueError, match="Invalid AAD format"):
            AAD.from_string("random-string-without-prefix")

    def test_aad_roundtrip(self):
        aad = build_aad(
            operation="audit",
            silo="transaction",
            record_id="jade-viper-titan",
            scope="write",
        )
        aad_str = aad.to_string()
        parsed = AAD.from_string(aad_str)
        assert parsed.operation == aad.operation
        assert parsed.silo == aad.silo
        assert parsed.record_id == aad.record_id
        assert parsed.scope == aad.scope
        assert parsed.timestamp == aad.timestamp