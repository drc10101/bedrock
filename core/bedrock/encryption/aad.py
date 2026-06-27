"""
Additional Authenticated Data (AAD) construction.

Binds ciphertext to its context: operation, silo, record_id, scope, timestamp.
Prevents record swapping, scope escalation, and replay attacks.

Wire format uses base64url encoding to avoid delimiter collisions with timestamps.
"""

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class AAD:
    """Additional Authenticated Data bound to every encryption operation.

    Serialized as base64url-encoded JSON to avoid delimiter collisions.
    If any field doesn't match at decryption time, the operation fails.
    """
    operation: str    # e.g., "field", "e2ee", "audit"
    silo: str         # e.g., "medical", "identity", "transaction"
    record_id: str    # anonymous ID or record UUID
    scope: str        # e.g., "read", "write", "consent"
    timestamp: str    # ISO 8601 UTC

    def to_string(self) -> str:
        """Serialize AAD to base64url-encoded JSON."""
        payload = json.dumps({
            "op": self.operation,
            "si": self.silo,
            "rid": self.record_id,
            "sc": self.scope,
            "ts": self.timestamp,
        }, separators=(",", ":"))
        return "bedrock:" + base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")

    @classmethod
    def from_string(cls, aad_string: str) -> "AAD":
        """Parse AAD from base64url-encoded JSON. Raises ValueError on malformed input."""
        if not aad_string.startswith("bedrock:"):
            raise ValueError(f"Invalid AAD format: {aad_string}")
        encoded = aad_string[len("bedrock:"):]
        # Restore padding
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding
        try:
            payload = json.loads(base64.urlsafe_b64decode(encoded))
        except (json.JSONDecodeError, Exception) as e:
            raise ValueError(f"Invalid AAD format: {aad_string}") from e

        required_keys = {"op", "si", "rid", "sc", "ts"}
        if not required_keys.issubset(payload.keys()):
            raise ValueError(f"Invalid AAD format: missing keys in {aad_string}")

        return cls(
            operation=payload["op"],
            silo=payload["si"],
            record_id=payload["rid"],
            scope=payload["sc"],
            timestamp=payload["ts"],
        )


def build_aad(operation: str, silo: str, record_id: str,
              scope: str, timestamp: Optional[str] = None) -> AAD:
    """Convenience function to build AAD with current UTC timestamp."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    return AAD(
        operation=operation,
        silo=silo,
        record_id=record_id,
        scope=scope,
        timestamp=ts,
    )