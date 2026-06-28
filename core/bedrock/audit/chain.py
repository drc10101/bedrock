"""
Audit chain — SHA-256 hash chain logging.

Each entry includes the hash of the previous entry, creating a
tamper-evident chain. Any modification to a past entry invalidates
all subsequent hashes.

6-year retention. Exportable for compliance (HIPAA, SOC 2, PCI-DSS).

Chain structure:
    entry_hash = SHA-256(prev_hash + action + actor_id + target_id + silo + timestamp + details_json)

The genesis entry has prev_hash = "0" * 64 (64 zero hex chars).

Verification: re-hash every entry and confirm the chain is unbroken.
Tamper detection: any modified entry breaks all subsequent hashes.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Sequence


class AuditAction(Enum):
    """Standard audit action types.

    Each action follows the format: category.operation
    e.g., node.register, field.encrypt, consent.approve
    """
    # Node lifecycle
    NODE_REGISTER = "node.register"
    NODE_ATTEST = "node.attest"
    NODE_QUARANTINE = "node.quarantine"
    NODE_REVOKE = "node.revoke"
    NODE_HEAL = "node.heal"

    # Certificate lifecycle
    CERT_ISSUE = "cert.issue"
    CERT_RENEW = "cert.renew"
    CERT_REVOKE = "cert.revoke"

    # Encryption operations
    FIELD_ENCRYPT = "field.encrypt"
    FIELD_DECRYPT = "field.decrypt"
    E2EE_SEND = "e2ee.send"
    E2EE_RECEIVE = "e2ee.receive"

    # Key management
    KEY_ROTATE = "key.rotate"
    KEY_RETIRE = "key.retire"

    # Data separation
    CONSENT_REQUEST = "consent.request"
    CONSENT_APPROVE = "consent.approve"
    CONSENT_DENY = "consent.deny"
    CONSENT_REVOKE = "consent.revoke"
    SILO_ACCESS = "silo.access"

    # Access control
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_MFA = "auth.mfa"
    AUTH_FAIL = "auth.fail"

    # Audit chain itself
    CHAIN_VERIFY = "chain.verify"
    CHAIN_EXPORT = "chain.export"

    # Custom
    CUSTOM = "custom.action"


# Genesis hash: 64 zero hex characters (SHA-256 length)
GENESIS_HASH = "0" * 64

# Retention period: 6 years (HIPAA, SOC 2, PCI-DSS)
RETENTION_YEARS = 6


@dataclass
class AuditEntry:
    """A single entry in the audit chain.

    Hash = SHA-256(prev_hash + action + actor_id + target_id + silo + timestamp + details_json)

    The chain is tamper-evident: modifying any entry invalidates all
    subsequent hashes. This provides cryptographic proof of audit log
    integrity without requiring a central authority.
    """
    timestamp: datetime
    action: str          # e.g., "node.register", "field.encrypt", "consent.approve"
    actor_id: str        # Node ID or user ID that performed the action
    target_id: str       # What was acted upon (record ID, node ID, etc.)
    silo: str            # Which silo this action relates to
    details: dict = field(default_factory=dict)  # Arbitrary key-value details
    prev_hash: str = ""  # SHA-256 hash of the previous entry
    entry_hash: str = "" # SHA-256 hash of this entry (computed on append)
    entry_index: int = 0 # Position in the chain (0-indexed)

    def compute_hash(self) -> str:
        """Compute the SHA-256 hash for this entry.

        The hash covers: prev_hash + action + actor_id + target_id + silo +
        ISO timestamp + sorted details JSON.

        This is deterministic — same inputs always produce the same hash.
        """
        timestamp_iso = self.timestamp.isoformat() if self.timestamp else ""
        details_json = json.dumps(self.details, sort_keys=True, separators=(",", ":"))

        payload = (
            f"{self.prev_hash}:{self.action}:{self.actor_id}:"
            f"{self.target_id}:{self.silo}:{timestamp_iso}:{details_json}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def verify_hash(self) -> bool:
        """Verify that this entry's stored hash matches a recomputation.

        Returns True if the hash is valid, False if tampered.
        """
        if not self.entry_hash:
            return False
        return self.compute_hash() == self.entry_hash

    def to_dict(self) -> dict:
        """Serialize entry to a dictionary for export."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEntry":
        """Deserialize entry from a dictionary (for import)."""
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


class AuditChain:
    """Append-only SHA-256 hash chain.

    Every action in a Bedrock network is logged to the audit chain:
    - Node registration, attestation, quarantine, revocation
    - Certificate issuance, renewal, revocation
    - Encryption/decryption operations
    - Key rotation events
    - Consent requests, approvals, denials, revocations
    - Data access across silos
    - Authentication events

    The chain is tamper-evident. Any modification to a past entry
    breaks all subsequent hashes, making it cryptographically impossible
    to alter audit logs undetected.

    Verification: re-hash every entry and confirm prev_hash matches.
    Export: JSONL format for compliance reporting (HIPAA, SOC 2, PCI-DSS).
    """

    def __init__(self):
        self._chain: List[AuditEntry] = []
        self._last_hash: str = GENESIS_HASH

    def append(self, action: str, actor_id: str, target_id: str,
               silo: str, details: Optional[dict] = None) -> AuditEntry:
        """Append a new entry to the audit chain.

        The entry's hash is computed from the previous entry's hash +
        the entry data, making the chain tamper-evident.

        Args:
            action: What happened (e.g., "node.register", "field.encrypt")
            actor_id: Who did it (node UUID or user ID)
            target_id: What was acted upon
            silo: Which data silo this relates to
            details: Optional key-value details

        Returns:
            The appended AuditEntry with computed hash
        """
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            action=action,
            actor_id=actor_id,
            target_id=target_id,
            silo=silo,
            details=details or {},
            prev_hash=self._last_hash,
            entry_index=len(self._chain),
        )
        entry.entry_hash = entry.compute_hash()
        self._chain.append(entry)
        self._last_hash = entry.entry_hash
        return entry

    def verify(self) -> bool:
        """Verify the entire chain is unbroken.

        Re-hashes every entry and confirms:
        1. Each entry's prev_hash matches the previous entry's entry_hash
        2. Each entry's entry_hash matches a fresh computation
        3. The first entry's prev_hash is the genesis hash

        Returns True if the chain is intact, False if tampered.
        """
        if not self._chain:
            return True  # Empty chain is valid

        # Check genesis link
        if self._chain[0].prev_hash != GENESIS_HASH:
            return False

        for i, entry in enumerate(self._chain):
            # Verify entry hash
            if entry.compute_hash() != entry.entry_hash:
                return False

            # Verify chain link
            if i > 0:
                if entry.prev_hash != self._chain[i - 1].entry_hash:
                    return False

        return True

    def verify_range(self, start_index: int, end_index: int) -> bool:
        """Verify a range of the chain.

        Useful for incremental verification without re-hashing
        the entire chain.

        Args:
            start_index: First entry index (inclusive)
            end_index: Last entry index (inclusive)

        Returns:
            True if the range is intact
        """
        if start_index < 0 or end_index >= len(self._chain):
            return False
        if start_index > end_index:
            return False

        for i in range(start_index, end_index + 1):
            entry = self._chain[i]
            if entry.compute_hash() != entry.entry_hash:
                return False
            if i > start_index and entry.prev_hash != self._chain[i - 1].entry_hash:
                return False
            if i == start_index and start_index > 0:
                if entry.prev_hash != self._chain[start_index - 1].entry_hash:
                    return False

        return True

    def get(self, index: int) -> Optional[AuditEntry]:
        """Get an entry by its index in the chain."""
        if 0 <= index < len(self._chain):
            return self._chain[index]
        return None

    def get_by_action(self, action: str, limit: int = 100) -> List[AuditEntry]:
        """Get entries filtered by action type."""
        entries = [e for e in self._chain if e.action == action]
        return entries[-limit:]

    def get_by_actor(self, actor_id: str, limit: int = 100) -> List[AuditEntry]:
        """Get entries filtered by actor."""
        entries = [e for e in self._chain if e.actor_id == actor_id]
        return entries[-limit:]

    def get_by_silo(self, silo: str, limit: int = 100) -> List[AuditEntry]:
        """Get entries filtered by silo."""
        entries = [e for e in self._chain if e.silo == silo]
        return entries[-limit:]

    def query(self, action: Optional[str] = None,
              actor_id: Optional[str] = None,
              target_id: Optional[str] = None,
              silo: Optional[str] = None,
              start_time: Optional[datetime] = None,
              end_time: Optional[datetime] = None,
              limit: int = 100) -> List[AuditEntry]:
        """Query the audit chain with multiple filters.

        All filters are optional. Only entries matching all provided
        filters are returned.

        Args:
            action: Filter by action type
            actor_id: Filter by actor
            target_id: Filter by target
            silo: Filter by silo
            start_time: Earliest timestamp (inclusive)
            end_time: Latest timestamp (inclusive)
            limit: Maximum entries to return

        Returns:
            List of matching AuditEntry, most recent last
        """
        results = self._chain

        if action is not None:
            results = [e for e in results if e.action == action]
        if actor_id is not None:
            results = [e for e in results if e.actor_id == actor_id]
        if target_id is not None:
            results = [e for e in results if e.target_id == target_id]
        if silo is not None:
            results = [e for e in results if e.silo == silo]
        if start_time is not None:
            results = [e for e in results if e.timestamp >= start_time]
        if end_time is not None:
            results = [e for e in results if e.timestamp <= end_time]

        return results[-limit:]

    def export(self, start_date: Optional[datetime] = None,
               end_date: Optional[datetime] = None,
               format: str = "jsonl") -> str:
        """Export audit chain entries for compliance reporting.

        Supports HIPAA, SOC 2, PCI-DSS audit requirements.
        Exports are tamper-evident — each entry includes its hash
        and the previous entry's hash.

        Args:
            start_date: Earliest timestamp (None = from beginning)
            end_date: Latest timestamp (None = to end)
            format: Export format ("jsonl" or "json")

        Returns:
            String representation of the exported entries
        """
        entries = self._chain
        if start_date is not None:
            entries = [e for e in entries if e.timestamp >= start_date]
        if end_date is not None:
            entries = [e for e in entries if e.timestamp <= end_date]

        if format == "jsonl":
            lines = [json.dumps(e.to_dict(), separators=(",", ":")) for e in entries]
            return "\n".join(lines)
        elif format == "json":
            return json.dumps([e.to_dict() for e in entries], indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    @classmethod
    def import_chain(cls, data: str, format: str = "jsonl") -> "AuditChain":
        """Import an audit chain from an export.

        Reconstructs the chain and verifies integrity.

        Args:
            data: Exported data string
            format: Import format ("jsonl" or "json")

        Returns:
            Reconstructed AuditChain

        Raises:
            ValueError: If the imported chain fails verification
        """
        chain = cls()

        if format == "jsonl":
            for line in data.strip().split("\n"):
                if not line.strip():
                    continue
                entry_dict = json.loads(line)
                entry = AuditEntry.from_dict(entry_dict)
                chain._chain.append(entry)
        elif format == "json":
            entries = json.loads(data)
            for entry_dict in entries:
                entry = AuditEntry.from_dict(entry_dict)
                chain._chain.append(entry)
        else:
            raise ValueError(f"Unsupported import format: {format}")

        # Set last hash from the final entry
        if chain._chain:
            chain._last_hash = chain._chain[-1].entry_hash

        # Verify integrity
        if not chain.verify():
            raise ValueError("Imported chain failed integrity verification")

        return chain

    def __len__(self) -> int:
        """Return the number of entries in the chain."""
        return len(self._chain)

    def __getitem__(self, index: int) -> AuditEntry:
        """Get an entry by index."""
        return self._chain[index]

    @property
    def head_hash(self) -> str:
        """Get the hash of the most recent entry (chain head)."""
        if not self._chain:
            return GENESIS_HASH
        return self._chain[-1].entry_hash

    @property
    def tail_hash(self) -> str:
        """Get the genesis hash (chain tail)."""
        return GENESIS_HASH