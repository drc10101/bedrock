"""Tests for Audit Chain (B-108)."""

import json
import pytest
from datetime import datetime, timezone, timedelta

from bedrock.audit.chain import (
    AuditChain, AuditEntry, AuditAction, GENESIS_HASH,
)


class TestAuditEntry:
    """Test audit entry creation and hashing."""

    def test_create_entry(self):
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            action="node.register",
            actor_id="node-001",
            target_id="server-01",
            silo="identity",
        )
        assert entry.action == "node.register"
        assert entry.actor_id == "node-001"
        assert entry.silo == "identity"

    def test_compute_hash_deterministic(self):
        """Same inputs produce the same hash."""
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        entry1 = AuditEntry(
            timestamp=ts, action="test", actor_id="a", target_id="b",
            silo="c", details={"key": "value"}, prev_hash=GENESIS_HASH,
        )
        entry2 = AuditEntry(
            timestamp=ts, action="test", actor_id="a", target_id="b",
            silo="c", details={"key": "value"}, prev_hash=GENESIS_HASH,
        )
        assert entry1.compute_hash() == entry2.compute_hash()

    def test_different_inputs_different_hash(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        entry1 = AuditEntry(
            timestamp=ts, action="node.register", actor_id="a", target_id="b",
            silo="c", prev_hash=GENESIS_HASH,
        )
        entry2 = AuditEntry(
            timestamp=ts, action="node.revoke", actor_id="a", target_id="b",
            silo="c", prev_hash=GENESIS_HASH,
        )
        assert entry1.compute_hash() != entry2.compute_hash()

    def test_hash_depends_on_prev_hash(self):
        """Changing prev_hash changes the entry hash (chain integrity)."""
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        entry1 = AuditEntry(
            timestamp=ts, action="test", actor_id="a", target_id="b",
            silo="c", prev_hash=GENESIS_HASH,
        )
        entry2 = AuditEntry(
            timestamp=ts, action="test", actor_id="a", target_id="b",
            silo="c", prev_hash="abc123",
        )
        assert entry1.compute_hash() != entry2.compute_hash()

    def test_verify_hash(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        entry = AuditEntry(
            timestamp=ts, action="test", actor_id="a", target_id="b",
            silo="c", prev_hash=GENESIS_HASH,
        )
        entry.entry_hash = entry.compute_hash()
        assert entry.verify_hash() is True

    def test_verify_hash_tampered(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        entry = AuditEntry(
            timestamp=ts, action="test", actor_id="a", target_id="b",
            silo="c", prev_hash=GENESIS_HASH,
        )
        entry.entry_hash = entry.compute_hash()
        # Tamper with the action
        entry.action = "node.revoke"
        assert entry.verify_hash() is False

    def test_verify_hash_empty(self):
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc), action="test",
            actor_id="a", target_id="b", silo="c",
        )
        assert entry.verify_hash() is False  # No hash computed yet

    def test_to_dict(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        entry = AuditEntry(
            timestamp=ts, action="test", actor_id="a", target_id="b",
            silo="c", details={"key": "val"},
        )
        d = entry.to_dict()
        assert d["action"] == "test"
        assert d["details"]["key"] == "val"
        assert isinstance(d["timestamp"], str)  # ISO format

    def test_from_dict(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        entry = AuditEntry(
            timestamp=ts, action="test", actor_id="a", target_id="b",
            silo="c", details={"key": "val"},
        )
        d = entry.to_dict()
        restored = AuditEntry.from_dict(d)
        assert restored.action == "test"
        assert restored.details["key"] == "val"


class TestAuditChain:
    """Test audit chain append and verify."""

    def setup_method(self):
        self.chain = AuditChain()

    def test_append_creates_entry(self):
        entry = self.chain.append("node.register", "admin", "server-01", "identity")
        assert entry.action == "node.register"
        assert entry.actor_id == "admin"
        assert entry.entry_hash != ""
        assert entry.prev_hash == GENESIS_HASH

    def test_append_chains_entries(self):
        entry1 = self.chain.append("node.register", "admin", "server-01", "identity")
        entry2 = self.chain.append("cert.issue", "ca", "server-01", "identity")

        # Second entry's prev_hash must equal first entry's entry_hash
        assert entry2.prev_hash == entry1.entry_hash
        assert self.chain.head_hash == entry2.entry_hash

    def test_chain_length(self):
        assert len(self.chain) == 0
        self.chain.append("test", "a", "b", "c")
        assert len(self.chain) == 1
        self.chain.append("test2", "d", "e", "f")
        assert len(self.chain) == 2

    def test_entry_index(self):
        self.chain.append("test", "a", "b", "c")
        self.chain.append("test2", "d", "e", "f")
        assert self.chain[0].entry_index == 0
        assert self.chain[1].entry_index == 1

    def test_get_by_index(self):
        self.chain.append("test", "a", "b", "c")
        entry = self.chain.get(0)
        assert entry is not None
        assert entry.action == "test"

    def test_get_out_of_range(self):
        assert self.chain.get(99) is None

    def test_verify_empty_chain(self):
        assert self.chain.verify() is True

    def test_verify_valid_chain(self):
        self.chain.append("node.register", "admin", "server-01", "identity")
        self.chain.append("cert.issue", "ca", "server-01", "identity")
        self.chain.append("field.encrypt", "server-01", "record-42", "medical")
        assert self.chain.verify() is True

    def test_verify_tampered_chain(self):
        self.chain.append("node.register", "admin", "server-01", "identity")
        self.chain.append("cert.issue", "ca", "server-01", "identity")

        # Tamper with the first entry
        self.chain[0].action = "node.revoke"
        assert self.chain.verify() is False

    def test_verify_tampered_hash_breaks_chain(self):
        self.chain.append("node.register", "admin", "server-01", "identity")
        self.chain.append("cert.issue", "ca", "server-01", "identity")

        # Tamper with the first entry's hash
        original_hash = self.chain[0].entry_hash
        self.chain[0].entry_hash = "tampered_hash"
        assert self.chain.verify() is False

        # Restore and verify works again
        self.chain[0].entry_hash = original_hash
        assert self.chain.verify() is True

    def test_genesis_hash(self):
        """First entry's prev_hash must be the genesis hash."""
        self.chain.append("test", "a", "b", "c")
        assert self.chain[0].prev_hash == GENESIS_HASH
        assert self.chain.tail_hash == GENESIS_HASH

    def test_head_hash_empty_chain(self):
        assert self.chain.head_hash == GENESIS_HASH

    def test_head_hash_after_append(self):
        entry = self.chain.append("test", "a", "b", "c")
        assert self.chain.head_hash == entry.entry_hash


class TestAuditChainQuery:
    """Test audit chain filtering and querying."""

    def setup_method(self):
        self.chain = AuditChain()
        self.chain.append("node.register", "admin", "server-01", "identity")
        self.chain.append("cert.issue", "ca", "server-01", "identity")
        self.chain.append("field.encrypt", "server-01", "record-42", "medical")
        self.chain.append("field.encrypt", "server-01", "record-43", "medical")
        self.chain.append("consent.approve", "patient-001", "record-42", "medical")
        self.chain.append("node.quarantine", "mesh", "server-02", "identity")

    def test_get_by_action(self):
        entries = self.chain.get_by_action("field.encrypt")
        assert len(entries) == 2
        assert all(e.action == "field.encrypt" for e in entries)

    def test_get_by_actor(self):
        entries = self.chain.get_by_actor("server-01")
        # server-01 is actor in: field.encrypt (record-42), field.encrypt (record-43) = 2
        assert len(entries) == 2

    def test_get_by_silo(self):
        entries = self.chain.get_by_silo("medical")
        assert len(entries) == 3

    def test_query_with_multiple_filters(self):
        entries = self.chain.query(
            actor_id="server-01",
            silo="medical",
        )
        assert len(entries) == 2
        assert all(e.actor_id == "server-01" for e in entries)
        assert all(e.silo == "medical" for e in entries)

    def test_query_with_time_range(self):
        now = datetime.now(timezone.utc)
        future = now + timedelta(hours=1)
        # All entries are recent, so this should return all
        entries = self.chain.query(start_time=now - timedelta(hours=1))
        assert len(entries) == 6

    def test_query_with_no_results(self):
        entries = self.chain.query(action="nonexistent.action")
        assert len(entries) == 0


class TestAuditChainExport:
    """Test audit chain export and import."""

    def setup_method(self):
        self.chain = AuditChain()
        self.chain.append("node.register", "admin", "server-01", "identity")
        self.chain.append("cert.issue", "ca", "server-01", "identity")
        self.chain.append("field.encrypt", "server-01", "record-42", "medical")

    def test_export_jsonl(self):
        exported = self.chain.export(fmt="jsonl")
        lines = exported.strip().split("\n")
        assert len(lines) == 3

        # Each line should be valid JSON
        for line in lines:
            data = json.loads(line)
            assert "action" in data
            assert "entry_hash" in data

    def test_export_json(self):
        exported = self.chain.export(fmt="json")
        data = json.loads(exported)
        assert len(data) == 3
        assert data[0]["action"] == "node.register"

    def test_export_with_date_filter(self):
        start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        end = datetime(2030, 1, 1, tzinfo=timezone.utc)
        exported = self.chain.export(start_date=start, end_date=end, fmt="jsonl")
        lines = exported.strip().split("\n")
        assert len(lines) == 3

    def test_import_jsonl(self):
        exported = self.chain.export(fmt="jsonl")
        imported = AuditChain.import_chain(exported, fmt="jsonl")
        assert len(imported) == 3
        assert imported.verify() is True
        assert imported.head_hash == self.chain.head_hash

    def test_import_json(self):
        exported = self.chain.export(fmt="json")
        imported = AuditChain.import_chain(exported, fmt="json")
        assert len(imported) == 3
        assert imported.verify() is True

    def test_import_tampered_chain_fails(self):
        exported = self.chain.export(fmt="jsonl")
        # Tamper with the first line
        lines = exported.strip().split("\n")
        data = json.loads(lines[0])
        data["action"] = "tampered"
        lines[0] = json.dumps(data, separators=(",", ":"))
        tampered = "\n".join(lines)

        with pytest.raises(ValueError, match="integrity verification"):
            AuditChain.import_chain(tampered, fmt="jsonl")

    def test_export_import_roundtrip_preserves_data(self):
        exported = self.chain.export(fmt="jsonl")
        imported = AuditChain.import_chain(exported, fmt="jsonl")

        for i in range(len(self.chain)):
            original = self.chain[i]
            restored = imported[i]
            assert original.action == restored.action
            assert original.actor_id == restored.actor_id
            assert original.target_id == restored.target_id
            assert original.silo == restored.silo
            assert original.entry_hash == restored.entry_hash


class TestAuditAction:
    """Test audit action enum."""

    def test_action_values(self):
        assert AuditAction.NODE_REGISTER.value == "node.register"
        assert AuditAction.CERT_ISSUE.value == "cert.issue"
        assert AuditAction.FIELD_ENCRYPT.value == "field.encrypt"
        assert AuditAction.CONSENT_APPROVE.value == "consent.approve"

    def test_action_categories(self):
        """All actions follow the category.operation format."""
        for action in AuditAction:
            assert "." in action.value, f"Action {action.value} doesn't follow category.operation format"


class TestAuditChainVerifyRange:
    """Test incremental chain verification."""

    def test_verify_range_valid(self):
        chain = AuditChain()
        for i in range(10):
            chain.append(f"action.{i}", f"actor-{i}", f"target-{i}", "test")

        # Verify first 5 entries
        assert chain.verify_range(0, 4) is True
        # Verify last 5 entries
        assert chain.verify_range(5, 9) is True
        # Verify single entry
        assert chain.verify_range(3, 3) is True

    def test_verify_range_invalid_indices(self):
        chain = AuditChain()
        chain.append("test", "a", "b", "c")

        assert chain.verify_range(-1, 0) is False
        assert chain.verify_range(0, 99) is False
        assert chain.verify_range(5, 3) is False  # start > end

    def test_verify_range_with_link_check(self):
        """Range verification checks the link to the previous entry."""
        chain = AuditChain()
        for i in range(5):
            chain.append(f"action.{i}", "actor", "target", "test")

        # Verify range starting from 1 checks link to entry 0
        assert chain.verify_range(1, 4) is True

    def test_verify_range_detects_tamper(self):
        chain = AuditChain()
        for i in range(5):
            chain.append(f"action.{i}", "actor", "target", "test")

        # Tamper with entry 2
        chain[2].action = "tampered"
        # Range that includes entry 2 should fail
        assert chain.verify_range(0, 4) is False
        # Range before entry 2 should pass
        assert chain.verify_range(0, 1) is True