"""
Tests for Bedrock Storage — SQLite backend and PersistentBedrock.
"""

import json
import os
import tempfile
import time
import unittest

import sys
sys.path.insert(0, "core")

from bedrock.storage.sqlite_backend import SQLiteBackend
from bedrock.storage.persistence import PersistentBedrock
from bedrock.identity.registration import NodeRegistry, NodeState
from bedrock.identity.certificates import CertificateManager
from bedrock.data_separation.silo import SiloManager
from bedrock.data_separation.consent import ConsentGate
from bedrock.audit.chain import AuditChain
from bedrock.licensing.keygen import LicenseKeygen, SigningKey
from bedrock.licensing.enforcement import LicenseTier


def _make_db():
    """Create a temp DB file and return (db, path) for cleanup."""
    tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmpfile.close()
    return SQLiteBackend(tmpfile.name), tmpfile.name


def _cleanup_db(db, path):
    """Close DB and remove file."""
    try:
        db.close()
    except Exception:
        pass
    try:
        os.unlink(path)
    except Exception:
        pass


class TestSQLiteBackend(unittest.TestCase):
    """Test raw key-value operations on the SQLite backend."""

    def setUp(self):
        self.db, self.db_path = _make_db()

    def tearDown(self):
        _cleanup_db(self.db, self.db_path)

    def test_save_and_load(self):
        self.db.save("bedrock_nodes", "node-1", {"name": "server-1", "type": "provider"})
        result = self.db.load("bedrock_nodes", "node-1")
        assert result is not None
        assert result["name"] == "server-1"

    def test_load_nonexistent(self):
        assert self.db.load("bedrock_nodes", "ghost") is None

    def test_save_overwrites(self):
        self.db.save("bedrock_nodes", "node-1", {"name": "old"})
        self.db.save("bedrock_nodes", "node-1", {"name": "new"})
        assert self.db.load("bedrock_nodes", "node-1")["name"] == "new"

    def test_load_all(self):
        self.db.save("bedrock_nodes", "n1", {"name": "alpha"})
        self.db.save("bedrock_nodes", "n2", {"name": "beta"})
        result = self.db.load_all("bedrock_nodes")
        assert len(result) == 2

    def test_delete(self):
        self.db.save("bedrock_nodes", "node-1", {"name": "deleteme"})
        assert self.db.delete("bedrock_nodes", "node-1") is True
        assert self.db.load("bedrock_nodes", "node-1") is None

    def test_delete_nonexistent(self):
        assert self.db.delete("bedrock_nodes", "ghost") is False

    def test_count(self):
        for i in range(3):
            self.db.save("bedrock_nodes", f"n{i}", {"name": f"s{i}"})
        assert self.db.count("bedrock_nodes") == 3

    def test_exists(self):
        self.db.save("bedrock_nodes", "node-1", {"name": "exists"})
        assert self.db.exists("bedrock_nodes", "node-1") is True
        assert self.db.exists("bedrock_nodes", "ghost") is False

    def test_query_with_filter(self):
        self.db.save("bedrock_nodes", "n1", {"name": "a", "type": "provider"})
        self.db.save("bedrock_nodes", "n2", {"name": "b", "type": "patient"})
        self.db.save("bedrock_nodes", "n3", {"name": "c", "type": "provider"})
        result = self.db.query("bedrock_nodes", lambda d: d["type"] == "provider")
        assert len(result) == 2

    def test_clear_table(self):
        for i in range(3):
            self.db.save("bedrock_nodes", f"n{i}", {"name": f"s{i}"})
        count = self.db.clear_table("bedrock_nodes")
        assert count == 3
        assert self.db.count("bedrock_nodes") == 0

    def test_list_tables(self):
        self.db.save("bedrock_nodes", "n1", {"name": "a"})
        self.db.save("bedrock_silos", "s1", {"name": "silo-1"})
        tables = self.db.list_tables()
        assert "bedrock_nodes" in tables
        assert "bedrock_silos" in tables

    def test_context_manager(self):
        with SQLiteBackend(self.db_path) as db:
            db.save("bedrock_nodes", "ctx-test", {"name": "context"})
            assert db.load("bedrock_nodes", "ctx-test")["name"] == "context"

    def test_convenience_methods(self):
        self.db.save_node({"uuid": "node-123", "name": "server-1", "node_type": "provider"})
        assert "node-123" in self.db.load_nodes()

    def test_json_special_characters(self):
        data = {
            "name": "O'Brien & Associates",
            "path": "C:\\Users\\dev\\file.txt",
            "unicode": "日本語テスト",
        }
        self.db.save("bedrock_nodes", "special", data)
        result = self.db.load("bedrock_nodes", "special")
        assert result["name"] == "O'Brien & Associates"
        assert result["unicode"] == "日本語テスト"

    def test_large_payload(self):
        data = {"content": "x" * 100000}
        self.db.save("bedrock_nodes", "large", data)
        result = self.db.load("bedrock_nodes", "large")
        assert len(result["content"]) == 100000

    def test_null_values(self):
        data = {"name": "nullable", "value": None, "count": 0}
        self.db.save("bedrock_nodes", "nullable", data)
        result = self.db.load("bedrock_nodes", "nullable")
        assert result["value"] is None
        assert result["count"] == 0

    def test_concurrent_writes(self):
        import threading
        results = {"ok": 0, "errors": 0}

        def write_node(i):
            try:
                db = SQLiteBackend(self.db_path)
                db.save("bedrock_nodes", f"node-{i}", {"name": f"server-{i}", "index": i})
                db.close()
                results["ok"] += 1
            except Exception:
                results["errors"] += 1

        threads = [threading.Thread(target=write_node, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results["ok"] == 20
        assert self.db.count("bedrock_nodes") == 20


class TestPersistentBedrock(unittest.TestCase):
    """Test PersistentBedrock save/restore across module state."""

    def setUp(self):
        self.db, self.db_path = _make_db()
        self.pb = PersistentBedrock(storage=self.db)

    def tearDown(self):
        _cleanup_db(self.db, self.db_path)

    def test_save_and_restore_node(self):
        node = self.pb.registry.register(name="test-server", node_type="provider")
        self.pb.save_node(node)
        assert self.db.count("bedrock_nodes") >= 1

    def test_save_all_and_restore_all(self):
        node = self.pb.registry.register(name="persist-test", node_type="server")
        self.pb.audit_chain.append(action="test", actor_id="admin", target_id="node-1", silo="test")
        saved = self.pb.save_all()
        assert saved["nodes"] >= 1
        assert saved["audit"] >= 1

        # Restore in a new instance
        db2 = SQLiteBackend(self.db_path)
        pb2 = PersistentBedrock(storage=db2)
        restored = pb2.restore_all()
        assert restored["nodes"] >= 1
        db2.close()

    def test_silo_save_and_restore(self):
        silo = self.pb.silo_manager.create_silo(
            name="medical-records",
            display_name="Medical Records",
            categories=["phi", "diagnosis"],
        )
        self.pb.save_silo(silo)
        assert self.db.count("bedrock_silos") >= 1

    def test_consent_save(self):
        event = self.pb.consent_gate.request_consent(
            requesting_node_id="provider-1",
            source_silo="medical",
            target_silo="phi",
            categories=["diagnosis"],
            scope="read",
        )
        self.pb.save_consent(event)
        assert self.db.count("bedrock_consents") >= 1

    def test_audit_save_and_restore(self):
        self.pb.audit_chain.append(action="node.registered", actor_id="admin", target_id="node-1", silo="system")
        self.pb.audit_chain.append(action="consent.approved", actor_id="patient-1", target_id="provider-1", silo="medical")
        count = self.pb.save_all_audit()
        assert count == 2

        # Restore audit
        db2 = SQLiteBackend(self.db_path)
        pb2 = PersistentBedrock(storage=db2)
        restored = pb2.restore_audit()
        assert restored >= 2
        db2.close()

    def test_signing_key_save_and_restore(self):
        key = self.pb.keygen.generate_signing_key(key_id="restore-test-01")
        self.pb.save_signing_key(key)

        db2 = SQLiteBackend(self.db_path)
        pb2 = PersistentBedrock(storage=db2)
        count = pb2.restore_signing_keys()
        assert count >= 1
        restored_key = pb2.keygen.get_key("restore-test-01")
        assert restored_key is not None
        assert restored_key.key_material == key.key_material
        db2.close()

    def test_signing_key_persists_revocation(self):
        key = self.pb.keygen.generate_signing_key(key_id="rev-persist-01")
        key.revoke("security incident")
        self.pb.save_signing_key(key)

        db2 = SQLiteBackend(self.db_path)
        pb2 = PersistentBedrock(storage=db2)
        pb2.restore_signing_keys()
        restored_key = pb2.keygen.get_key("rev-persist-01")
        assert restored_key.revoked is True
        assert restored_key.revocation_reason == "security incident"
        db2.close()

    def test_clear_all(self):
        self.pb.registry.register(name="clear-test", node_type="server")
        self.pb.save_all()
        assert self.db.count("bedrock_nodes") >= 1
        cleared = self.pb.clear_all()
        assert cleared["bedrock_nodes"] >= 1

    def test_empty_restore(self):
        restored = self.pb.restore_all()
        assert restored["nodes"] == 0
        assert restored["silos"] == 0
        assert restored["signing_keys"] == 0

    def test_full_workflow(self):
        """Create state, save, restore in fresh instance, validate."""
        node = self.pb.registry.register(name="workflow-server", node_type="server")
        silo = self.pb.silo_manager.create_silo(
            name="workflow-silo", display_name="Workflow Silo", categories=["test"],
        )
        key = self.pb.keygen.generate_signing_key(key_id="workflow-key")
        license_key = self.pb.keygen.issue_license(
            key=key, tier=LicenseTier.STARTER, issued_to="Workflow Corp",
        )

        self.pb.save_all()
        assert self.db.count("bedrock_nodes") >= 1
        assert self.db.count("bedrock_silos") >= 1
        assert self.db.count("bedrock_licenses") >= 1

        # Restore in fresh instance
        db2 = SQLiteBackend(self.db_path)
        pb2 = PersistentBedrock(storage=db2)
        restored = pb2.restore_all()

        restored_key = pb2.keygen.get_key("workflow-key")
        assert restored_key is not None
        assert restored_key.key_material == key.key_material

        # Validate license with restored key
        license_obj = pb2.keygen.validate_license(license_key)
        assert license_obj.tier == LicenseTier.STARTER
        assert license_obj.issued_to == "Workflow Corp"
        db2.close()


if __name__ == "__main__":
    unittest.main()