"""
Bedrock Persistence — synchronizes in-memory module state to SQLite.

Each module (NodeRegistry, CertificateManager, SiloManager, etc.) operates
in-memory for speed. PersistentBedrock wraps these modules and syncs their
state to a SQLite database on every mutation, and restores state on startup.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import json
import time
from datetime import datetime
from typing import Optional

from bedrock.storage.sqlite_backend import SQLiteBackend
from bedrock.identity.registration import NodeRegistry, Node, NodeState
from bedrock.identity.certificates import CertificateManager, Certificate
from bedrock.data_separation.silo import SiloManager, Silo
from bedrock.data_separation.consent import ConsentGate, ConsentEvent
from bedrock.audit.chain import AuditChain, AuditEntry
from bedrock.licensing.keygen import LicenseKeygen, SigningKey


class PersistentBedrock:
    """Wraps Bedrock modules with SQLite persistence.

    On init, loads saved state from the database into each module.
    After that, the modules work in-memory for speed, and this class
    provides save/load methods for explicit persistence points.

    Usage:
        storage = SQLiteBackend("bedrock.db")
        pb = PersistentBedrock(storage=storage)
        pb.restore_all()  # Load state from disk

        # Use modules normally
        node = pb.registry.register(name="server-1", node_type="server")
        pb.save_node(node)  # Persist to disk

        # Or save everything at once
        pb.save_all()
    """

    def __init__(
        self,
        storage: Optional[SQLiteBackend] = None,
        registry: Optional[NodeRegistry] = None,
        cert_manager: Optional[CertificateManager] = None,
        silo_manager: Optional[SiloManager] = None,
        consent_gate: Optional[ConsentGate] = None,
        audit_chain: Optional[AuditChain] = None,
        keygen: Optional[LicenseKeygen] = None,
    ):
        self.storage = storage or SQLiteBackend("bedrock.db")

        self.registry = registry or NodeRegistry()
        self.cert_manager = cert_manager or CertificateManager(license_tier="enterprise")
        self.silo_manager = silo_manager or SiloManager()
        self.consent_gate = consent_gate or ConsentGate()
        self.audit_chain = audit_chain or AuditChain()
        self.keygen = keygen or LicenseKeygen()

    @staticmethod
    def _dt_to_str(dt) -> str:
        """Convert datetime to ISO string for JSON serialization."""
        if isinstance(dt, datetime):
            return dt.isoformat()
        return str(dt)

    # --- Node persistence ---

    def save_node(self, node: Node) -> None:
        """Persist a node to the database."""
        self.storage.save_node({
            "uuid": node.node_id.uuid,
            "name": node.name,
            "node_type": node.node_type,
            "state": node.state.value if hasattr(node.state, "value") else str(node.state),
            "public_key_hex": node.node_id.public_key_hex(),
            "metadata": json.dumps(node.metadata) if node.metadata else "{}",
        })

    def save_all_nodes(self) -> int:
        """Persist all registered nodes. Returns count saved."""
        count = 0
        for uuid, node in self.registry._nodes.items():
            self.save_node(node)
            count += 1
        return count

    def restore_nodes(self) -> int:
        """Restore nodes from the database into the registry.

        Returns count of nodes restored.
        Note: Nodes are restored with fresh keys (private keys are not stored).
        """
        saved = self.storage.load_nodes()
        count = 0
        for uuid, data in saved.items():
            if self.registry.get(uuid) is not None:
                continue
            try:
                node = self.registry.register(
                    name=data["name"],
                    node_type=data["node_type"],
                    metadata=json.loads(data.get("metadata", "{}")),
                )
                count += 1
            except Exception:
                continue
        return count

    # --- Certificate persistence ---

    def save_certificate(self, cert: dict) -> None:
        """Persist a certificate to the database."""
        self.storage.save_certificate(cert)

    def save_all_certificates(self) -> int:
        """Persist all certificates. Returns count saved."""
        count = 0
        for serial, cert in self.cert_manager._certificates.items():
            cert_data = {
                "serial_number": serial,
                "node_uuid": getattr(cert, "node_uuid", ""),
                "node_name": getattr(cert, "node_name", ""),
                "is_valid": getattr(cert, "is_valid", False),
            }
            self.storage.save_certificate(cert_data)
            count += 1
        return count

    def restore_certificates(self) -> int:
        """Restore certificate metadata from the database.

        Note: Certificates cannot be truly restored without the original
        key material. This creates a record of what was issued.
        Returns count of records found.
        """
        saved = self.storage.load_certificates()
        return len(saved)

    # --- Silo persistence ---

    def save_silo(self, silo: Silo) -> None:
        """Persist a silo to the database."""
        self.storage.save_silo({
            "name": silo.name,
            "display_name": silo.display_name,
            "categories": json.dumps(list(silo.categories)) if hasattr(silo, "categories") else "[]",
            "description": getattr(silo, "description", ""),
            "encrypted": getattr(silo, "encrypted", False),
        })

    def save_all_silos(self) -> int:
        """Persist all silos. Returns count saved."""
        count = 0
        for name, silo in self.silo_manager._silos.items():
            self.save_silo(silo)
            count += 1
        return count

    def restore_silos(self) -> int:
        """Restore silos from the database. Returns count restored."""
        saved = self.storage.load_silos()
        count = 0
        for silo_id, data in saved.items():
            if self.silo_manager._silos.get(data.get("name")) is not None:
                continue
            try:
                silo = self.silo_manager.create_silo(
                    name=data["name"],
                    display_name=data.get("display_name", data["name"]),
                    categories=json.loads(data.get("categories", "[]")),
                )
                count += 1
            except Exception:
                continue
        return count

    # --- Consent persistence ---

    def save_consent(self, event: ConsentEvent) -> None:
        """Persist a consent event to the database."""
        self.storage.save_consent({
            "consent_id": event.consent_id,
            "requesting_node_id": event.requesting_node_id,
            "data_owner_id": getattr(event, "data_owner_id", ""),
            "source_silo": event.source_silo,
            "target_silo": event.target_silo,
            "categories": json.dumps(list(event.categories)) if hasattr(event, "categories") else "[]",
            "scope": event.scope,
            "reason": getattr(event, "reason", ""),
            "status": event.status,
            "created_at": self._dt_to_str(getattr(event, "created_at", "")),
        })

    def restore_consents(self) -> int:
        """Restore consent events from the database. Returns count restored."""
        saved = self.storage.load_consents()
        count = 0
        for consent_id, data in saved.items():
            if self.consent_gate._events.get(consent_id) is not None:
                continue
            try:
                event = ConsentEvent(
                    consent_id=data["consent_id"],
                    requesting_node_id=data["requesting_node_id"],
                    data_owner_id=data.get("data_owner_id", ""),
                    source_silo=data["source_silo"],
                    target_silo=data["target_silo"],
                    categories=json.loads(data.get("categories", "[]")),
                    scope=data.get("scope", "read"),
                    reason=data.get("reason", ""),
                    status=data["status"],
                )
                self.consent_gate._events[consent_id] = event
                count += 1
            except Exception:
                continue
        return count

    # --- Audit persistence ---

    def save_audit_entry(self, entry: AuditEntry) -> None:
        """Persist an audit chain entry to the database."""
        details = getattr(entry, "details", {})
        if details is None:
            details = {}
        entry_data = {
            "entry_id": str(getattr(entry, "entry_index", "")),
            "action": getattr(entry, "action", ""),
            "actor_id": getattr(entry, "actor_id", ""),
            "target_id": getattr(entry, "target_id", ""),
            "silo": getattr(entry, "silo", ""),
            "timestamp": self._dt_to_str(getattr(entry, "timestamp", "")),
            "details": json.dumps(details) if isinstance(details, dict) else str(details),
            "entry_hash": getattr(entry, "entry_hash", ""),
        }
        self.storage.save_audit_entry(entry_data)

    def save_all_audit(self) -> int:
        """Persist all audit entries. Returns count saved."""
        count = 0
        for entry in self.audit_chain._chain:
            self.save_audit_entry(entry)
            count += 1
        return count

    def restore_audit(self) -> int:
        """Restore audit chain entries from the database. Returns count restored."""
        saved = self.storage.load_audit_chain()
        count = 0
        for entry_id, data in saved.items():
            try:
                details_raw = data.get("details", "{}")
                details = json.loads(details_raw) if isinstance(details_raw, str) else details_raw
                self.audit_chain.append(
                    action=data["action"],
                    actor_id=data["actor_id"],
                    target_id=data["target_id"],
                    silo=data["silo"],
                    details=details,
                )
                count += 1
            except Exception:
                continue
        return count

    # --- Signing key persistence ---

    def save_signing_key(self, key: SigningKey) -> None:
        """Persist a signing key to the database."""
        self.storage.save_signing_key(key.to_dict())

    def save_all_signing_keys(self) -> int:
        """Persist all signing keys. Returns count saved."""
        count = 0
        for key_id, key in self.keygen._keys.items():
            self.save_signing_key(key)
            count += 1
        return count

    def restore_signing_keys(self) -> int:
        """Restore signing keys from the database. Returns count restored."""
        saved = self.storage.load_signing_keys()
        count = 0
        for key_id, data in saved.items():
            if self.keygen.get_key(key_id) is not None:
                continue
            try:
                key = SigningKey.from_dict(data)
                self.keygen._keys[key_id] = key
                count += 1
            except Exception:
                continue
        return count

    # --- Bulk operations ---

    def save_all(self) -> dict[str, int]:
        """Save all module state to the database.

        Returns dict with count of items saved per module.
        """
        return {
            "nodes": self.save_all_nodes(),
            "certificates": self.save_all_certificates(),
            "silos": self.save_all_silos(),
            "audit": self.save_all_audit(),
            "signing_keys": self.save_all_signing_keys(),
        }

    def restore_all(self) -> dict[str, int]:
        """Restore all module state from the database.

        Returns dict with count of items restored per module.
        """
        return {
            "nodes": self.restore_nodes(),
            "silos": self.restore_silos(),
            "consents": self.restore_consents(),
            "audit": self.restore_audit(),
            "signing_keys": self.restore_signing_keys(),
            "certificates": self.restore_certificates(),
        }

    def clear_all(self) -> dict[str, int]:
        """Clear all persisted data from the database.

        Returns dict with count of items cleared per table.
        """
        tables = [
            "bedrock_nodes",
            "bedrock_certificates",
            "bedrock_silos",
            "bedrock_consents",
            "bedrock_audit",
            "bedrock_licenses",
        ]
        result = {}
        for table in tables:
            result[table] = self.storage.clear_table(table)
        return result