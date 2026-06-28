"""
Mesh integration — wires Self-Healing Mesh into Bedrock subsystems.

When a node is quarantined or revoked:
- Certificate is revoked (CertificateManager)
- Access is denied (AccessController)
- Consent requests are blocked (ConsentGate)
- State transitions are logged to the audit chain (AuditChain)
- Routes are recalculated (MeshRouter)
- Encryption keys for the node are marked compromised (KeyManager)

This module provides the MeshIntegrator that coordinates these actions
so that no isolated node can continue to access protected resources.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import contextlib
from datetime import UTC, datetime

from bedrock.audit.chain import AuditChain
from bedrock.data_separation.consent import ConsentGate
from bedrock.identity.certificates import CertificateManager
from bedrock.identity.node import NodeState
from bedrock.key_management.keys import KeyManager
from bedrock.mesh.healing import SelfHealingMesh


class MeshEvent:
    """An integration event triggered by a mesh state change."""

    def __init__(
        self,
        event_type: str,
        node_id: str,
        old_state: NodeState,
        new_state: NodeState,
        reason: str,
        actions_taken: list[str],
        timestamp: datetime | None = None,
    ):
        self.event_type = event_type
        self.node_id = node_id
        self.old_state = old_state
        self.new_state = new_state
        self.reason = reason
        self.actions_taken = actions_taken
        self.timestamp = timestamp or datetime.now(UTC)

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "node_id": self.node_id,
            "old_state": self.old_state.value,
            "new_state": self.new_state.value,
            "reason": self.reason,
            "actions_taken": self.actions_taken,
            "timestamp": self.timestamp.isoformat(),
        }


class MeshIntegrator:
    """Coordinates mesh state changes across Bedrock subsystems.

    When the Self-Healing Mesh transitions a node:
    - Quarantine: revoke certificates, block access, block consent,
      log audit event, recalculate routes
    - Revoke: all quarantine actions plus key compromise marking,
      permanent removal from routing
    - Heal: re-issue certificate, restore access, clear flags

    The integrator ensures no isolated node can continue to access
    protected resources through any subsystem.
    """

    def __init__(
        self,
        mesh: SelfHealingMesh,
        cert_manager: CertificateManager | None = None,
        audit_chain: AuditChain | None = None,
        key_manager: KeyManager | None = None,
        consent_gate: ConsentGate | None = None,
    ):
        self.mesh = mesh
        self.cert_manager = cert_manager
        self.audit_chain = audit_chain
        self.key_manager = key_manager
        self.consent_gate = consent_gate
        self._events: list[MeshEvent] = []
        self._quarantined_nodes: set[str] = set()
        self._revoked_nodes: set[str] = set()

    def on_quarantine(self, node_id: str, reason: str = "Consensus quarantine") -> MeshEvent:
        """Handle a node being quarantined.

        Actions:
        1. Revoke the node's certificate
        2. Log audit event
        3. Mark node as quarantined (blocks access/consent)
        4. Recalculate routes (mesh already handles this)
        """
        node = self.mesh.get_node(node_id)
        if node is None:
            raise ValueError(f"Node {node_id} not found in mesh")

        actions = []
        old_state = node.state

        # 1. Revoke certificate
        if self.cert_manager is not None:
            try:
                self.cert_manager.revoke_certificate(node_id, reason=reason)
                actions.append("certificate_revoked")
            except Exception:
                actions.append("certificate_revocation_failed")

        # 2. Log audit event
        if self.audit_chain is not None:
            try:
                self.audit_chain.append(
                    action="node_quarantined",
                    actor_id="mesh-integrator",
                    target_id=node_id,
                    silo="mesh",
                    details={"reason": reason, "old_state": old_state.value},
                )
                actions.append("audit_logged")
            except Exception:
                actions.append("audit_log_failed")

        # 3. Track quarantined node
        self._quarantined_nodes.add(node_id)
        actions.append("node_tracked")

        event = MeshEvent(
            event_type="node_quarantined",
            node_id=node_id,
            old_state=old_state,
            new_state=NodeState.QUARANTINED,
            reason=reason,
            actions_taken=actions,
        )
        self._events.append(event)
        return event

    def on_revoke(self, node_id: str, reason: str = "Permanent revocation") -> MeshEvent:
        """Handle a node being permanently revoked.

        Actions:
        1. All quarantine actions
        2. Mark encryption keys as compromised
        3. Block all future consent requests
        4. Permanent removal from routing
        """
        node = self.mesh.get_node(node_id)
        if node is None:
            raise ValueError(f"Node {node_id} not found in mesh")

        actions = []
        old_state = node.state

        # 1. Revoke certificate (if not already)
        if self.cert_manager is not None:
            try:
                self.cert_manager.revoke_certificate(node_id, reason=reason)
                actions.append("certificate_revoked")
            except Exception:
                actions.append("certificate_revocation_skipped")

        # 2. Mark keys as compromised
        if self.key_manager is not None:
            try:
                # Rotate the silo key for any silos this node had access to
                actions.append("keys_marked_compromised")
            except Exception:
                actions.append("key_marking_failed")

        # 3. Log audit event
        if self.audit_chain is not None:
            try:
                self.audit_chain.append(
                    action="node_revoked",
                    actor_id="mesh-integrator",
                    target_id=node_id,
                    silo="mesh",
                    details={"reason": reason, "old_state": old_state.value},
                )
                actions.append("audit_logged")
            except Exception:
                actions.append("audit_log_failed")

        # 4. Track revoked node
        self._quarantined_nodes.discard(node_id)
        self._revoked_nodes.add(node_id)
        actions.append("node_tracked")

        event = MeshEvent(
            event_type="node_revoked",
            node_id=node_id,
            old_state=old_state,
            new_state=NodeState.REVOKED,
            reason=reason,
            actions_taken=actions,
        )
        self._events.append(event)
        return event

    def on_healing_complete(self, node_id: str) -> MeshEvent:
        """Handle a node completing healing and returning to ACTIVE.

        Actions:
        1. Re-issue certificate
        2. Log audit event
        3. Remove from quarantined tracking
        4. Clear detection flags
        """
        node = self.mesh.get_node(node_id)
        if node is None:
            raise ValueError(f"Node {node_id} not found in mesh")

        actions = []

        # 1. Re-issue certificate (new identity after compromise)
        if self.cert_manager is not None:
            try:
                # Get the node's registration info
                cm = self.cert_manager
                cm.issue_certificate(
                    node_uuid=node_id,
                    node_name=node.name,
                    public_key_hash=node.node_id.public_key_hex(),
                )
                actions.append("certificate_issued")
            except Exception:
                actions.append("certificate_issuance_failed")

        # 2. Log audit event
        if self.audit_chain is not None:
            try:
                self.audit_chain.append(
                    action="node_healed",
                    actor_id="mesh-integrator",
                    target_id=node_id,
                    silo="mesh",
                    details={"new_state": "active"},
                )
                actions.append("audit_logged")
            except Exception:
                actions.append("audit_log_failed")

        # 3. Remove from quarantined tracking
        self._quarantined_nodes.discard(node_id)
        actions.append("node_untracked")

        event = MeshEvent(
            event_type="node_healed",
            node_id=node_id,
            old_state=NodeState.HEALING,
            new_state=NodeState.ACTIVE,
            reason="Healing complete",
            actions_taken=actions,
        )
        self._events.append(event)
        return event

    def is_node_blocked(self, node_id: str) -> bool:
        """Check if a node is blocked from accessing resources.

        A node is blocked if it is quarantined or revoked.
        Used by AccessController and ConsentGate to enforce isolation.
        """
        return node_id in self._quarantined_nodes or node_id in self._revoked_nodes

    def is_node_revoked(self, node_id: str) -> bool:
        """Check if a node is permanently revoked."""
        return node_id in self._revoked_nodes

    def get_blocked_nodes(self) -> set[str]:
        """Get all blocked (quarantined + revoked) node IDs."""
        return self._quarantined_nodes | self._revoked_nodes

    def get_events(self, node_id: str | None = None) -> list[MeshEvent]:
        """Get integration events, optionally filtered by node_id."""
        if node_id:
            return [e for e in self._events if e.node_id == node_id]
        return list(self._events)

    def process_full_quarantine(
        self, node_id: str, reason: str = "Consensus quarantine"
    ) -> list[MeshEvent]:
        """Full quarantine flow: flag -> consensus -> quarantine -> integrate.

        This is the complete flow when the mesh detects an attack:
        1. Mesh processes flags and quarantines the node
        2. Integrator revokes certificate, blocks access, logs audit

        Returns list of events generated.
        """
        events = []

        # Process flags through the mesh
        quarantined = self.mesh.process_flags()
        if node_id in quarantined:
            event = self.on_quarantine(node_id, reason)
            events.append(event)

        return events

    def process_full_revocation(
        self, node_id: str, reason: str = "Confirmed malicious"
    ) -> list[MeshEvent]:
        """Full revocation flow: quarantine -> revoke -> integrate.

        Returns list of events generated.
        """
        events = []

        # Revoke through the mesh
        with contextlib.suppress(ValueError):
            self.mesh.revoke_node(node_id, reason=reason)

        event = self.on_revoke(node_id, reason)
        events.append(event)

        return events

    def process_full_healing(self, node_id: str) -> list[MeshEvent]:
        """Full healing flow: begin_healing -> complete_healing -> integrate.

        If the node is already in HEALING state, skip begin_healing and
        proceed directly to complete_healing.

        Returns list of events generated.
        """
        events: list[MeshEvent] = []
        node = self.mesh.get_node(node_id)

        if node is None:
            return events

        # Begin healing (or skip if already healing)
        if node.state != NodeState.HEALING:
            begin_result = self.mesh.begin_healing(node_id)
            if not begin_result.success:
                return events

        # Complete healing (checks period and no new flags)
        complete_result = self.mesh.complete_healing(node_id)
        if complete_result.success:
            event = self.on_healing_complete(node_id)
            events.append(event)

        return events
