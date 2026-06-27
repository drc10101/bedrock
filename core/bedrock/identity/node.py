"""
Node identity model.

Every node in a Bedrock network has a cryptographic identity:
- Node ID (UUID v7 + ed25519 public key)
- Capability scope (what data categories this node can access)
- Audit trail (every action logged)
- Attestation baseline (known-good software state hash)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class NodeState(Enum):
    """Node trust states in the Self-Healing Mesh."""
    ACTIVE = "active"
    SUSPECT = "suspect"
    QUARANTINED = "quarantined"
    HEALING = "healing"
    REVOKED = "revoked"


@dataclass
class NodeID:
    """Cryptographic node identifier."""
    uuid: str  # UUID v7, time-sortable
    public_key: bytes  # ed25519 public key (32 bytes)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def generate(cls) -> "NodeID":
        """Generate a new node ID with ed25519 key pair."""
        # Actual key generation in B-105; placeholder for structure
        return cls(
            uuid=str(uuid.uuid7()) if hasattr(uuid, 'uuid7') else str(uuid.uuid4()),
            public_key=b"",  # Will be populated by ed25519 key generation
        )


@dataclass
class Node:
    """A node in the Bedrock network.

    Every node — server, container, IoT device, API gateway — is a Node.
    Nodes have cryptographic identity, capability scope, and a trust state
    managed by the Self-Healing Mesh.
    """
    node_id: NodeID
    name: str
    capabilities: list = field(default_factory=list)  # CapabilityScope items
    state: NodeState = NodeState.ACTIVE
    attestation_baseline: Optional[str] = None  # SHA-256 hash of known-good state
    certificate_serial: Optional[str] = None
    certificate_expires: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None
    flags: list = field(default_factory=list)  # Neighbor flags for consensus
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def can_route(self) -> bool:
        """Whether this node can route traffic."""
        return self.state in (NodeState.ACTIVE, NodeState.SUSPECT)

    def can_relay(self) -> bool:
        """Whether this node can relay (but not decrypt) traffic."""
        return self.state in (NodeState.ACTIVE, NodeState.SUSPECT, NodeState.HEALING)

    def can_decrypt(self) -> bool:
        """Whether this node can decrypt data."""
        return self.state in (NodeState.ACTIVE, NodeState.SUSPECT)

    def flag(self, flagger_id: str, reason: str) -> None:
        """Record a neighbor flagging this node."""
        self.flags.append({
            "flagger": flagger_id,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def flag_count(self) -> int:
        """Number of unique neighbors that have flagged this node."""
        return len({f["flagger"] for f in self.flags})