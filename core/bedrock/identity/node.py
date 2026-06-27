"""
Node identity model.

Every node in a Bedrock network has a cryptographic identity:
- Node ID (UUID v7 + ed25519 public key)
- Capability scope (what data categories this node can access)
- Audit trail (every action logged)
- Attestation baseline (known-good software state hash)

B-105: Full implementation with ed25519 key generation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import uuid


class NodeState(Enum):
    """Node trust states in the Self-Healing Mesh.

    Lifecycle: ACTIVE → SUSPECT → QUARANTINED → HEALING → ACTIVE
    Any state can transition to REVOKED (terminal).

    ACTIVE:       Normal operation. Can route, relay, and decrypt.
    SUSPECT:       Flagged by neighbors. Can still route and decrypt.
    QUARANTINED:   Attestation failed or consensus threshold met. Cannot route or decrypt.
    HEALING:       Re-attesting after quarantine. Can relay but not decrypt.
    REVOKED:       Permanently removed. Terminal state.
    """
    ACTIVE = "active"
    SUSPECT = "suspect"
    QUARANTINED = "quarantined"
    HEALING = "healing"
    REVOKED = "revoked"


@dataclass
class NodeID:
    """Cryptographic node identifier.

    Every node gets a UUID v7 (time-sortable) and an ed25519 key pair.
    The public key is the node's cryptographic identity — used for
    signing attestation claims, E2EE key agreement, and certificate binding.
    The private key never leaves the node.
    """
    uuid: str  # UUID v7, time-sortable
    public_key: bytes  # ed25519 public key (32 bytes)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def generate(cls, private_key: Optional[Ed25519PrivateKey] = None) -> "NodeID":
        """Generate a new node ID with ed25519 key pair.

        Args:
            private_key: Optional pre-generated key. If None, a new one is generated.

        Returns:
            NodeID with UUID v7 and the public key from the key pair.
        """
        if private_key is None:
            private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()

        # UUID v7 if available (Python 3.13+), fallback to UUID v4
        node_uuid = str(uuid.uuid7()) if hasattr(uuid, 'uuid7') else str(uuid.uuid4())

        return cls(
            uuid=node_uuid,
            public_key=public_key,
        )

    def public_key_hex(self) -> str:
        """Return the public key as a hex string for display/logging."""
        return self.public_key.hex()

    def fingerprint(self) -> str:
        """Short fingerprint for identification (first 16 hex chars of public key)."""
        return self.public_key.hex()[:16]


@dataclass
class Node:
    """A node in the Bedrock network.

    Every node — server, container, IoT device, API gateway — is a Node.
    Nodes have cryptographic identity, capability scope, and a trust state
    managed by the Self-Healing Mesh.
    """
    node_id: NodeID
    name: str
    node_type: str = "server"  # server, container, iot, gateway, client
    capabilities: List = field(default_factory=list)  # CapabilityScope items
    state: NodeState = NodeState.ACTIVE
    attestation_baseline: Optional[str] = None  # SHA-256 hash of known-good state
    certificate_serial: Optional[str] = None
    certificate_expires: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None
    flags: List = field(default_factory=list)  # Neighbor flags for consensus
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)  # Extensible key-value pairs

    def can_route(self) -> bool:
        """Whether this node can route traffic.

        Only ACTIVE and SUSPECT nodes can route. QUARANTINED nodes are
        isolated. HEALING nodes can only relay.
        """
        return self.state in (NodeState.ACTIVE, NodeState.SUSPECT)

    def can_relay(self) -> bool:
        """Whether this node can relay (but not decrypt) traffic.

        HEALING nodes can relay traffic but cannot decrypt payloads.
        This lets them participate in the mesh while re-attesting.
        """
        return self.state in (NodeState.ACTIVE, NodeState.SUSPECT, NodeState.HEALING)

    def can_decrypt(self) -> bool:
        """Whether this node can decrypt data.

        Only ACTIVE and SUSPECT nodes can decrypt. QUARANTINED and HEALING
        nodes see only ciphertext.
        """
        return self.state in (NodeState.ACTIVE, NodeState.SUSPECT)

    def flag(self, flagger_id: str, reason: str) -> None:
        """Record a neighbor flagging this node.

        When enough neighbors flag a node (consensus threshold), the
        Self-Healing Mesh transitions it to SUSPECT or QUARANTINED.
        """
        self.flags.append({
            "flagger": flagger_id,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def flag_count(self) -> int:
        """Number of unique neighbors that have flagged this node."""
        return len({f["flagger"] for f in self.flags})

    def update_heartbeat(self) -> None:
        """Record a heartbeat from this node."""
        self.last_heartbeat = datetime.now(timezone.utc)

    def is_healthy(self, max_heartbeat_age_seconds: int = 300) -> bool:
        """Check if the node's heartbeat is recent enough.

        Args:
            max_heartbeat_age_seconds: Maximum seconds since last heartbeat
                before considering the node unhealthy. Default 5 minutes.
        """
        if self.last_heartbeat is None:
            return False
        age = (datetime.now(timezone.utc) - self.last_heartbeat).total_seconds()
        return age <= max_heartbeat_age_seconds