"""
Node attestation — proving a node's software state matches a known-good baseline.

Attestation is the trust foundation of the Self-Healing Mesh. When a node boots,
it hashes its software state (firmware, OS, config, running processes) and submits
the hash. The AttestationManager verifies it against the registered baseline.

If the hash doesn't match, the node is quarantined — it can't route, relay, or
decrypt data until it re-attests successfully.

Attestation flow:
1. Admin registers a baseline hash for a node type (e.g., "warehouse-sensor-v2")
2. Node boots, computes its state hash, submits it via signed attestation claim
3. AttestationManager verifies: signed by node's key + hash matches baseline
4. Pass → node transitions to ACTIVE (or stays ACTIVE)
5. Fail → node transitions to QUARANTINED, audit chain records the failure

Trade Secret — InFill Systems, LLC.
"""

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature


class AttestationStatus(Enum):
    """Result of an attestation verification."""
    PASSED = "passed"
    FAILED = "failed"
    PENDING = "pending"
    EXPIRED = "expired"


class AttestationPolicy(Enum):
    """How strict attestation enforcement is.

    STRICT:   Any baseline mismatch → immediate quarantine.
    MODERATE: First mismatch → SUSPECT, second → QUARANTINED.
    PERMISSIVE: Log mismatches, no automatic state change.
    """
    STRICT = "strict"
    MODERATE = "moderate"
    PERMISSIVE = "permissive"


@dataclass
class AttestationClaim:
    """A node's claim about its current software state.

    The claim is signed by the node's ed25519 private key, proving it came
    from the node (not spoofed by an attacker).
    """
    node_uuid: str
    state_hash: str  # SHA-256 of node's software state
    components: List[str]  # What was hashed: ["firmware", "os", "config", ...]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signature: Optional[bytes] = None  # ed25519 signature over (uuid + state_hash + timestamp)

    def sign(self, private_key: Ed25519PrivateKey) -> None:
        """Sign the claim with the node's ed25519 private key.

        The signature covers: node_uuid + state_hash + ISO timestamp.
        This prevents replay attacks and claim tampering.
        """
        message = self._signing_message()
        self.signature = private_key.sign(message)

    def verify_signature(self, public_key: bytes) -> bool:
        """Verify the claim's ed25519 signature against the node's public key.

        Args:
            public_key: The node's ed25519 public key (32 bytes)

        Returns:
            True if the signature is valid, False otherwise.
        """
        if self.signature is None:
            return False
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            pk = Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(self.signature, self._signing_message())
            return True
        except (InvalidSignature, Exception):
            return False

    def _signing_message(self) -> bytes:
        """Construct the message that gets signed/verified.

        Covers: node_uuid + state_hash + ISO timestamp.
        """
        return (
            f"{self.node_uuid}:{self.state_hash}:{self.timestamp.isoformat()}"
        ).encode("utf-8")


@dataclass
class AttestationResult:
    """The outcome of an attestation verification."""
    claim: AttestationClaim
    status: AttestationStatus
    baseline_hash: Optional[str] = None  # The registered baseline, if found
    reason: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BaselineEntry:
    """A registered known-good baseline for a node type.

    Baselines can be versioned — a new firmware version gets a new baseline.
    Old baselines are kept for rollback comparison but marked as superseded.
    """
    node_type: str  # e.g., "warehouse-sensor", "api-server"
    version: str    # e.g., "v2.1.0"
    baseline_hash: str  # SHA-256 of known-good state
    components: List[str] = field(default_factory=lambda: ["firmware", "os", "config"])  # What was hashed
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    registered_by: str = ""  # Admin who registered
    superseded: bool = False  # True if a newer baseline exists


class AttestationManager:
    """Manages node attestation: baseline registration, verification, and failure handling.

    Attestation is the foundation of the Self-Healing Mesh. When a node boots,
    it hashes its software state and submits a signed attestation claim. The
    AttestationManager verifies:

    1. The claim is signed by the node's ed25519 key (not spoofed)
    2. The state hash matches the registered baseline (not tampered)
    3. The claim is not too old (not replayed)

    If verification fails, the manager returns a FAILED result and the
    Self-Healing Mesh handles quarantine.
    """

    def __init__(self, policy: AttestationPolicy = AttestationPolicy.STRICT,
                 max_claim_age_seconds: int = 300):
        self._baselines: Dict[str, BaselineEntry] = {}  # node_type -> BaselineEntry
        self._results: List[AttestationResult] = []  # Audit trail
        self._failure_counts: Dict[str, int] = {}  # node_uuid -> consecutive failures
        self._public_keys: Dict[str, bytes] = {}  # node_uuid -> ed25519 public key
        self.policy = policy
        self.max_claim_age_seconds = max_claim_age_seconds

    def register_baseline(self, node_type: str, version: str,
                          baseline_hash: str, components: Optional[List[str]] = None,
                          registered_by: str = "admin") -> BaselineEntry:
        """Register a known-good software state hash for a node type.

        If a baseline already exists for this node_type+version, it's updated.
        If a baseline exists for the same node_type with a different version,
        the old one is marked as superseded.

        Args:
            node_type: Type of node (e.g., "warehouse-sensor")
            version: Software version (e.g., "v2.1.0")
            baseline_hash: SHA-256 hash of known-good state
            components: What was hashed (default: ["firmware", "os", "config"])
            registered_by: Admin who registered this baseline

        Returns:
            The registered BaselineEntry
        """
        if components is None:
            components = ["firmware", "os", "config"]

        # Mark existing baselines for this node_type as superseded
        for key, entry in self._baselines.items():
            if entry.node_type == node_type and not entry.superseded:
                entry.superseded = True

        entry = BaselineEntry(
            node_type=node_type,
            version=version,
            baseline_hash=baseline_hash,
            components=components,
            registered_by=registered_by,
        )
        self._baselines[node_type] = entry
        return entry

    def register_public_key(self, node_uuid: str, public_key: bytes) -> None:
        """Register a node's ed25519 public key for signature verification.

        In production, this would be done during node registration and
        bound to the node's certificate.
        """
        self._public_keys[node_uuid] = public_key

    def verify_attestation(self, claim: AttestationClaim,
                           node_type: Optional[str] = None) -> AttestationResult:
        """Verify a node's attestation claim against its registered baseline.

        Verification checks:
        1. Signature: Claim is signed by the node's ed25519 key
        2. Freshness: Claim timestamp is within max_claim_age_seconds
        3. Baseline: State hash matches the registered baseline for the node type

        Args:
            claim: The attestation claim to verify
            node_type: The node type to check against. If None, uses
                       the first non-superseded baseline found.

        Returns:
            AttestationResult with status PASSED, FAILED, or EXPIRED
        """
        # Check 1: Verify signature
        public_key = self._public_keys.get(claim.node_uuid)
        if public_key is None:
            result = AttestationResult(
                claim=claim,
                status=AttestationStatus.FAILED,
                reason="No public key registered for node",
            )
            self._results.append(result)
            return result

        if not claim.verify_signature(public_key):
            result = AttestationResult(
                claim=claim,
                status=AttestationStatus.FAILED,
                reason="Invalid signature — claim may be spoofed",
            )
            self._results.append(result)
            self._record_failure(claim.node_uuid)
            return result

        # Check 2: Verify freshness (replay protection)
        age = (datetime.now(timezone.utc) - claim.timestamp).total_seconds()
        if age > self.max_claim_age_seconds:
            result = AttestationResult(
                claim=claim,
                status=AttestationStatus.EXPIRED,
                baseline_hash=self._get_baseline_hash(node_type),
                reason=f"Claim age {age:.0f}s exceeds max {self.max_claim_age_seconds}s",
            )
            self._results.append(result)
            return result

        # Check 3: Verify state hash against baseline
        baseline = self._find_baseline(node_type)
        if baseline is None:
            result = AttestationResult(
                claim=claim,
                status=AttestationStatus.FAILED,
                reason="No baseline registered for this node type",
            )
            self._results.append(result)
            return result

        if claim.state_hash != baseline.baseline_hash:
            result = AttestationResult(
                claim=claim,
                status=AttestationStatus.FAILED,
                baseline_hash=baseline.baseline_hash,
                reason=f"State hash mismatch: expected {baseline.baseline_hash[:16]}..., "
                       f"got {claim.state_hash[:16]}...",
            )
            self._results.append(result)
            self._record_failure(claim.node_uuid)
            return result

        # All checks passed
        self._failure_counts.pop(claim.node_uuid, None)  # Reset failure count
        result = AttestationResult(
            claim=claim,
            status=AttestationStatus.PASSED,
            baseline_hash=baseline.baseline_hash,
            reason="Attestation passed",
        )
        self._results.append(result)
        return result

    def should_quarantine(self, node_uuid: str) -> bool:
        """Determine if a node should be quarantined based on attestation policy.

        STRICT:   Any failure → quarantine
        MODERATE: 2+ consecutive failures → quarantine
        PERMISSIVE: Never quarantine automatically

        Args:
            node_uuid: The node to evaluate

        Returns:
            True if the node should be quarantined
        """
        failures = self._failure_counts.get(node_uuid, 0)
        if self.policy == AttestationPolicy.STRICT:
            return failures >= 1
        elif self.policy == AttestationPolicy.MODERATE:
            return failures >= 2
        else:  # PERMISSIVE
            return False

    def get_failure_count(self, node_uuid: str) -> int:
        """Get the number of consecutive attestation failures for a node."""
        return self._failure_counts.get(node_uuid, 0)

    def get_baseline(self, node_type: str) -> Optional[BaselineEntry]:
        """Get the current baseline for a node type."""
        return self._baselines.get(node_type)

    def get_attestation_history(self, node_uuid: Optional[str] = None,
                                limit: int = 100) -> List[AttestationResult]:
        """Get attestation results, optionally filtered by node.

        Args:
            node_uuid: Filter to a specific node (None = all nodes)
            limit: Maximum results to return

        Returns:
            List of AttestationResult, most recent first
        """
        results = self._results
        if node_uuid is not None:
            results = [r for r in results if r.claim.node_uuid == node_uuid]
        return list(reversed(results[-limit:]))

    def _find_baseline(self, node_type: Optional[str] = None) -> Optional[BaselineEntry]:
        """Find the current (non-superseded) baseline for a node type."""
        if node_type is not None:
            return self._baselines.get(node_type)
        # If no type specified, return first non-superseded baseline
        for entry in self._baselines.values():
            if not entry.superseded:
                return entry
        return None

    def _get_baseline_hash(self, node_type: Optional[str] = None) -> Optional[str]:
        """Get just the hash string for a baseline."""
        baseline = self._find_baseline(node_type)
        return baseline.baseline_hash if baseline else None

    def _record_failure(self, node_uuid: str) -> None:
        """Increment the consecutive failure counter for a node."""
        self._failure_counts[node_uuid] = self._failure_counts.get(node_uuid, 0) + 1


def compute_state_hash(*components: bytes) -> str:
    """Compute a SHA-256 state hash from one or more component hashes.

    This is how nodes compute their attestation hash at boot time.
    Each component (firmware, OS, config) is hashed separately,
    then the hashes are combined into a final state hash.

    Args:
        components: One or more byte strings representing software state

    Returns:
        SHA-256 hex digest of the combined state

    Example:
        >>> firmware_hash = hashlib.sha256(firmware_data).hexdigest()
        >>> os_hash = hashlib.sha256(os_data).hexdigest()
        >>> config_hash = hashlib.sha256(config_data).hexdigest()
        >>> state_hash = compute_state_hash(
        ...     firmware_hash.encode(), os_hash.encode(), config_hash.encode()
        ... )
    """
    h = hashlib.sha256()
    for component in components:
        h.update(component)
    return h.hexdigest()