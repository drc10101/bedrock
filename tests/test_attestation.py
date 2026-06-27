"""Tests for Identity Fabric — Attestation (B-106)."""

import hashlib
import pytest
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bedrock.identity.attestation import (
    AttestationManager, AttestationClaim, AttestationResult,
    AttestationStatus, AttestationPolicy, BaselineEntry, compute_state_hash,
)


class TestComputeStateHash:
    """Test the state hash computation utility."""

    def test_single_component(self):
        result = compute_state_hash(b"firmware-v2.1.0")
        expected = hashlib.sha256(b"firmware-v2.1.0").hexdigest()
        assert result == expected

    def test_multiple_components(self):
        fw = hashlib.sha256(b"firmware").hexdigest().encode()
        os = hashlib.sha256(b"os").hexdigest().encode()
        cfg = hashlib.sha256(b"config").hexdigest().encode()
        result = compute_state_hash(fw, os, cfg)
        # Should be SHA-256 of all three concatenated
        h = hashlib.sha256()
        h.update(fw)
        h.update(os)
        h.update(cfg)
        assert result == h.hexdigest()

    def test_deterministic(self):
        """Same inputs produce same hash."""
        result1 = compute_state_hash(b"abc", b"def")
        result2 = compute_state_hash(b"abc", b"def")
        assert result1 == result2

    def test_different_inputs_different_hash(self):
        result1 = compute_state_hash(b"abc")
        result2 = compute_state_hash(b"xyz")
        assert result1 != result2


class TestAttestationClaim:
    """Test signed attestation claims."""

    def setup_method(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes_raw()

    def test_sign_and_verify(self):
        claim = AttestationClaim(
            node_uuid="test-node-1",
            state_hash=hashlib.sha256(b"good-state").hexdigest(),
            components=["firmware", "os", "config"],
        )
        claim.sign(self.private_key)
        assert claim.verify_signature(self.public_key) is True

    def test_wrong_key_fails_verification(self):
        claim = AttestationClaim(
            node_uuid="test-node-1",
            state_hash=hashlib.sha256(b"good-state").hexdigest(),
            components=["firmware"],
        )
        claim.sign(self.private_key)

        # Different key should fail
        other_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        assert claim.verify_signature(other_key) is False

    def test_unsigned_claim_fails_verification(self):
        claim = AttestationClaim(
            node_uuid="test-node-1",
            state_hash="abc123",
            components=["firmware"],
        )
        assert claim.verify_signature(self.public_key) is False

    def test_tampered_state_hash_fails(self):
        claim = AttestationClaim(
            node_uuid="test-node-1",
            state_hash=hashlib.sha256(b"good-state").hexdigest(),
            components=["firmware"],
        )
        claim.sign(self.private_key)

        # Tamper with the state hash after signing
        claim.state_hash = hashlib.sha256(b"tampered-state").hexdigest()
        assert claim.verify_signature(self.public_key) is False

    def test_tampered_uuid_fails(self):
        claim = AttestationClaim(
            node_uuid="test-node-1",
            state_hash=hashlib.sha256(b"good-state").hexdigest(),
            components=["firmware"],
        )
        claim.sign(self.private_key)

        claim.node_uuid = "different-node"
        assert claim.verify_signature(self.public_key) is False

    def test_signing_message_format(self):
        claim = AttestationClaim(
            node_uuid="node-1",
            state_hash="abc123",
            components=["firmware"],
        )
        msg = claim._signing_message()
        assert b"node-1" in msg
        assert b"abc123" in msg


class TestBaselineEntry:
    """Test baseline registration."""

    def test_create_baseline(self):
        baseline = BaselineEntry(
            node_type="warehouse-sensor",
            version="v2.1.0",
            baseline_hash=hashlib.sha256(b"known-good-state").hexdigest(),
            components=["firmware", "os", "config"],
            registered_by="admin",
        )
        assert baseline.node_type == "warehouse-sensor"
        assert baseline.version == "v2.1.0"
        assert baseline.superseded is False

    def test_default_components(self):
        baseline = BaselineEntry(
            node_type="server",
            version="v1.0.0",
            baseline_hash="abc",
        )
        assert baseline.components == ["firmware", "os", "config"]


class TestAttestationManager:
    """Test the full attestation lifecycle."""

    def setup_method(self):
        self.manager = AttestationManager(policy=AttestationPolicy.STRICT)
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes_raw()
        self.node_uuid = "test-node-001"
        self.baseline_hash = compute_state_hash(
            hashlib.sha256(b"firmware-v2").hexdigest().encode(),
            hashlib.sha256(b"linux-6.1").hexdigest().encode(),
            hashlib.sha256(b"config-prod").hexdigest().encode(),
        )

    def _register_baseline_and_key(self):
        """Helper: register baseline and public key."""
        self.manager.register_baseline(
            node_type="warehouse-sensor",
            version="v2.1.0",
            baseline_hash=self.baseline_hash,
            components=["firmware", "os", "config"],
        )
        self.manager.register_public_key(self.node_uuid, self.public_key)

    def _make_claim(self, state_hash=None, timestamp=None):
        """Helper: create and sign an attestation claim."""
        claim = AttestationClaim(
            node_uuid=self.node_uuid,
            state_hash=state_hash or self.baseline_hash,
            components=["firmware", "os", "config"],
            timestamp=timestamp or datetime.now(timezone.utc),
        )
        claim.sign(self.private_key)
        return claim

    def test_register_baseline(self):
        entry = self.manager.register_baseline(
            node_type="server",
            version="v1.0.0",
            baseline_hash="abc123",
            registered_by="admin-dave",
        )
        assert entry.node_type == "server"
        assert entry.version == "v1.0.0"
        assert entry.baseline_hash == "abc123"
        assert entry.superseded is False

    def test_baseline_supersedes_old(self):
        """Registering a new baseline marks the old one as superseded."""
        self.manager.register_baseline("server", "v1.0", "hash-v1")
        self.manager.register_baseline("server", "v2.0", "hash-v2")

        baseline = self.manager.get_baseline("server")
        assert baseline.version == "v2.0"
        assert baseline.baseline_hash == "hash-v2"

    def test_successful_attestation(self):
        """Full happy path: register baseline, verify signed claim."""
        self._register_baseline_and_key()
        claim = self._make_claim()
        result = self.manager.verify_attestation(claim, node_type="warehouse-sensor")
        assert result.status == AttestationStatus.PASSED
        assert result.baseline_hash == self.baseline_hash
        assert "passed" in result.reason.lower()

    def test_attestation_hash_mismatch(self):
        """Node sends a different state hash → FAILED."""
        self._register_baseline_and_key()
        wrong_hash = compute_state_hash(b"tampered-firmware")
        claim = self._make_claim(state_hash=wrong_hash)
        result = self.manager.verify_attestation(claim, node_type="warehouse-sensor")
        assert result.status == AttestationStatus.FAILED
        assert "mismatch" in result.reason.lower()

    def test_attestation_no_public_key(self):
        """Node not registered → FAILED."""
        self.manager.register_baseline("warehouse-sensor", "v2.1.0", self.baseline_hash)
        claim = self._make_claim()
        result = self.manager.verify_attestation(claim, node_type="warehouse-sensor")
        assert result.status == AttestationStatus.FAILED
        assert "no public key" in result.reason.lower()

    def test_attestation_no_baseline(self):
        """No baseline registered → FAILED."""
        self.manager.register_public_key(self.node_uuid, self.public_key)
        claim = self._make_claim()
        result = self.manager.verify_attestation(claim, node_type="nonexistent-type")
        assert result.status == AttestationStatus.FAILED
        assert "no baseline" in result.reason.lower()

    def test_attestation_invalid_signature(self):
        """Claim signed by wrong key → FAILED."""
        self._register_baseline_and_key()
        other_key = Ed25519PrivateKey.generate()
        claim = AttestationClaim(
            node_uuid=self.node_uuid,
            state_hash=self.baseline_hash,
            components=["firmware", "os", "config"],
        )
        claim.sign(other_key)  # Wrong key!
        result = self.manager.verify_attestation(claim, node_type="warehouse-sensor")
        assert result.status == AttestationStatus.FAILED
        assert "invalid signature" in result.reason.lower()

    def test_attestation_expired_claim(self):
        """Claim too old → EXPIRED (not FAILED, different security meaning)."""
        self._register_baseline_and_key()
        old_timestamp = datetime.now(timezone.utc) - timedelta(seconds=600)
        claim = self._make_claim(timestamp=old_timestamp)
        result = self.manager.verify_attestation(claim, node_type="warehouse-sensor")
        assert result.status == AttestationStatus.EXPIRED
        assert "exceeds max" in result.reason.lower()

    def test_attestation_fresh_claim_within_window(self):
        """Claim within the freshness window passes."""
        self._register_baseline_and_key()
        recent_timestamp = datetime.now(timezone.utc) - timedelta(seconds=10)
        claim = self._make_claim(timestamp=recent_timestamp)
        result = self.manager.verify_attestation(claim, node_type="warehouse-sensor")
        assert result.status == AttestationStatus.PASSED


class TestAttestationPolicy:
    """Test policy-based quarantine decisions."""

    def _setup_manager(self, policy):
        manager = AttestationManager(policy=policy)
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()
        node_uuid = "policy-test-node"
        baseline_hash = "good-hash"

        manager.register_baseline("sensor", "v1.0", baseline_hash)
        manager.register_public_key(node_uuid, public_key)
        return manager, private_key, node_uuid, baseline_hash

    def _make_failing_claim(self, manager, private_key, node_uuid, node_type):
        """Create a claim that will fail (wrong hash)."""
        claim = AttestationClaim(
            node_uuid=node_uuid,
            state_hash="wrong-hash",
            components=["firmware"],
        )
        claim.sign(private_key)
        return manager.verify_attestation(claim, node_type=node_type)

    def test_strict_quarantine_on_first_failure(self):
        """STRICT policy: any failure → quarantine."""
        manager, pk, uuid, bh = self._setup_manager(AttestationPolicy.STRICT)
        self._make_failing_claim(manager, pk, uuid, "sensor")
        assert manager.should_quarantine(uuid) is True

    def test_moderate_quarantine_on_second_failure(self):
        """MODERATE policy: 2+ consecutive failures → quarantine."""
        manager, pk, uuid, bh = self._setup_manager(AttestationPolicy.MODERATE)
        self._make_failing_claim(manager, pk, uuid, "sensor")
        assert manager.should_quarantine(uuid) is False  # 1 failure, not enough
        self._make_failing_claim(manager, pk, uuid, "sensor")
        assert manager.should_quarantine(uuid) is True  # 2 failures

    def test_permissive_never_quarantine(self):
        """PERMISSIVE policy: never auto-quarantine."""
        manager, pk, uuid, bh = self._setup_manager(AttestationPolicy.PERMISSIVE)
        for _ in range(5):
            self._make_failing_claim(manager, pk, uuid, "sensor")
        assert manager.should_quarantine(uuid) is False

    def test_success_resets_failure_count(self):
        """A successful attestation resets the failure counter."""
        manager, pk, uuid, bh = self._setup_manager(AttestationPolicy.MODERATE)
        self._make_failing_claim(manager, pk, uuid, "sensor")
        assert manager.get_failure_count(uuid) == 1

        # Now pass attestation
        claim = AttestationClaim(node_uuid=uuid, state_hash=bh, components=["firmware"])
        claim.sign(pk)
        manager.verify_attestation(claim, node_type="sensor")
        assert manager.get_failure_count(uuid) == 0


class TestAttestationHistory:
    """Test attestation audit trail."""

    def test_history_records_all_results(self):
        manager = AttestationManager()
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()
        node_uuid = "history-node"
        baseline_hash = "good-state"

        manager.register_baseline("sensor", "v1.0", baseline_hash)
        manager.register_public_key(node_uuid, public_key)

        # Pass
        claim_pass = AttestationClaim(node_uuid=node_uuid, state_hash=baseline_hash, components=["fw"])
        claim_pass.sign(private_key)
        manager.verify_attestation(claim_pass, node_type="sensor")

        # Fail
        claim_fail = AttestationClaim(node_uuid=node_uuid, state_hash="bad-state", components=["fw"])
        claim_fail.sign(private_key)
        manager.verify_attestation(claim_fail, node_type="sensor")

        history = manager.get_attestation_history()
        assert len(history) == 2

    def test_history_filter_by_node(self):
        manager = AttestationManager()
        pk1 = Ed25519PrivateKey.generate()
        pub1 = pk1.public_key().public_bytes_raw()
        pk2 = Ed25519PrivateKey.generate()
        pub2 = pk2.public_key().public_bytes_raw()

        manager.register_baseline("sensor", "v1.0", "hash-1")
        manager.register_public_key("node-1", pub1)
        manager.register_public_key("node-2", pub2)

        claim1 = AttestationClaim(node_uuid="node-1", state_hash="hash-1", components=["fw"])
        claim1.sign(pk1)
        manager.verify_attestation(claim1, node_type="sensor")

        claim2 = AttestationClaim(node_uuid="node-2", state_hash="hash-1", components=["fw"])
        claim2.sign(pk2)
        manager.verify_attestation(claim2, node_type="sensor")

        node1_history = manager.get_attestation_history(node_uuid="node-1")
        assert len(node1_history) == 1
        assert node1_history[0].claim.node_uuid == "node-1"

    def test_history_limit(self):
        manager = AttestationManager()
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()

        manager.register_baseline("sensor", "v1.0", "hash")
        manager.register_public_key("node-1", public_key)

        for i in range(20):
            claim = AttestationClaim(node_uuid="node-1", state_hash="hash", components=["fw"])
            claim.sign(private_key)
            manager.verify_attestation(claim, node_type="sensor")

        history = manager.get_attestation_history(limit=5)
        assert len(history) == 5


class TestAttestationIntegration:
    """Integration: attestation + node registry state transitions."""

    def test_attestation_failure_triggers_quarantine_lifecycle(self):
        """Full lifecycle: register node → attestation fails → quarantine → re-attest → active."""
        from bedrock.identity.registration import NodeRegistry, NodeState

        # Setup
        registry = NodeRegistry()
        attestor = AttestationManager(policy=AttestationPolicy.STRICT)

        # Register node
        private_key = Ed25519PrivateKey.generate()
        node = registry.register(name="warehouse-sensor-01", node_type="iot", private_key=private_key)
        good_hash = compute_state_hash(b"firmware-v2", b"os-v6", b"config-prod")

        # Register baseline and public key
        attestor.register_baseline("iot", "v2.1.0", good_hash, ["firmware", "os", "config"])
        attestor.register_public_key(node.node_id.uuid, node.node_id.public_key)

        # Node attests successfully
        claim = AttestationClaim(
            node_uuid=node.node_id.uuid,
            state_hash=good_hash,
            components=["firmware", "os", "config"],
        )
        claim.sign(private_key)
        result = attestor.verify_attestation(claim, node_type="iot")
        assert result.status == AttestationStatus.PASSED
        assert node.state == NodeState.ACTIVE

        # Node gets compromised — bad attestation
        bad_claim = AttestationClaim(
            node_uuid=node.node_id.uuid,
            state_hash="tampered-hash",
            components=["firmware", "os", "config"],
        )
        bad_claim.sign(private_key)
        result = attestor.verify_attestation(bad_claim, node_type="iot")
        assert result.status == AttestationStatus.FAILED

        # STRICT policy → quarantine
        assert attestor.should_quarantine(node.node_id.uuid) is True
        registry.transition(node.node_id.uuid, NodeState.SUSPECT, reason="attestation failed")
        registry.transition(node.node_id.uuid, NodeState.QUARANTINED, reason="attestation failed")

        # QUARANTINED: can't route, relay, or decrypt
        node = registry.get(node.node_id.uuid)
        assert node.can_route() is False
        assert node.can_decrypt() is False

        # Node re-attests successfully
        good_claim = AttestationClaim(
            node_uuid=node.node_id.uuid,
            state_hash=good_hash,
            components=["firmware", "os", "config"],
        )
        good_claim.sign(private_key)
        result = attestor.verify_attestation(good_claim, node_type="iot")
        assert result.status == AttestationStatus.PASSED

        # Node transitions back to ACTIVE via HEALING
        registry.transition(node.node_id.uuid, NodeState.HEALING, reason="re-attesting")
        registry.transition(node.node_id.uuid, NodeState.ACTIVE, reason="re-attestation passed")
        node = registry.get(node.node_id.uuid)
        assert node.can_route() is True
        assert node.can_decrypt() is True