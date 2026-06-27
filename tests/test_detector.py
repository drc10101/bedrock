"""Tests for Attack Detector."""

from bedrock.mesh.detector import AttackDetector, SignalType


class TestAttackDetector:
    """Test mesh attack detection heuristics."""

    def test_detect_credential_stuffing(self):
        detector = AttackDetector(node_id="node-001")
        signal = detector.detect(
            signal_type=SignalType.CREDENTIAL_STUFFING,
            target_node_id="node-abc",
            details={"attempts": 75, "window_seconds": 60},
        )
        assert signal.signal_type == SignalType.CREDENTIAL_STUFFING
        assert signal.target_node_id == "node-abc"
        assert signal.source_node_id == "node-001"

    def test_should_isolate_below_threshold(self):
        detector = AttackDetector(node_id="node-001")
        # Only 1 flagger — below consensus threshold
        detector.detect(SignalType.CREDENTIAL_STUFFING, "node-abc")
        assert detector.should_isolate("node-abc", consensus_threshold=2) is False

    def test_should_isolate_at_threshold(self):
        detector = AttackDetector(node_id="node-001")
        # 2 unique flaggers — meets consensus threshold
        s1 = detector.detect(SignalType.CREDENTIAL_STUFFING, "node-abc")
        s1.source_node_id = "neighbor-1"
        s2 = detector.detect(SignalType.UNUSUAL_VOLUME, "node-abc")
        s2.source_node_id = "neighbor-2"
        assert detector.should_isolate("node-abc", consensus_threshold=2) is True

    def test_get_flags_for_node(self):
        detector = AttackDetector(node_id="node-001")
        detector.detect(SignalType.CREDENTIAL_STUFFING, "node-abc")
        detector.detect(SignalType.UNUSUAL_VOLUME, "node-xyz")
        flags = detector.get_flags_for_node("node-abc")
        assert len(flags) == 1
        assert flags[0].target_node_id == "node-abc"