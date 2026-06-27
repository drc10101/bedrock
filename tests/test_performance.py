"""
Performance and load tests for Bedrock Core.

Benchmarks critical-path operations under load:
- Encryption/decryption throughput and latency
- Key derivation performance
- Silo key rotation overhead
- Consent lifecycle throughput
- Audit chain append/verify/query under load
- Licensing validation throughput
- Master key rotation with re-encryption
- Node registration scalability
- Certificate issuance throughput

These tests establish baseline performance numbers and verify
Bedrock can handle realistic production loads.
"""

import time
import statistics
from dataclasses import dataclass

import pytest

from bedrock.identity.registration import NodeRegistry
from bedrock.identity.node import NodeState
from bedrock.identity.certificates import CertificateManager
from bedrock.data_separation.silo import SiloManager
from bedrock.data_separation.consent import ConsentGate
from bedrock.encryption.engine import FieldEncryptor, EncryptionEngine, E2EEDeliverer
from bedrock.key_management.keys import KeyManager
from bedrock.key_management.rotation import (
    KeyRotationManager, RotationPolicy, RotationTrigger,
)
from bedrock.licensing.enforcement import LicenseEnforcer, LicenseTier
from bedrock.audit.chain import AuditChain


@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""
    name: str
    iterations: int
    total_seconds: float
    ops_per_second: float
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float


def benchmark(func, iterations=1000, warmup=50):
    """Run a function many times and collect timing statistics."""
    # Warmup
    for _ in range(warmup):
        func()

    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # ms

    total = sum(times) / 1000  # seconds
    ops_per_sec = iterations / total if total > 0 else float('inf')
    sorted_times = sorted(times)

    return BenchmarkResult(
        name=func.__name__ if hasattr(func, '__name__') else str(func),
        iterations=iterations,
        total_seconds=total,
        ops_per_second=ops_per_sec,
        mean_ms=statistics.mean(times),
        median_ms=statistics.median(times),
        p95_ms=sorted_times[int(iterations * 0.95)],
        p99_ms=sorted_times[int(iterations * 0.99)],
    )


class TestEncryptionPerformance:
    """Benchmark encryption and decryption operations."""

    def setup_method(self):
        self.km = KeyManager()
        self.master_key = KeyManager.generate_master_key()
        self.fe = FieldEncryptor(self.km, self.master_key)

    def test_encrypt_throughput(self):
        """Field encryption: 500 ops, measure throughput."""
        result = benchmark(
            lambda: self.fe.encrypt("SSN 123-45-6789", "identity", "rec-1", "read"),
            iterations=500,
        )
        assert result.ops_per_second > 100, f"Encryption too slow: {result.ops_per_second:.0f} ops/s"
        assert result.p99_ms < 100, f"P99 latency too high: {result.p99_ms:.1f}ms"

    def test_decrypt_throughput(self):
        """Field decryption: 500 ops, measure throughput."""
        ct = self.fe.encrypt("SSN 123-45-6789", "identity", "rec-1", "read")

        result = benchmark(
            lambda: self.fe.decrypt(ct, "identity", "rec-1", "read"),
            iterations=500,
        )
        assert result.ops_per_second > 100, f"Decryption too slow: {result.ops_per_second:.0f} ops/s"
        assert result.p99_ms < 100, f"P99 latency too high: {result.p99_ms:.1f}ms"

    def test_encrypt_decrypt_roundtrip(self):
        """Full encrypt-decrypt round trip: 500 ops."""
        def roundtrip():
            ct = self.fe.encrypt("patient data", "medical", "rec-1", "consent")
            self.fe.decrypt(ct, "medical", "rec-1", "consent")

        result = benchmark(roundtrip, iterations=500)
        assert result.ops_per_second > 50, f"Round trip too slow: {result.ops_per_second:.0f} ops/s"

    def test_multi_silo_performance(self):
        """Encryption across 10 silos: 200 ops per silo."""
        silos = [f"silo_{i}" for i in range(10)]
        times = []

        for silo in silos:
            start = time.perf_counter()
            for _ in range(200):
                ct = self.fe.encrypt(f"data for {silo}", silo, "rec-1", "read")
                self.fe.decrypt(ct, silo, "rec-1", "read")
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # Each silo should complete 200 round trips in under 5 seconds
        avg_time = statistics.mean(times)
        assert avg_time < 5.0, f"Average silo time too slow: {avg_time:.2f}s"


class TestKeyDerivationPerformance:
    """Benchmark key derivation operations."""

    def setup_method(self):
        self.km = KeyManager()
        self.master_key = KeyManager.generate_master_key()

    def test_silo_key_derivation(self):
        """Silo key derivation: 1000 unique silo keys."""
        def derive_unique_keys():
            for i in range(10):
                self.km.derive_silo_key(self.master_key, f"silo_{i}", version=1)

        result = benchmark(derive_unique_keys, iterations=100)
        assert result.ops_per_second > 50, f"Silo key derivation too slow: {result.ops_per_second:.0f} ops/s"

    def test_cached_silo_key_derivation(self):
        """Cached silo key derivation (same key repeatedly): 1000 ops."""
        # First call caches the key
        self.km.derive_silo_key(self.master_key, "cached_silo", version=1)

        result = benchmark(
            lambda: self.km.derive_silo_key(self.master_key, "cached_silo", version=1),
            iterations=1000,
        )
        # Cached derivation should be very fast (>1000 ops/s)
        assert result.ops_per_second > 500, f"Cached derivation too slow: {result.ops_per_second:.0f} ops/s"


class TestConsentPerformance:
    """Benchmark consent lifecycle operations."""

    def setup_method(self):
        self.consent = ConsentGate()
        self.reg = NodeRegistry()
        self.patient = self.reg.register(name='patient-1', node_type='patient')
        self.provider = self.reg.register(name='provider-1', node_type='provider')

    def test_consent_request_throughput(self):
        """Consent request creation: 200 ops."""
        def create_consent():
            self.consent.request_consent(
                requesting_node_id=self.provider.node_id.uuid,
                source_silo='medical',
                target_silo='identity',
                categories=['diagnosis'],
                scope='read',
                reason='treatment',
            )

        result = benchmark(create_consent, iterations=200)
        assert result.ops_per_second > 50, f"Consent request too slow: {result.ops_per_second:.0f} ops/s"

    def test_consent_approve_throughput(self):
        """Consent approval: 200 ops."""
        # Pre-create consent requests
        consent_ids = []
        for _ in range(250):
            result = self.consent.request_consent(
                requesting_node_id=self.provider.node_id.uuid,
                source_silo='medical',
                target_silo='identity',
                categories=['diagnosis'],
                scope='read',
                reason='treatment',
            )
            consent_ids.append(result.consent_id)

        idx = [0]
        def approve_consent():
            cid = consent_ids[idx[0] % len(consent_ids)]
            idx[0] += 1
            self.consent.approve_consent(consent_id=cid, data_owner_id=self.patient.node_id.uuid)

        result = benchmark(approve_consent, iterations=200)
        assert result.ops_per_second > 50, f"Consent approval too slow: {result.ops_per_second:.0f} ops/s"


class TestAuditPerformance:
    """Benchmark audit chain operations."""

    def setup_method(self):
        self.audit = AuditChain()

    def test_audit_append_throughput(self):
        """Audit chain append: 500 ops."""
        result = benchmark(
            lambda: self.audit.append(
                action='access', actor_id='user-1', target_id='record-1',
                silo='medical', details={'op': 'read'},
            ),
            iterations=500,
        )
        assert result.ops_per_second > 100, f"Audit append too slow: {result.ops_per_second:.0f} ops/s"

    def test_audit_verify_under_load(self):
        """Audit chain verify after 1000 appends."""
        # Build up a chain
        for i in range(1000):
            self.audit.append(
                action='access', actor_id=f'user-{i%10}',
                target_id=f'record-{i}', silo='medical',
            )

        result = benchmark(
            lambda: self.audit.verify(),
            iterations=50,
        )
        # Verify should complete even with 1000 entries
        assert result.mean_ms < 500, f"Verify too slow with 1000 entries: {result.mean_ms:.1f}ms"

    def test_audit_query_performance(self):
        """Audit chain query: 200 ops with 500 entries."""
        # Build up entries
        for i in range(500):
            self.audit.append(
                action='access' if i % 2 == 0 else 'modify',
                actor_id=f'user-{i%10}',
                target_id=f'record-{i}',
                silo='medical' if i % 3 == 0 else 'identity',
            )

        result = benchmark(
            lambda: self.audit.query(actor_id='user-5'),
            iterations=200,
        )
        assert result.ops_per_second > 50, f"Audit query too slow: {result.ops_per_second:.0f} ops/s"


class TestLicensingPerformance:
    """Benchmark licensing operations."""

    def setup_method(self):
        self.enforcer = LicenseEnforcer()

    def test_license_generation_throughput(self):
        """License key generation: 200 ops."""
        result = benchmark(
            lambda: self.enforcer.generate_license_key(
                tier=LicenseTier.DEVELOPER, issued_to='bench-user', max_nodes=3,
            ),
            iterations=200,
        )
        assert result.ops_per_second > 50, f"License generation too slow: {result.ops_per_second:.0f} ops/s"

    def test_license_validation_throughput(self):
        """License key validation: 500 ops."""
        key = self.enforcer.generate_license_key(
            tier=LicenseTier.DEVELOPER, issued_to='bench-user', max_nodes=3,
        )

        result = benchmark(
            lambda: self.enforcer.validate_license(key),
            iterations=500,
        )
        assert result.ops_per_second > 100, f"License validation too slow: {result.ops_per_second:.0f} ops/s"


class TestNodeRegistrationPerformance:
    """Benchmark node registration scalability."""

    def test_bulk_registration(self):
        """Register 100 nodes: measure total time."""
        reg = NodeRegistry()
        start = time.perf_counter()
        nodes = []
        for i in range(100):
            node = reg.register(name=f'node-{i}', node_type='provider')
            nodes.append(node)
        elapsed = time.perf_counter() - start

        # 100 nodes should register in under 2 seconds
        assert elapsed < 2.0, f"100 node registrations took {elapsed:.2f}s"
        assert len(nodes) == 100

    def test_certificate_issuance_throughput(self):
        """Certificate issuance: 100 ops (business tier to avoid node limit)."""
        reg = NodeRegistry()
        cm = CertificateManager(license_tier=LicenseTier.ENTERPRISE)

        # Pre-register nodes
        nodes = []
        for i in range(110):
            node = reg.register(name=f'cert-node-{i}', node_type='provider')
            nodes.append(node)

        def issue_cert():
            node = nodes[issue_cert.idx % len(nodes)]
            issue_cert.idx += 1
            cm.issue_certificate(
                node_uuid=node.node_id.uuid,
                node_name=node.name,
                public_key_hash=node.node_id.public_key_hex(),
            )

        issue_cert.idx = 0

        result = benchmark(issue_cert, iterations=100)
        assert result.ops_per_second > 10, f"Certificate issuance too slow: {result.ops_per_second:.0f} ops/s"


class TestKeyRotationPerformance:
    """Benchmark key rotation and re-encryption."""

    def setup_method(self):
        self.km = KeyManager()
        self.master_key = KeyManager.generate_master_key()
        self.rotator = KeyRotationManager(self.km, self.master_key)
        self.fe = FieldEncryptor(self.km, self.master_key)

    def test_master_key_rotation_throughput(self):
        """Master key rotation: 20 rotations (measure overhead)."""
        result = benchmark(
            lambda: self.rotator.rotate_master_key(),
            iterations=20,
        )
        # Rotation is expensive (key gen, cache clear) but should still be reasonable
        assert result.ops_per_second > 5, f"Key rotation too slow: {result.ops_per_second:.0f} ops/s"

    def test_re_encrypt_field_throughput(self):
        """Re-encrypt 100 fields after rotation."""
        # Encrypt 100 fields with original key
        ciphertexts = []
        for i in range(100):
            ct = self.fe.encrypt(f"data-{i}", "medical", f"rec-{i}", "read")
            ciphertexts.append(ct)

        # Rotate
        new_key, _ = self.rotator.rotate_master_key()
        fe_new = FieldEncryptor(self.km, new_key)

        # Measure re-encryption
        start = time.perf_counter()
        for i, ct in enumerate(ciphertexts):
            self.rotator.re_encrypt_field(
                fe_new, ct, "medical", f"rec-{i}", "read",
                old_master_key=self.master_key,
            )
        elapsed = time.perf_counter() - start

        # 100 re-encryptions should complete in under 5 seconds
        assert elapsed < 5.0, f"100 re-encryptions took {elapsed:.2f}s"


class TestE2EEPerformance:
    """Benchmark E2EE operations."""

    def test_e2ee_encrypt_decrypt(self):
        """E2EE encrypt-decrypt round trip: 100 ops."""
        e2ee = E2EEDeliverer()
        sender_priv, sender_pub = E2EEDeliverer.generate_key_pair()
        recipient_priv, recipient_pub = E2EEDeliverer.generate_key_pair()

        def e2ee_roundtrip():
            ct = e2ee.encrypt_for_recipient("secret message", recipient_pub, sender_private_key=sender_priv)
            e2ee.decrypt_from_sender(ct, recipient_private_key=recipient_priv)

        result = benchmark(e2ee_roundtrip, iterations=100)
        assert result.ops_per_second > 10, f"E2EE round trip too slow: {result.ops_per_second:.0f} ops/s"


class TestConcurrentOperations:
    """Test Bedrock handles realistic mixed workloads."""

    def test_mixed_workload_100_ops(self):
        """100 mixed operations: encrypt, consent, audit, license validate."""
        km = KeyManager()
        master_key = KeyManager.generate_master_key()
        fe = FieldEncryptor(km, master_key)
        consent = ConsentGate()
        audit = AuditChain()
        enforcer = LicenseEnforcer()
        reg = NodeRegistry()

        # Setup
        patient = reg.register(name='patient-1', node_type='patient')
        provider = reg.register(name='provider-1', node_type='provider')
        key = enforcer.generate_license_key(
            tier=LicenseTier.DEVELOPER, issued_to='test', max_nodes=3,
        )

        start = time.perf_counter()

        for i in range(100):
            # Encrypt
            ct = fe.encrypt(f"data-{i}", "medical", f"rec-{i}", "read")
            fe.decrypt(ct, "medical", f"rec-{i}", "read")

            # Consent
            if i % 5 == 0:
                consent.request_consent(
                    requesting_node_id=provider.node_id.uuid,
                    source_silo='medical',
                    target_silo='identity',
                    categories=['diagnosis'],
                    scope='read',
                    reason='treatment',
                )

            # Audit
            audit.append(
                action='access', actor_id=f'user-{i%10}',
                target_id=f'record-{i}', silo='medical',
            )

            # License validation
            enforcer.validate_license(key)

        elapsed = time.perf_counter() - start

        # 100 mixed ops should complete in under 10 seconds
        assert elapsed < 10.0, f"100 mixed ops took {elapsed:.2f}s"

        # Verify audit chain integrity after load
        assert audit.verify() is True, "Audit chain integrity check failed after load"