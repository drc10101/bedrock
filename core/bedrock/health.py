"""
Bedrock Core — Health Check Module.

Provides a simple health/status endpoint for container orchestration
and load balancers. Reports component readiness without exposing
sensitive configuration.
"""

import time
from dataclasses import dataclass

from bedrock.config import CoreConfig


@dataclass
class HealthStatus:
    """Health check result for a single component."""

    name: str
    healthy: bool
    message: str = ""
    latency_ms: float = 0.0


@dataclass
class HealthReport:
    """Aggregate health report for all Bedrock components."""

    status: str  # "healthy" | "degraded" | "unhealthy"
    environment: str
    tier: str
    timestamp: float
    uptime_seconds: float
    components: dict[str, HealthStatus]

    def is_healthy(self) -> bool:
        """True if all components are healthy."""
        return all(c.healthy for c in self.components.values())

    def to_dict(self) -> dict:
        """Serialize to dict for API response."""
        return {
            "status": self.status,
            "environment": self.environment,
            "tier": self.tier,
            "timestamp": self.timestamp,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "components": {
                name: {
                    "healthy": c.healthy,
                    "message": c.message,
                    "latency_ms": round(c.latency_ms, 2),
                }
                for name, c in self.components.items()
            },
        }


class HealthChecker:
    """Runs health checks on all Bedrock Core components."""

    def __init__(self, config: CoreConfig | None = None):
        self._config = config or CoreConfig.from_env()
        self._start_time = time.time()

    def _check_encryption(self) -> HealthStatus:
        """Verify encryption module can derive keys and encrypt/decrypt."""
        try:
            from bedrock.encryption.engine import FieldEncryptor
            from bedrock.key_management.keys import KeyManager

            start = time.perf_counter()
            km = KeyManager()
            master_key = KeyManager.generate_master_key()
            fe = FieldEncryptor(km, master_key)

            ct = fe.encrypt("health-check", "system", "health", "read")
            pt = fe.decrypt(ct, "system", "health", "read")
            latency = (time.perf_counter() - start) * 1000

            if pt == "health-check":
                return HealthStatus(
                    name="encryption",
                    healthy=True,
                    message="Encrypt/decrypt round-trip OK",
                    latency_ms=latency,
                )
            else:
                return HealthStatus(
                    name="encryption",
                    healthy=False,
                    message="Round-trip mismatch",
                    latency_ms=latency,
                )
        except Exception as e:
            return HealthStatus(name="encryption", healthy=False, message=str(e))

    def _check_identity(self) -> HealthStatus:
        """Verify node registration works."""
        try:
            from bedrock.identity.registration import NodeRegistry

            start = time.perf_counter()
            reg = NodeRegistry()
            node = reg.register(name="health-check", node_type="system")
            latency = (time.perf_counter() - start) * 1000

            return HealthStatus(
                name="identity",
                healthy=True,
                message=f"Node registered: {node.node_id.uuid[:8]}",
                latency_ms=latency,
            )
        except Exception as e:
            return HealthStatus(name="identity", healthy=False, message=str(e))

    def _check_audit(self) -> HealthStatus:
        """Verify audit chain append and verify."""
        try:
            from bedrock.audit.chain import AuditChain

            start = time.perf_counter()
            audit = AuditChain()
            audit.append("health-check", "system", "self", "system")
            verified = audit.verify()
            latency = (time.perf_counter() - start) * 1000

            return HealthStatus(
                name="audit",
                healthy=verified,
                message="Chain integrity verified" if verified else "Chain integrity FAILED",
                latency_ms=latency,
            )
        except Exception as e:
            return HealthStatus(name="audit", healthy=False, message=str(e))

    def _check_licensing(self) -> HealthStatus:
        """Verify license validation works."""
        try:
            from bedrock.licensing.enforcement import LicenseEnforcer, LicenseTier

            start = time.perf_counter()
            enforcer = LicenseEnforcer()
            key = enforcer.generate_license_key(
                tier=LicenseTier.DEVELOPER,
                issued_to="health-check",
            )
            license_obj = enforcer.validate_license(key)
            latency = (time.perf_counter() - start) * 1000

            return HealthStatus(
                name="licensing",
                healthy=license_obj.is_valid,
                message=f"Tier: {license_obj.tier.value}",
                latency_ms=latency,
            )
        except Exception as e:
            return HealthStatus(name="licensing", healthy=False, message=str(e))

    def check(self) -> HealthReport:
        """Run all health checks and return aggregate report."""
        components = {
            "encryption": self._check_encryption(),
            "identity": self._check_identity(),
            "audit": self._check_audit(),
            "licensing": self._check_licensing(),
        }

        all_healthy = all(c.healthy for c in components.values())
        status = "healthy" if all_healthy else "degraded"

        return HealthReport(
            status=status,
            environment=self._config.environment,
            tier=self._config.licensing.tier,
            timestamp=time.time(),
            uptime_seconds=time.time() - self._start_time,
            components=components,
        )
