"""
Health check tests for Bedrock Core deployment readiness.
"""

from bedrock.health import HealthChecker, HealthReport


class TestHealthCheck:
    """Test health check module."""

    def test_health_check_all_components_healthy(self):
        """All core components should be healthy in a working system."""
        checker = HealthChecker()
        report = checker.check()

        assert report.status in ("healthy", "degraded")
        assert report.environment in ("development", "test", "staging", "production")
        assert report.uptime_seconds >= 0
        assert len(report.components) == 4  # encryption, identity, audit, licensing

        # In a working system, all should be healthy
        for name, status in report.components.items():
            assert status.healthy, f"{name} unhealthy: {status.message}"

    def test_health_report_serialization(self):
        """Health report should serialize cleanly to dict."""
        checker = HealthChecker()
        report = checker.check()
        d = report.to_dict()

        assert "status" in d
        assert "environment" in d
        assert "tier" in d
        assert "timestamp" in d
        assert "uptime_seconds" in d
        assert "components" in d
        assert "encryption" in d["components"]
        assert "identity" in d["components"]
        assert "audit" in d["components"]
        assert "licensing" in d["components"]

    def test_health_report_latency(self):
        """Each component health check should report latency."""
        checker = HealthChecker()
        report = checker.check()

        for name, status in report.components.items():
            assert status.latency_ms >= 0, f"{name} has negative latency"

    def test_is_healthy_method(self):
        """is_healthy() should reflect component status."""
        checker = HealthChecker()
        report = checker.check()

        # If all components are healthy, is_healthy() should be True
        all_healthy = all(c.healthy for c in report.components.values())
        assert report.is_healthy() == all_healthy

    def test_uptime_increases(self):
        """Uptime should increase between checks."""
        checker = HealthChecker()
        report1 = checker.check()
        report2 = checker.check()

        # Uptime should be non-decreasing
        assert report2.uptime_seconds >= report1.uptime_seconds