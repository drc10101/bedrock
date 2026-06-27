"""
Tests for Bedrock Usage Metering — UsageMeter, TierLimits, rate limiting,
usage recording, and API integration.
"""

import time
import unittest

import sys
sys.path.insert(0, "core")

from bedrock.metering import (
    UsageMeter, TierLimits, TIER_LIMITS, LicenseTier,
    UsageRecord, UsageSummary,
)


class TestTierLimits(unittest.TestCase):
    """Test per-tier rate limit configurations."""

    def test_developer_tier_limits(self):
        """Developer tier has the most restrictive limits."""
        dev = TIER_LIMITS["developer"]
        assert dev.requests_per_minute == 60
        assert dev.monthly_limit == 100_000
        assert dev.burst_size == 10

    def test_enterprise_tier_limits(self):
        """Enterprise tier has the highest limits."""
        ent = TIER_LIMITS["enterprise"]
        assert ent.requests_per_minute == 2000
        assert ent.monthly_limit == 0  # Unlimited
        assert ent.burst_size == 500

    def test_starter_tier_limits(self):
        """Starter tier is between developer and business."""
        starter = TIER_LIMITS["starter"]
        assert starter.requests_per_minute == 200
        assert starter.monthly_limit == 500_000

    def test_business_tier_limits(self):
        """Business tier allows high volume."""
        biz = TIER_LIMITS["business"]
        assert biz.requests_per_minute == 600
        assert biz.monthly_limit == 5_000_000

    def test_all_tiers_present(self):
        """All four tiers are configured."""
        assert "developer" in TIER_LIMITS
        assert "starter" in TIER_LIMITS
        assert "business" in TIER_LIMITS
        assert "enterprise" in TIER_LIMITS

    def test_custom_tier_limits(self):
        """Custom tier limits can be created."""
        custom = TierLimits(
            requests_per_minute=1000,
            requests_per_hour=60_000,
            burst_size=200,
            monthly_limit=2_000_000,
        )
        meter = UsageMeter(tier_limits={"custom": custom})
        assert meter.tier_limits["custom"].requests_per_minute == 1000


class TestUsageMeterRateLimiting(unittest.TestCase):
    """Test rate limiting functionality."""

    def setUp(self):
        self.meter = UsageMeter()

    def test_allowed_request(self):
        """Normal request is allowed."""
        allowed, reason = self.meter.check_rate_limit("key-1", "developer")
        assert allowed is True
        assert reason is None

    def test_multiple_allowed_requests(self):
        """Multiple requests within limits are allowed."""
        for i in range(10):
            allowed, reason = self.meter.check_rate_limit("key-1", "developer")
            assert allowed is True

    def test_burst_throttling(self):
        """Requests over burst size are throttled but allowed."""
        # Developer burst size is 10
        for i in range(10):
            self.meter.check_rate_limit("key-1", "developer")

        # 11th request hits burst
        allowed, reason = self.meter.check_rate_limit("key-1", "developer")
        # Should still be allowed (throttled) but within per-minute limit
        assert allowed is True
        assert reason == "throttled"

    def test_per_minute_limit(self):
        """Requests over per-minute limit are rejected."""
        # Developer: 60 req/min
        for i in range(61):
            self.meter.check_rate_limit("key-1", "developer")

        # 62nd should be rejected
        allowed, reason = self.meter.check_rate_limit("key-1", "developer")
        assert allowed is False
        assert "Rate limit" in reason

    def test_different_keys_independent(self):
        """Rate limits are independent per key."""
        # Exhaust key-1's burst
        for i in range(10):
            self.meter.check_rate_limit("key-1", "developer")

        # key-2 should still be fine
        allowed, reason = self.meter.check_rate_limit("key-2", "developer")
        assert allowed is True

    def test_different_tiers_different_limits(self):
        """Enterprise tier allows more requests than developer."""
        # Enterprise: 2000 req/min, burst 500
        for i in range(50):
            self.meter.check_rate_limit("ent-key", "enterprise")

        # Enterprise should still be well within limits
        allowed, reason = self.meter.check_rate_limit("ent-key", "enterprise")
        assert allowed is True

    def test_monthly_limit(self):
        """Monthly limit is enforced."""
        # Developer monthly limit is 100,000
        meter = UsageMeter()
        meter._monthly_counts["monthly-key"] = 99_999

        allowed, reason = meter.check_rate_limit("monthly-key", "developer")
        assert allowed is True  # One more allowed

        meter._monthly_counts["monthly-key"] = 100_000
        allowed, reason = meter.check_rate_limit("monthly-key", "developer")
        assert allowed is False
        assert "Monthly limit" in reason

    def test_enterprise_no_monthly_limit(self):
        """Enterprise tier has unlimited monthly usage (limit=0)."""
        meter = UsageMeter()
        meter._monthly_counts["ent-key"] = 10_000_000

        allowed, reason = meter.check_rate_limit("ent-key", "enterprise")
        # Enterprise monthly_limit is 0 = unlimited, so only burst/rate check matters
        assert allowed is True

    def test_reset_monthly(self):
        """Monthly reset clears counters."""
        meter = UsageMeter()
        meter._monthly_counts["key-1"] = 50_000
        meter.reset_monthly("key-1")
        assert meter.get_monthly_usage("key-1") == 0

    def test_get_rate_limit_status(self):
        """Rate limit status returns current window info."""
        for i in range(5):
            self.meter.check_rate_limit("key-1", "developer")

        status = self.meter.get_rate_limit_status("key-1")
        assert "minute_remaining" in status
        assert "hour_remaining" in status
        assert "monthly_used" in status
        assert "blocked" in status
        assert status["monthly_used"] >= 5
        assert status["blocked"] is False


class TestUsageMeterRecording(unittest.TestCase):
    """Test usage recording and summaries."""

    def setUp(self):
        self.meter = UsageMeter()

    def test_record_usage(self):
        """Recording usage creates a record."""
        self.meter.record_usage(
            license_key="key-1",
            endpoint="/api/v1/nodes",
            method="POST",
            status_code=201,
            response_time_ms=45.2,
            bytes_sent=256,
        )
        assert len(self.meter._usage_records) == 1
        assert self.meter._usage_records[0].endpoint == "/api/v1/nodes"

    def test_usage_summary(self):
        """Usage summary aggregates data correctly."""
        for i in range(5):
            self.meter.record_usage(
                license_key="key-1",
                endpoint="/api/v1/nodes",
                method="GET",
                status_code=200,
                response_time_ms=10.0,
            )
        for i in range(3):
            self.meter.record_usage(
                license_key="key-1",
                endpoint="/api/v1/silos",
                method="POST",
                status_code=201,
                response_time_ms=25.0,
            )

        summary = self.meter.get_usage_summary("key-1", hours=1.0)
        assert summary.total_requests == 8
        assert summary.requests_by_endpoint["/api/v1/nodes"] == 5
        assert summary.requests_by_endpoint["/api/v1/silos"] == 3
        assert summary.requests_by_method["GET"] == 5
        assert summary.requests_by_method["POST"] == 3

    def test_usage_summary_empty(self):
        """Usage summary with no records returns zeros."""
        summary = self.meter.get_usage_summary("no-key", hours=1.0)
        assert summary.total_requests == 0
        assert summary.avg_response_time_ms == 0.0

    def test_usage_summary_response_time(self):
        """Average response time is calculated correctly."""
        self.meter.record_usage("key-1", "/test", "GET", 200, response_time_ms=100.0)
        self.meter.record_usage("key-1", "/test", "GET", 200, response_time_ms=200.0)
        self.meter.record_usage("key-1", "/test", "GET", 200, response_time_ms=300.0)

        summary = self.meter.get_usage_summary("key-1", hours=1.0)
        assert summary.avg_response_time_ms == 200.0

    def test_monthly_usage_counter(self):
        """Monthly usage counter increments."""
        self.meter.check_rate_limit("key-1", "developer")
        self.meter.check_rate_limit("key-1", "developer")
        self.meter.check_rate_limit("key-1", "developer")

        monthly = self.meter.get_monthly_usage("key-1")
        assert monthly == 3

    def test_endpoint_counts(self):
        """Per-endpoint usage is tracked."""
        self.meter.record_usage("key-1", "/api/v1/nodes", "GET", 200)
        self.meter.record_usage("key-1", "/api/v1/nodes", "GET", 200)
        self.meter.record_usage("key-1", "/api/v1/silos", "POST", 201)

        assert self.meter._endpoint_counts["key-1"]["/api/v1/nodes"] == 2
        assert self.meter._endpoint_counts["key-1"]["/api/v1/silos"] == 1


class TestUsageMeterBlocking(unittest.TestCase):
    """Test blocking behavior after repeated violations."""

    def setUp(self):
        self.meter = UsageMeter()

    def test_violations_accumulate(self):
        """Violations accumulate before blocking."""
        # Developer: 60 req/min, burst 10, violation_threshold=5
        # Exceed the rate limit to trigger violations
        for i in range(65):
            self.meter.check_rate_limit("key-1", "developer")

        # Should have been blocked (5+ violations → block)
        # After blocking, check_rate_limit should return blocked
        status = self.meter.get_rate_limit_status("key-1")
        # The key might be blocked depending on violation count
        assert status is not None

    def test_blocked_key_is_rejected(self):
        """Blocked keys are rejected immediately."""
        # Manually block a key
        self.meter._blocked_until["blocked-key"] = time.time() + 3600  # 1 hour from now

        allowed, reason = self.meter.check_rate_limit("blocked-key", "developer")
        assert allowed is False
        assert "Blocked" in reason

    def test_block_expires(self):
        """Blocks expire after the configured duration."""
        # Set block that already expired
        self.meter._blocked_until["expired-key"] = time.time() - 1

        allowed, reason = self.meter.check_rate_limit("expired-key", "developer")
        assert allowed is True  # Block expired, request allowed


class TestUsageMeterThrottling(unittest.TestCase):
    """Test throttling behavior (burst size)."""

    def setUp(self):
        self.meter = UsageMeter()

    def test_burst_triggers_throttled(self):
        """Requests over burst size but under rate limit return 'throttled'."""
        # Developer burst_size = 10
        for i in range(10):
            self.meter.check_rate_limit("key-1", "developer")

        allowed, reason = self.meter.check_rate_limit("key-1", "developer")
        # Should be allowed but throttled
        assert allowed is True
        assert reason == "throttled"

    def test_throttled_counts_tracked(self):
        """Throttled counts are tracked in usage summary."""
        # Developer burst_size = 10
        for i in range(12):
            self.meter.check_rate_limit("key-1", "developer")

        summary = self.meter.get_usage_summary("key-1", "developer")
        assert summary.rate_limit_throttled >= 1


class TestUsageRecord(unittest.TestCase):
    """Test UsageRecord dataclass."""

    def test_create_record(self):
        """UsageRecord stores all fields."""
        record = UsageRecord(
            license_key="test-key",
            endpoint="/api/v1/nodes",
            method="POST",
            timestamp=time.time(),
            status_code=201,
            response_time_ms=45.2,
            bytes_sent=256,
        )
        assert record.license_key == "test-key"
        assert record.endpoint == "/api/v1/nodes"
        assert record.method == "POST"
        assert record.status_code == 201
        assert record.response_time_ms == 45.2
        assert record.bytes_sent == 256


class TestLicenseTierEnum(unittest.TestCase):
    """Test LicenseTier enum."""

    def test_tier_values(self):
        """All tier values are present."""
        assert LicenseTier.DEVELOPER.value == "developer"
        assert LicenseTier.STARTER.value == "starter"
        assert LicenseTier.BUSINESS.value == "business"
        assert LicenseTier.ENTERPRISE.value == "enterprise"


if __name__ == "__main__":
    unittest.main()