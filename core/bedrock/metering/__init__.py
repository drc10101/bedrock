"""
Bedrock Usage Metering — API call tracking and per-tier rate enforcement.

Tracks API calls per license key, per endpoint, per time period for:
- Billing data (how many calls did each licensee make?)
- Rate limiting (enforce per-tier limits)
- Abuse detection (spike detection beyond normal usage)

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class LicenseTier(Enum):
    """License tier for rate limiting and metering."""
    DEVELOPER = "developer"
    STARTER = "starter"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


@dataclass
class TierLimits:
    """Rate limits per license tier.

    Each tier has different allowances for requests per minute,
    burst size, and total monthly API calls.
    """
    requests_per_minute: int = 60
    requests_per_hour: int = 3600
    burst_size: int = 10
    monthly_limit: int = 100_000
    violation_threshold: int = 5
    block_duration_minutes: int = 15


# Pre-configured limits per tier
TIER_LIMITS: Dict[str, TierLimits] = {
    "developer": TierLimits(
        requests_per_minute=60,
        requests_per_hour=3600,
        burst_size=10,
        monthly_limit=100_000,
        violation_threshold=5,
        block_duration_minutes=15,
    ),
    "starter": TierLimits(
        requests_per_minute=200,
        requests_per_hour=12_000,
        burst_size=30,
        monthly_limit=500_000,
        violation_threshold=5,
        block_duration_minutes=10,
    ),
    "business": TierLimits(
        requests_per_minute=600,
        requests_per_hour=36_000,
        burst_size=100,
        monthly_limit=5_000_000,
        violation_threshold=10,
        block_duration_minutes=5,
    ),
    "enterprise": TierLimits(
        requests_per_minute=2000,
        requests_per_hour=120_000,
        burst_size=500,
        monthly_limit=0,  # Unlimited
        violation_threshold=20,
        block_duration_minutes=1,
    ),
}


@dataclass
class UsageRecord:
    """A single API usage record."""
    license_key: str
    endpoint: str
    method: str
    timestamp: float
    status_code: int
    response_time_ms: float = 0.0
    bytes_sent: int = 0


@dataclass
class UsageSummary:
    """Aggregated usage summary for a license key."""
    license_key: str
    tier: str
    period_start: float
    period_end: float
    total_requests: int = 0
    requests_by_endpoint: Dict[str, int] = field(default_factory=dict)
    requests_by_method: Dict[str, int] = field(default_factory=dict)
    requests_by_status: Dict[int, int] = field(default_factory=dict)
    total_bytes_sent: int = 0
    avg_response_time_ms: float = 0.0
    rate_limit_throttled: int = 0
    rate_limit_blocked: int = 0


class UsageMeter:
    """Tracks API usage per license key for billing and rate limiting.

    Maintains:
    - Rolling windows for rate limit enforcement
    - Cumulative counters for monthly billing
    - Per-endpoint breakdowns for usage reports
    """

    def __init__(self, tier_limits: Optional[Dict[str, TierLimits]] = None):
        self.tier_limits = tier_limits or TIER_LIMITS

        # Rate limit windows (key -> [timestamps])
        self._minute_windows: Dict[str, List[float]] = defaultdict(list)
        self._hour_windows: Dict[str, List[float]] = defaultdict(list)

        # Violation tracking
        self._violation_counts: Dict[str, int] = {}
        self._blocked_until: Dict[str, float] = {}

        # Usage records for metering
        self._usage_records: List[UsageRecord] = []
        self._monthly_counts: Dict[str, int] = defaultdict(int)  # key -> count
        self._monthly_reset: Dict[str, float] = {}  # key -> last_reset_timestamp

        # Per-endpoint counters
        self._endpoint_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        # Per-key throttled/blocked counters
        self._throttled_counts: Dict[str, int] = defaultdict(int)
        self._blocked_counts: Dict[str, int] = defaultdict(int)

    def check_rate_limit(self, key: str, tier: str = "developer") -> Tuple[bool, Optional[str]]:
        """Check if a request from key is within rate limits.

        Args:
            key: License key or API key to check
            tier: License tier for per-tier limits

        Returns:
            (allowed, reason) — allowed=True if request is permitted,
            reason is set if blocked/throttled
        """
        now = time.time()
        limits = self.tier_limits.get(tier, self.tier_limits["developer"])

        # Check if currently blocked
        blocked_until = self._blocked_until.get(key, 0)
        if now < blocked_until:
            self._blocked_counts[key] += 1
            return False, f"Blocked until {blocked_until:.0f}"

        # Clean and count minute window
        self._clean_window(key, now)
        minute_count = len(self._minute_windows.get(key, []))
        hour_count = len(self._hour_windows.get(key, []))

        # Check limits
        if minute_count >= limits.requests_per_minute:
            return self._handle_violation(key, now, limits)

        if hour_count >= limits.requests_per_hour:
            return self._handle_violation(key, now, limits)

        # Check burst (over burst threshold but under hard rate limit)
        if minute_count >= limits.burst_size and minute_count < limits.requests_per_minute:
            # Record the request (it's allowed, just throttled)
            self._minute_windows[key].append(now)
            self._hour_windows[key].append(now)
            self._monthly_counts[key] = self._monthly_counts.get(key, 0) + 1
            self._throttled_counts[key] += 1
            return True, "throttled"  # Allowed but warned

        # Check monthly limit (0 = unlimited)
        if limits.monthly_limit > 0:
            monthly_count = self._monthly_counts.get(key, 0)
            if monthly_count >= limits.monthly_limit:
                self._blocked_counts[key] += 1
                return False, "Monthly limit exceeded"

        # Request is allowed — record it
        self._minute_windows[key].append(now)
        self._hour_windows[key].append(now)
        self._monthly_counts[key] += 1

        return True, None

    def record_usage(self, license_key: str, endpoint: str, method: str,
                     status_code: int, response_time_ms: float = 0.0,
                     bytes_sent: int = 0, tier: str = "developer") -> None:
        """Record an API usage event for billing and analytics.

        Args:
            license_key: The license key making the request
            endpoint: API endpoint (e.g., "/api/v1/nodes")
            method: HTTP method (GET, POST, etc.)
            status_code: HTTP response status code
            response_time_ms: Response time in milliseconds
            bytes_sent: Bytes sent in response
            tier: License tier
        """
        record = UsageRecord(
            license_key=license_key,
            endpoint=endpoint,
            method=method,
            timestamp=time.time(),
            status_code=status_code,
            response_time_ms=response_time_ms,
            bytes_sent=bytes_sent,
        )
        self._usage_records.append(record)
        self._endpoint_counts[license_key][endpoint] += 1

    def get_usage_summary(self, license_key: str, tier: str = "developer",
                          hours: float = 1.0) -> UsageSummary:
        """Get usage summary for a license key over the last N hours.

        Args:
            license_key: License key to summarize
            tier: License tier
            hours: Hours of history to include

        Returns:
            UsageSummary with aggregated usage data
        """
        now = time.time()
        cutoff = now - (hours * 3600)

        relevant = [r for r in self._usage_records
                     if r.license_key == license_key and r.timestamp >= cutoff]

        by_endpoint: Dict[str, int] = defaultdict(int)
        by_method: Dict[str, int] = defaultdict(int)
        by_status: Dict[int, int] = defaultdict(int)
        total_bytes = 0
        total_response_time = 0.0

        for record in relevant:
            by_endpoint[record.endpoint] += 1
            by_method[record.method] += 1
            by_status[record.status_code] += 1
            total_bytes += record.bytes_sent
            total_response_time += record.response_time_ms

        return UsageSummary(
            license_key=license_key,
            tier=tier,
            period_start=cutoff,
            period_end=now,
            total_requests=len(relevant),
            requests_by_endpoint=dict(by_endpoint),
            requests_by_method=dict(by_method),
            requests_by_status=dict(by_status),
            total_bytes_sent=total_bytes,
            avg_response_time_ms=total_response_time / len(relevant) if relevant else 0.0,
            rate_limit_throttled=self._throttled_counts.get(license_key, 0),
            rate_limit_blocked=self._blocked_counts.get(license_key, 0),
        )

    def get_monthly_usage(self, license_key: str) -> int:
        """Get monthly API call count for a license key."""
        return self._monthly_counts.get(license_key, 0)

    def reset_monthly(self, license_key: str) -> None:
        """Reset monthly counters for a license key (billing cycle)."""
        self._monthly_counts[license_key] = 0
        self._monthly_reset[license_key] = time.time()

    def get_rate_limit_status(self, key: str) -> dict:
        """Get rate limit status for a key (for X-RateLimit-* headers)."""
        now = time.time()
        self._clean_window(key, now)
        minute_count = len(self._minute_windows.get(key, []))
        hour_count = len(self._hour_windows.get(key, []))

        blocked_until = self._blocked_until.get(key, 0)
        is_blocked = now < blocked_until

        return {
            "minute_remaining": max(0, 60 - minute_count),
            "hour_remaining": max(0, 3600 - hour_count),
            "monthly_used": self._monthly_counts.get(key, 0),
            "throttled_count": self._throttled_counts.get(key, 0),
            "blocked": is_blocked,
            "blocked_until": blocked_until if is_blocked else None,
        }

    def _handle_violation(self, key: str, now: float, limits: TierLimits) -> Tuple[bool, Optional[str]]:
        """Handle a rate limit violation."""
        self._violation_counts[key] = self._violation_counts.get(key, 0) + 1

        if self._violation_counts[key] >= limits.violation_threshold:
            self._blocked_until[key] = now + (limits.block_duration_minutes * 60)
            self._violation_counts[key] = 0
            self._blocked_counts[key] += 1
            return False, "Rate limit exceeded — key blocked"

        self._throttled_counts[key] += 1
        return False, "Rate limit exceeded — retry later"

    def _clean_window(self, key: str, now: float) -> None:
        """Remove expired timestamps from sliding windows."""
        minute_cutoff = now - 60
        hour_cutoff = now - 3600

        if key in self._minute_windows:
            self._minute_windows[key] = [
                ts for ts in self._minute_windows[key] if ts > minute_cutoff
            ]
        if key in self._hour_windows:
            self._hour_windows[key] = [
                ts for ts in self._hour_windows[key] if ts > hour_cutoff
            ]