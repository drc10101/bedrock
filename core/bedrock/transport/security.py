"""
Bedrock Transport Security.

TLS termination config, E2EE delivery, AAD-bound encryption, downgrade detection,
rate limiting, and connection management.

The transport layer sits on top of the encryption engine. It handles:
1. TLS configuration — minimum version, cipher suites, certificate binding
2. Downgrade detection — reject connections that fall below TLS 1.2
3. Rate limiting — per-node and per-IP throttling to prevent abuse
4. Connection tracking — active connections, cleanup, max connections

The E2EE wrapping/unwrapping is delegated to the Encryption Engine's
E2EEDeliverer class. Transport security ensures the channel is safe
before data is exchanged.

Trade Secret — InFill Systems, LLC.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple


class TLSVersion(Enum):
    """Supported TLS versions."""
    TLS_1_2 = "1.2"
    TLS_1_3 = "1.3"


class DowngradeStatus(Enum):
    """Result of a downgrade detection check."""
    SECURE = "secure"           # Connection is using an acceptable TLS version
    DOWNGRADE = "downgrade"     # Downgrade attack detected
    UNKNOWN = "unknown"         # Cannot determine TLS version


class RateLimitResult(Enum):
    """Result of a rate limit check."""
    ALLOWED = "allowed"         # Request is within limits
    THROTTLED = "throttled"     # Request is rate-limited, retry after delay
    BLOCKED = "blocked"         # Request is blocked (too many violations)


@dataclass
class TLSConfig:
    """TLS termination configuration.

    Enforces minimum TLS version and cipher suite requirements.
    Developer mode allows TLS 1.2+ with self-signed certs.
    Runtime mode requires TLS 1.3+ with CA-signed certs.
    """
    min_version: TLSVersion = TLSVersion.TLS_1_3
    cert_path: str = ""
    key_path: str = ""
    ca_cert_path: str = ""
    verify_client: bool = True          # Require client certificates
    prefer_server_cipher: bool = True   # Server cipher suite preference
    session_timeout_seconds: int = 300  # 5-minute TLS session timeout
    max_sessions_per_client: int = 10   # Max concurrent TLS sessions per client

    def is_developer_mode(self) -> bool:
        """Check if this is a developer-mode TLS config."""
        return self.min_version == TLSVersion.TLS_1_2 and not self.ca_cert_path

    def is_production_mode(self) -> bool:
        """Check if this is a production TLS config (TLS 1.3 + CA cert)."""
        return self.min_version == TLSVersion.TLS_1_3 and bool(self.ca_cert_path)


@dataclass
class RateLimitConfig:
    """Rate limiting configuration per node/IP.

    Uses a sliding window algorithm. Each window tracks request counts
    and resets after the window expires.
    """
    max_requests_per_minute: int = 60       # Per node/IP
    max_requests_per_hour: int = 3600       # Per node/IP
    burst_size: int = 10                     # Max burst requests
    violation_threshold: int = 5             # Violations before blocking
    block_duration_minutes: int = 15         # How long to block after threshold


@dataclass
class ConnectionInfo:
    """Tracks a single connection's state."""
    connection_id: str
    node_id: str
    ip_address: str
    tls_version: TLSVersion
    established_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    bytes_sent: int = 0
    bytes_received: int = 0
    is_e2ee: bool = False  # Whether E2EE is active on this connection


class RateLimiter:
    """Sliding window rate limiter for per-node and per-IP throttling.

    Tracks request counts in sliding windows (1-minute and 1-hour).
    Violations accumulate — too many violations trigger a temporary block.
    This prevents credential stuffing, DDoS, and abuse.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._minute_windows: Dict[str, List[float]] = {}  # key -> [timestamps]
        self._hour_windows: Dict[str, List[float]] = {}
        self._violation_counts: Dict[str, int] = {}
        self._blocked_until: Dict[str, float] = {}  # key -> unblock_timestamp

    def check(self, key: str) -> RateLimitResult:
        """Check if a request from key (node_id or IP) is allowed.

        Args:
            key: Node ID or IP address to check

        Returns:
            ALLOWED: Request is within limits
            THROTTLED: Over limit but not yet blocked
            BLOCKED: Key is blocked due to repeated violations
        """
        now = time.time()

        # Check if currently blocked
        blocked_until = self._blocked_until.get(key, 0)
        if now < blocked_until:
            return RateLimitResult.BLOCKED

        # Clean and count minute window
        self._clean_window(self._minute_windows, key, now, 60)
        minute_count = len(self._minute_windows.get(key, []))

        # Clean and count hour window
        self._clean_window(self._hour_windows, key, now, 3600)
        hour_count = len(self._hour_windows.get(key, []))

        # Check burst
        if minute_count >= self.config.burst_size and minute_count <= self.config.max_requests_per_minute:
            # Over burst but under rate limit — throttle
            self._record_request(key, now)
            return RateLimitResult.THROTTLED

        # Check minute limit
        if minute_count >= self.config.max_requests_per_minute:
            return self._handle_violation(key, now)

        # Check hour limit
        if hour_count >= self.config.max_requests_per_hour:
            return self._handle_violation(key, now)

        # Request is allowed
        self._record_request(key, now)
        return RateLimitResult.ALLOWED

    def _record_request(self, key: str, timestamp: float) -> None:
        """Record a request in both sliding windows."""
        if key not in self._minute_windows:
            self._minute_windows[key] = []
        if key not in self._hour_windows:
            self._hour_windows[key] = []

        self._minute_windows[key].append(timestamp)
        self._hour_windows[key].append(timestamp)

    def _handle_violation(self, key: str, now: float) -> RateLimitResult:
        """Handle a rate limit violation.

        Increment violation count. If over threshold, block the key.
        """
        self._violation_counts[key] = self._violation_counts.get(key, 0) + 1

        if self._violation_counts[key] >= self.config.violation_threshold:
            self._blocked_until[key] = now + (self.config.block_duration_minutes * 60)
            self._violation_counts[key] = 0  # Reset after blocking
            return RateLimitResult.BLOCKED

        return RateLimitResult.THROTTLED

    def _clean_window(self, windows: Dict[str, List[float]], key: str,
                      now: float, window_seconds: int) -> None:
        """Remove timestamps outside the sliding window."""
        if key in windows:
            cutoff = now - window_seconds
            windows[key] = [ts for ts in windows[key] if ts > cutoff]

    def reset(self, key: str) -> None:
        """Reset rate limits for a specific key (admin action)."""
        self._minute_windows.pop(key, None)
        self._hour_windows.pop(key, None)
        self._violation_counts.pop(key, None)
        self._blocked_until.pop(key, None)

    def get_status(self, key: str) -> dict:
        """Get rate limit status for a key."""
        now = time.time()
        self._clean_window(self._minute_windows, key, now, 60)
        self._clean_window(self._hour_windows, key, now, 3600)

        return {
            "key": key,
            "minute_count": len(self._minute_windows.get(key, [])),
            "hour_count": len(self._hour_windows.get(key, [])),
            "violations": self._violation_counts.get(key, 0),
            "blocked": now < self._blocked_until.get(key, 0),
            "blocked_until": self._blocked_until.get(key, 0),
        }


class TransportLayer:
    """Manages transport-level security: TLS, E2EE, downgrade detection, rate limiting.

    The transport layer wraps the encryption engine's E2EE functionality
    and adds:
    - TLS version enforcement (1.2 minimum, 1.3 preferred)
    - Downgrade attack detection
    - Per-node rate limiting
    - Connection tracking and lifecycle management

    Every connection is tracked, every request is rate-limited, and
    every downgrade attempt is rejected and logged.
    """

    def __init__(self, tls_config: Optional[TLSConfig] = None,
                 rate_limit_config: Optional[RateLimitConfig] = None):
        self.tls_config = tls_config or TLSConfig()
        self.rate_limiter = RateLimiter(rate_limit_config or RateLimitConfig())
        self._connections: Dict[str, ConnectionInfo] = {}
        self._max_connections: int = 1000  # Per transport instance

    def configure_tls(self, cert_path: str, key_path: str,
                      ca_cert_path: str = "",
                      min_version: TLSVersion = TLSVersion.TLS_1_3,
                      verify_client: bool = True) -> TLSConfig:
        """Configure TLS termination with minimum version enforcement.

        Args:
            cert_path: Path to the server certificate
            key_path: Path to the server private key
            ca_cert_path: Path to the CA certificate (production mode)
            min_version: Minimum TLS version (1.3 for production, 1.2 for dev)
            verify_client: Whether to require client certificates

        Returns:
            The configured TLSConfig
        """
        self.tls_config = TLSConfig(
            min_version=min_version,
            cert_path=cert_path,
            key_path=key_path,
            ca_cert_path=ca_cert_path,
            verify_client=verify_client,
        )
        return self.tls_config

    def detect_downgrade(self, request_headers: dict) -> DowngradeStatus:
        """Detect TLS downgrade attacks from request headers.

        Checks for:
        1. TLS version in headers falls below configured minimum
        2. Missing TLS headers (indicates plain HTTP)
        3. X-Forwarded-Proto indicates non-HTTPS when TLS is required

        Args:
            request_headers: HTTP headers from the connection

        Returns:
            SECURE: Connection meets TLS requirements
            DOWNGRADE: Downgrade attack detected
            UNKNOWN: Cannot determine TLS version
        """
        # Check for X-Forwarded-Proto (reverse proxy header)
        forwarded_proto = request_headers.get("x-forwarded-proto", "").lower()
        if forwarded_proto and forwarded_proto != "https":
            return DowngradeStatus.DOWNGRADE

        # Check TLS version header
        tls_version_str = request_headers.get("x-tls-version", "")
        if not tls_version_str:
            # No TLS version header — could be HTTP or missing header
            # In production mode, this is suspicious
            if self.tls_config.is_production_mode():
                return DowngradeStatus.UNKNOWN
            return DowngradeStatus.UNKNOWN

        # Parse TLS version
        try:
            # Format: "1.2", "1.3", "TLSv1.2", "TLSv1.3"
            version_str = tls_version_str.lower().replace("tlsv", "").replace("tls", "")
            if version_str.startswith("v"):
                version_str = version_str[1:]

            requested = TLSVersion(version_str)
        except ValueError:
            return DowngradeStatus.UNKNOWN

        # Compare against minimum
        version_order = {TLSVersion.TLS_1_2: 2, TLSVersion.TLS_1_3: 3}
        if version_order.get(requested, 0) < version_order.get(self.tls_config.min_version, 3):
            return DowngradeStatus.DOWNGRADE

        return DowngradeStatus.SECURE

    def register_connection(self, connection_id: str, node_id: str,
                            ip_address: str,
                            tls_version: TLSVersion = TLSVersion.TLS_1_3,
                            is_e2ee: bool = False) -> ConnectionInfo:
        """Register a new connection.

        Args:
            connection_id: Unique connection identifier
            node_id: Node ID of the connecting party
            ip_address: IP address of the connecting party
            tls_version: Negotiated TLS version
            is_e2ee: Whether E2EE is active on this connection

        Returns:
            ConnectionInfo for the registered connection

        Raises:
            ValueError: If max connections exceeded
        """
        if len(self._connections) >= self._max_connections:
            raise ValueError(f"Max connections ({self._max_connections}) exceeded")

        conn = ConnectionInfo(
            connection_id=connection_id,
            node_id=node_id,
            ip_address=ip_address,
            tls_version=tls_version,
            is_e2ee=is_e2ee,
        )
        self._connections[connection_id] = conn
        return conn

    def close_connection(self, connection_id: str) -> Optional[ConnectionInfo]:
        """Close and remove a connection.

        Returns:
            The closed ConnectionInfo, or None if not found
        """
        return self._connections.pop(connection_id, None)

    def get_connection(self, connection_id: str) -> Optional[ConnectionInfo]:
        """Get connection info by ID."""
        return self._connections.get(connection_id)

    def get_active_connections(self, node_id: Optional[str] = None) -> List[ConnectionInfo]:
        """Get active connections, optionally filtered by node_id.

        Args:
            node_id: Optional filter by node ID

        Returns:
            List of active ConnectionInfo objects
        """
        connections = list(self._connections.values())
        if node_id:
            connections = [c for c in connections if c.node_id == node_id]
        return connections

    def check_rate_limit(self, key: str) -> RateLimitResult:
        """Check rate limit for a node or IP address.

        Args:
            key: Node ID or IP address

        Returns:
            ALLOWED, THROTTLED, or BLOCKED
        """
        return self.rate_limiter.check(key)

    def update_activity(self, connection_id: str,
                        bytes_sent: int = 0,
                        bytes_received: int = 0) -> Optional[ConnectionInfo]:
        """Update connection activity metrics.

        Args:
            connection_id: Connection to update
            bytes_sent: Bytes sent since last update
            bytes_received: Bytes received since last update

        Returns:
            Updated ConnectionInfo, or None if not found
        """
        conn = self._connections.get(connection_id)
        if conn is None:
            return None

        conn.last_activity = datetime.now(timezone.utc)
        conn.bytes_sent += bytes_sent
        conn.bytes_received += bytes_received
        return conn

    @property
    def connection_count(self) -> int:
        """Number of active connections."""
        return len(self._connections)

    @property
    def max_connections(self) -> int:
        """Maximum allowed connections."""
        return self._max_connections

    @max_connections.setter
    def max_connections(self, value: int) -> None:
        """Set maximum allowed connections."""
        if value < 1:
            raise ValueError("Max connections must be at least 1")
        self._max_connections = value