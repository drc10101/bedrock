"""
Bedrock Transport Security.

TLS termination config, E2EE delivery, AAD-bound encryption, downgrade detection.

Trade Secret — InFill Systems, LLC.
"""

from bedrock.transport.security import (
    TLSVersion, DowngradeStatus, RateLimitResult,
    TLSConfig, RateLimitConfig, ConnectionInfo,
    RateLimiter, TransportLayer,
)

__all__ = [
    "TLSVersion", "DowngradeStatus", "RateLimitResult",
    "TLSConfig", "RateLimitConfig", "ConnectionInfo",
    "RateLimiter", "TransportLayer",
]