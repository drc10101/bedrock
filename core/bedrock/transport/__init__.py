"""
Bedrock Transport Security.

TLS termination config, E2EE delivery, AAD-bound encryption, downgrade detection.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
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