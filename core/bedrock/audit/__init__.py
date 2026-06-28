"""
Bedrock Audit Chain.

SHA-256 hash chain logging. Tamper-evident, 6-year retention.
Every action is appended to an immutable chain.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from bedrock.audit.chain import AuditChain, AuditEntry, AuditAction, GENESIS_HASH

__all__ = ["AuditChain", "AuditEntry", "AuditAction", "GENESIS_HASH"]