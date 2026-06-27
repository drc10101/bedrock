"""
Bedrock Audit Chain.

SHA-256 hash chain logging. Tamper-evident, 6-year retention.
Every action is appended to an immutable chain.

Trade Secret — InFill Systems, LLC.
"""

from bedrock.audit.chain import AuditChain, AuditEntry

__all__ = ["AuditChain", "AuditEntry"]