"""
Bedrock Access Control.

RBAC with role-portal mapping, scoped sessions, MFA, account lockout.

Trade Secret — InFill Systems, LLC.
"""

from bedrock.access_control.controller import (
    AccessController, Role, Portal, Permission, Session, UserAccount,
    DEFAULT_ROLE_PERMISSIONS, PORTAL_ROLE_COMPATIBILITY,
    MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_MINUTES, PROGRESSIVE_DELAY_SECONDS,
)

__all__ = [
    "AccessController", "Role", "Portal", "Permission", "Session", "UserAccount",
    "DEFAULT_ROLE_PERMISSIONS", "PORTAL_ROLE_COMPATIBILITY",
    "MAX_FAILED_ATTEMPTS", "LOCKOUT_DURATION_MINUTES", "PROGRESSIVE_DELAY_SECONDS",
]