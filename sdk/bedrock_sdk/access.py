"""
Access SDK module — RBAC, sessions, MFA.

Wraps bedrock.access_control with developer-friendly defaults.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

from typing import Optional

from bedrock.access_control.controller import (
    AccessController, Role, Portal, Permission, Session,
)


class AccessModule:
    """SDK module for access control.

    Provides a simplified API for:
    - Role-based access control (RBAC)
    - Session management with MFA
    - Permission checking
    """

    def __init__(self, controller: AccessController):
        self._controller = controller

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "viewer",
    ) -> str:
        """Create a user account.

        Args:
            username: Unique username.
            password: Password (will be hashed internally).
            role: Role name ("admin", "operator", "viewer", "denied").

        Returns:
            The user_id of the newly created account.
        """
        role_enum = Role(role)
        account = self._controller.create_user(
            username=username,
            password=password,
            role=role_enum,
        )
        return account.user_id

    def authenticate(
        self,
        username: str,
        password: str,
        portal: str = "system",
    ) -> Optional[Session]:
        """Authenticate a user and create a session.

        Args:
            username: The username.
            password: The password.
            portal: Portal name ("admin", "provider", "patient", "system").

        Returns:
            An authenticated Session, or None if auth failed.
        """
        portal_enum = Portal(portal)
        return self._controller.authenticate(
            username=username,
            password=password,
            portal=portal_enum,
        )

    def check_permission(self, session: Session, permission: str) -> bool:
        """Check if a session has a specific permission.

        Write operations (cert.issue, data.write, consent.approve, etc.)
        require MFA verification in the session.

        Args:
            session: The authenticated session.
            permission: Permission to check (e.g., "data.read", "cert.issue").

        Returns:
            True if the session has the permission.
        """
        perm_enum = Permission(permission)
        return self._controller.check_permission(session, perm_enum)

    def verify_mfa(self, session_id: str, totp_code: str) -> bool:
        """Verify a TOTP MFA code for a session.

        After successful verification, the session's mfa_verified flag
        is set to True, enabling write operations.

        Args:
            session_id: The session ID to verify MFA for.
            totp_code: The 6-digit TOTP code.

        Returns:
            True if the code was valid and MFA is now verified.
        """
        return self._controller.verify_mfa(session_id, totp_code)

    def end_session(self, session_id: str) -> bool:
        """End an authenticated session (logout).

        Args:
            session_id: The session ID to end.

        Returns:
            True if the session was found and ended.
        """
        return self._controller.end_session(session_id)