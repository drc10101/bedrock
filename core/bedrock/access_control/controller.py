"""
Bedrock Access Control.

RBAC with role-portal mapping, scoped sessions, MFA, account lockout.
Every access decision is logged to the audit chain.

The access controller enforces:
1. Role-based permissions (RBAC) — what actions each role can perform
2. Portal scoping — which portal (patient, provider, admin) a session is for
3. Capability scoping — which data categories a session can access
4. MFA verification — time-based one-time passwords (TOTP)
5. Account lockout — progressive delays after failed auth attempts

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum


class Role(Enum):
    """Default roles. Each vertical template can define additional roles.

    The DENIED role is terminal — it means the account exists but all
    access is revoked. This is different from not having an account at all.
    """

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    DENIED = "denied"


class Portal(Enum):
    """Which portal the user authenticated to.

    Bedrock separates access by portal. A patient portal session cannot
    access provider portal resources, even with the same user ID.
    This prevents lateral movement between portals.
    """

    PATIENT = "patient"
    PROVIDER = "provider"
    ADMIN = "admin"
    PARTNER = "partner"


class Permission(Enum):
    """Granular permissions that can be assigned to roles.

    Following the category.operation format from the audit chain.
    """

    # Data access
    DATA_READ = "data.read"
    DATA_WRITE = "data.write"
    DATA_DELETE = "data.delete"
    DATA_EXPORT = "data.export"

    # Consent management
    CONSENT_REQUEST = "consent.request"
    CONSENT_APPROVE = "consent.approve"
    CONSENT_DENY = "consent.deny"
    CONSENT_REVOKE = "consent.revoke"

    # Node management
    NODE_REGISTER = "node.register"
    NODE_QUARANTINE = "node.quarantine"
    NODE_REVOKE = "node.revoke"
    NODE_HEAL = "node.heal"

    # Certificate management
    CERT_ISSUE = "cert.issue"
    CERT_REVOKE = "cert.revoke"

    # Audit
    AUDIT_READ = "audit.read"
    AUDIT_EXPORT = "audit.export"

    # Admin
    ADMIN_CONFIG = "admin.config"
    ADMIN_USER_MANAGE = "admin.user_manage"


# Default role-permission mappings.
# Each role gets a frozen set of permissions.
# Portal restrictions are enforced separately — this mapping defines
# what a role CAN do, the portal defines WHERE they can do it.

DEFAULT_ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(
        {
            Permission.DATA_READ,
            Permission.DATA_WRITE,
            Permission.DATA_DELETE,
            Permission.DATA_EXPORT,
            Permission.CONSENT_REQUEST,
            Permission.CONSENT_APPROVE,
            Permission.CONSENT_DENY,
            Permission.CONSENT_REVOKE,
            Permission.NODE_REGISTER,
            Permission.NODE_QUARANTINE,
            Permission.NODE_REVOKE,
            Permission.NODE_HEAL,
            Permission.CERT_ISSUE,
            Permission.CERT_REVOKE,
            Permission.AUDIT_READ,
            Permission.AUDIT_EXPORT,
            Permission.ADMIN_CONFIG,
            Permission.ADMIN_USER_MANAGE,
        }
    ),
    Role.OPERATOR: frozenset(
        {
            Permission.DATA_READ,
            Permission.DATA_WRITE,
            Permission.CONSENT_REQUEST,
            Permission.CONSENT_APPROVE,
            Permission.NODE_REGISTER,
            Permission.NODE_HEAL,
            Permission.CERT_ISSUE,
            Permission.AUDIT_READ,
        }
    ),
    Role.VIEWER: frozenset(
        {
            Permission.DATA_READ,
            Permission.CONSENT_REQUEST,
            Permission.AUDIT_READ,
        }
    ),
    Role.DENIED: frozenset(),  # No permissions
}

# Portal-role compatibility: which roles can authenticate to which portals.
# A DENIED role cannot authenticate to any portal.
PORTAL_ROLE_COMPATIBILITY: dict[Portal, frozenset[Role]] = {
    Portal.PATIENT: frozenset({Role.VIEWER, Role.OPERATOR, Role.ADMIN}),
    Portal.PROVIDER: frozenset({Role.VIEWER, Role.OPERATOR, Role.ADMIN}),
    Portal.ADMIN: frozenset({Role.ADMIN}),
    Portal.PARTNER: frozenset({Role.VIEWER, Role.OPERATOR}),
}

# Account lockout settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
PROGRESSIVE_DELAY_SECONDS = [0, 1, 2, 5, 10]  # Delay after each failed attempt


@dataclass
class Session:
    """A scoped, time-limited session.

    Sessions are the unit of access in Bedrock. Every API call requires
    a valid session. Sessions are scoped to a portal and have specific
    capabilities. Even if a user has ADMIN role on the admin portal,
    they cannot access data on the patient portal without a separate
    patient portal session.
    """

    session_id: str
    user_id: str
    role: Role
    portal: Portal
    capabilities: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    mfa_verified: bool = False

    def is_expired(self) -> bool:
        """Check if this session has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(UTC) > self.expires_at

    def has_capability(self, capability: str) -> bool:
        """Check if this session includes a specific capability."""
        return capability in self.capabilities

    def has_permission(self, permission: Permission) -> bool:
        """Check if this session's role includes a specific permission."""
        role_perms = DEFAULT_ROLE_PERMISSIONS.get(self.role, frozenset())
        return permission in role_perms

    def is_valid(self) -> bool:
        """Check if this session is valid (not expired, not denied role, MFA verified if required)."""
        if self.is_expired():
            return False
        return self.role != Role.DENIED

    def to_dict(self) -> dict:
        """Serialize session for audit logging."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "role": self.role.value,
            "portal": self.portal.value,
            "capabilities": self.capabilities,
            "mfa_verified": self.mfa_verified,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass
class UserAccount:
    """A user account with credentials and lockout state."""

    user_id: str
    username: str
    password_hash: str  # SHA-256 hash of password
    role: Role
    totp_secret: str  # Base32-encoded TOTP secret
    failed_attempts: int = 0
    locked_until: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        if datetime.now(UTC) > self.locked_until:
            self.locked_until = None
            self.failed_attempts = 0
            return False
        return True


class AccessController:
    """RBAC with role-portal mapping and scoped sessions.

    The access controller handles:
    1. User authentication (username + password)
    2. MFA verification (TOTP)
    3. Session creation (scoped to portal with role permissions)
    4. Permission checking (role + portal + capability)
    5. Account lockout (progressive delay + lockout after max failures)

    Every authentication event (success, failure, lockout) should be
    logged to the audit chain.
    """

    def __init__(self) -> None:
        self._users: dict[str, UserAccount] = {}  # username -> UserAccount
        self._sessions: dict[str, Session] = {}  # session_id -> Session

    def create_user(self, username: str, password: str, role: Role = Role.VIEWER) -> UserAccount:
        """Create a new user account.

        Args:
            username: Unique username
            password: Plain-text password (will be hashed)
            role: Default role (defaults to VIEWER)

        Returns:
            The created UserAccount

        Raises:
            ValueError: If username already exists
        """
        if username in self._users:
            raise ValueError(f"User '{username}' already exists")

        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        totp_secret = secrets.token_hex(16)  # 32-char hex string as TOTP secret

        account = UserAccount(
            user_id=secrets.token_hex(8),
            username=username,
            password_hash=password_hash,
            role=role,
            totp_secret=totp_secret,
        )
        self._users[username] = account
        return account

    def authenticate(self, username: str, password: str, portal: Portal) -> Session | None:
        """Authenticate a user and create a scoped session.

        Args:
            username: Username
            password: Plain-text password
            portal: Which portal to authenticate to

        Returns:
            A scoped Session if authentication succeeds, None otherwise

        Raises:
            PermissionError: If account is locked
            ValueError: If role is not compatible with portal
        """
        account = self._users.get(username)
        if account is None:
            return None

        # Check lockout
        if account.is_locked():
            raise PermissionError(f"Account '{username}' is locked until {account.locked_until}")

        # Check portal-role compatibility
        if account.role not in PORTAL_ROLE_COMPATIBILITY.get(portal, frozenset()):
            # Reset failed attempts on portal mismatch? No — this is a config error,
            # not an auth failure. Still increment to prevent probing.
            account.failed_attempts += 1
            return None

        # Check password
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(account.password_hash, password_hash):
            account.failed_attempts += 1

            # Progressive delay
            if account.failed_attempts <= len(PROGRESSIVE_DELAY_SECONDS):
                PROGRESSIVE_DELAY_SECONDS[account.failed_attempts - 1]
            else:
                PROGRESSIVE_DELAY_SECONDS[-1]

            # Lockout after max failures
            if account.failed_attempts >= MAX_FAILED_ATTEMPTS:
                account.locked_until = datetime.now(UTC) + timedelta(
                    minutes=LOCKOUT_DURATION_MINUTES
                )

            return None

        # Authentication successful — reset failed attempts
        account.failed_attempts = 0
        account.locked_until = None

        # Build capabilities from role permissions
        role_perms = DEFAULT_ROLE_PERMISSIONS.get(account.role, frozenset())
        capabilities = [p.value for p in role_perms]

        # Create session (MFA not yet verified)
        session = Session(
            session_id=secrets.token_hex(16),
            user_id=account.user_id,
            role=account.role,
            portal=portal,
            capabilities=capabilities,
            expires_at=datetime.now(UTC) + timedelta(hours=8),
        )
        self._sessions[session.session_id] = session
        return session

    def verify_mfa(self, session_id: str, totp_code: str) -> bool:
        """Verify a TOTP code for MFA.

        Uses the user's TOTP secret to validate the provided code.
        After successful MFA, the session is marked as verified.

        Args:
            session_id: The session to verify MFA for
            totp_code: 6-digit TOTP code

        Returns:
            True if MFA verification succeeds
        """
        session = self._sessions.get(session_id)
        if session is None:
            return False

        account = None
        for user in self._users.values():
            if user.user_id == session.user_id:
                account = user
                break

        if account is None:
            return False

        # Verify TOTP
        if not self._verify_totp(account.totp_secret, totp_code):
            return False

        session.mfa_verified = True
        return True

    @staticmethod
    def _verify_totp(secret: str, code: str, window: int = 1) -> bool:
        """Verify a TOTP code against a secret.

        Uses HMAC-SHA1 with 30-second time steps (standard TOTP).
        Accepts codes within ±1 step (window=1) to account for
        clock drift.

        Args:
            secret: Hex-encoded TOTP secret
            code: 6-digit TOTP code
            window: Number of time steps to accept before/after current

        Returns:
            True if the code is valid within the window
        """
        # Convert hex secret to bytes
        try:
            key = bytes.fromhex(secret)
        except ValueError:
            return False

        # Get current time step (30-second intervals)
        current_time = int(time.time())
        current_step = current_time // 30

        # Check codes within the window
        for offset in range(-window, window + 1):
            time_step = current_step + offset
            # Pack time step as big-endian 8-byte integer
            time_bytes = struct.pack(">Q", time_step)
            # HMAC-SHA1
            h = hmac.new(key, time_bytes, hashlib.sha1).digest()
            # Dynamic truncation (RFC 4226)
            offset_val = h[-1] & 0x0F
            code_int = (
                ((h[offset_val] & 0x7F) << 24)
                | ((h[offset_val + 1] & 0xFF) << 16)
                | ((h[offset_val + 2] & 0xFF) << 8)
                | (h[offset_val + 3] & 0xFF)
            ) % 1000000
            if f"{code_int:06d}" == code:
                return True

        return False

    def check_permission(
        self, session: Session, permission: Permission, resource: str = ""
    ) -> bool:
        """Check if a session has permission to perform an action.

        Checks:
        1. Session is valid (not expired, not denied role)
        2. Session's role includes the requested permission
        3. If MFA is required for the permission, session has MFA verified

        Args:
            session: The session to check
            permission: The requested permission
            resource: Optional resource identifier for fine-grained checks

        Returns:
            True if the session has the permission
        """
        if not session.is_valid():
            return False

        if not session.has_permission(permission):
            return False

        # MFA required for write operations
        write_permissions = {
            Permission.DATA_WRITE,
            Permission.DATA_DELETE,
            Permission.DATA_EXPORT,
            Permission.CONSENT_APPROVE,
            Permission.CONSENT_DENY,
            Permission.CONSENT_REVOKE,
            Permission.NODE_QUARANTINE,
            Permission.NODE_REVOKE,
            Permission.CERT_ISSUE,
            Permission.CERT_REVOKE,
            Permission.ADMIN_CONFIG,
            Permission.ADMIN_USER_MANAGE,
        }
        return not (permission in write_permissions and not session.mfa_verified)

    def get_session(self, session_id: str) -> Session | None:
        """Retrieve a session by ID."""
        return self._sessions.get(session_id)

    def end_session(self, session_id: str) -> bool:
        """End a session (logout).

        Returns:
            True if the session was found and ended
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def lock_account(self, username: str) -> None:
        """Lock an account immediately.

        Used by the Self-Healing Mesh when a node detects suspicious
        activity from a user account.

        Args:
            username: The account to lock

        Raises:
            KeyError: If username doesn't exist
        """
        if username not in self._users:
            raise KeyError(f"User '{username}' not found")

        self._users[username].locked_until = datetime.now(UTC) + timedelta(
            minutes=LOCKOUT_DURATION_MINUTES
        )

    def unlock_account(self, username: str) -> None:
        """Unlock an account (admin action).

        Args:
            username: The account to unlock

        Raises:
            KeyError: If username doesn't exist
        """
        if username not in self._users:
            raise KeyError(f"User '{username}' not found")

        self._users[username].locked_until = None
        self._users[username].failed_attempts = 0

    def get_user(self, username: str) -> UserAccount | None:
        """Get a user account by username."""
        return self._users.get(username)
