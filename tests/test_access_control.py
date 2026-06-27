"""Tests for Access Control (B-109)."""

import hashlib
import time
import pytest
from datetime import datetime, timezone, timedelta

from bedrock.access_control.controller import (
    AccessController, Role, Portal, Permission, Session, UserAccount,
    DEFAULT_ROLE_PERMISSIONS, PORTAL_ROLE_COMPATIBILITY,
    MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_MINUTES, PROGRESSIVE_DELAY_SECONDS,
)


class TestRole:
    """Test role definitions."""

    def test_role_values(self):
        assert Role.ADMIN.value == "admin"
        assert Role.OPERATOR.value == "operator"
        assert Role.VIEWER.value == "viewer"
        assert Role.DENIED.value == "denied"

    def test_admin_has_all_permissions(self):
        admin_perms = DEFAULT_ROLE_PERMISSIONS[Role.ADMIN]
        assert Permission.ADMIN_CONFIG in admin_perms
        assert Permission.ADMIN_USER_MANAGE in admin_perms
        assert Permission.DATA_DELETE in admin_perms

    def test_operator_has_no_admin_config(self):
        op_perms = DEFAULT_ROLE_PERMISSIONS[Role.OPERATOR]
        assert Permission.ADMIN_CONFIG not in op_perms
        assert Permission.DATA_READ in op_perms

    def test_viewer_readonly(self):
        viewer_perms = DEFAULT_ROLE_PERMISSIONS[Role.VIEWER]
        assert Permission.DATA_READ in viewer_perms
        assert Permission.DATA_WRITE not in viewer_perms
        assert Permission.DATA_DELETE not in viewer_perms

    def test_denied_has_no_permissions(self):
        assert len(DEFAULT_ROLE_PERMISSIONS[Role.DENIED]) == 0


class TestPortal:
    """Test portal-role compatibility."""

    def test_admin_can_access_all_portals(self):
        assert Role.ADMIN in PORTAL_ROLE_COMPATIBILITY[Portal.PATIENT]
        assert Role.ADMIN in PORTAL_ROLE_COMPATIBILITY[Portal.PROVIDER]
        assert Role.ADMIN in PORTAL_ROLE_COMPATIBILITY[Portal.ADMIN]

    def test_admin_only_on_admin_portal(self):
        """Only ADMIN role can access the admin portal."""
        admin_roles = PORTAL_ROLE_COMPATIBILITY[Portal.ADMIN]
        assert len(admin_roles) == 1
        assert Role.ADMIN in admin_roles

    def test_viewer_cannot_access_admin_portal(self):
        assert Role.VIEWER not in PORTAL_ROLE_COMPATIBILITY[Portal.ADMIN]

    def test_partner_portal_roles(self):
        partner_roles = PORTAL_ROLE_COMPATIBILITY[Portal.PARTNER]
        assert Role.VIEWER in partner_roles
        assert Role.OPERATOR in partner_roles
        assert Role.ADMIN not in partner_roles


class TestPermission:
    """Test permission enum."""

    def test_permission_format(self):
        """All permissions follow category.operation format."""
        for perm in Permission:
            assert "." in perm.value, f"Permission {perm.value} doesn't follow category.operation format"

    def test_data_permissions(self):
        assert Permission.DATA_READ.value == "data.read"
        assert Permission.DATA_WRITE.value == "data.write"
        assert Permission.DATA_DELETE.value == "data.delete"
        assert Permission.DATA_EXPORT.value == "data.export"


class TestSession:
    """Test session creation and validation."""

    def test_session_creation(self):
        session = Session(
            session_id="abc123",
            user_id="user-001",
            role=Role.VIEWER,
            portal=Portal.PATIENT,
        )
        assert session.session_id == "abc123"
        assert session.role == Role.VIEWER
        assert session.portal == Portal.PATIENT
        assert session.mfa_verified is False

    def test_session_not_expired_by_default(self):
        session = Session(
            session_id="abc", user_id="u1", role=Role.VIEWER, portal=Portal.PATIENT,
        )
        assert session.is_expired() is False

    def test_session_expired(self):
        session = Session(
            session_id="abc", user_id="u1", role=Role.VIEWER, portal=Portal.PATIENT,
            expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        assert session.is_expired() is True

    def test_session_has_capability(self):
        session = Session(
            session_id="abc", user_id="u1", role=Role.VIEWER, portal=Portal.PATIENT,
            capabilities=["data.read", "audit.read"],
        )
        assert session.has_capability("data.read") is True
        assert session.has_capability("data.write") is False

    def test_session_has_permission(self):
        session = Session(
            session_id="abc", user_id="u1", role=Role.VIEWER, portal=Portal.PATIENT,
        )
        assert session.has_permission(Permission.DATA_READ) is True
        assert session.has_permission(Permission.DATA_WRITE) is False

    def test_session_valid(self):
        session = Session(
            session_id="abc", user_id="u1", role=Role.VIEWER, portal=Portal.PATIENT,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        )
        assert session.is_valid() is True

    def test_session_invalid_when_denied(self):
        session = Session(
            session_id="abc", user_id="u1", role=Role.DENIED, portal=Portal.PATIENT,
        )
        assert session.is_valid() is False

    def test_session_invalid_when_expired(self):
        session = Session(
            session_id="abc", user_id="u1", role=Role.VIEWER, portal=Portal.PATIENT,
            expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        assert session.is_valid() is False

    def test_session_to_dict(self):
        session = Session(
            session_id="abc", user_id="u1", role=Role.VIEWER, portal=Portal.PATIENT,
        )
        d = session.to_dict()
        assert d["session_id"] == "abc"
        assert d["role"] == "viewer"
        assert d["portal"] == "patient"


class TestAccessController:
    """Test AccessController authentication and authorization."""

    def setup_method(self):
        self.ac = AccessController()

    def test_create_user(self):
        account = self.ac.create_user("alice", "password123", Role.VIEWER)
        assert account.username == "alice"
        assert account.role == Role.VIEWER
        assert account.failed_attempts == 0

    def test_create_user_duplicate_fails(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        with pytest.raises(ValueError, match="already exists"):
            self.ac.create_user("alice", "other_password", Role.OPERATOR)

    def test_authenticate_success(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        session = self.ac.authenticate("alice", "password123", Portal.PATIENT)
        assert session is not None
        assert session.user_id is not None
        assert session.role == Role.VIEWER
        assert session.portal == Portal.PATIENT
        assert session.mfa_verified is False

    def test_authenticate_wrong_password(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        session = self.ac.authenticate("alice", "wrong_password", Portal.PATIENT)
        assert session is None

    def test_authenticate_nonexistent_user(self):
        session = self.ac.authenticate("nobody", "password123", Portal.PATIENT)
        assert session is None

    def test_authenticate_incompatible_portal(self):
        """VIEWER cannot access admin portal."""
        self.ac.create_user("alice", "password123", Role.VIEWER)
        session = self.ac.authenticate("alice", "password123", Portal.ADMIN)
        assert session is None

    def test_authenticate_admin_all_portals(self):
        """ADMIN can access all portals."""
        self.ac.create_user("admin", "admin_pass", Role.ADMIN)
        for portal in [Portal.PATIENT, Portal.PROVIDER, Portal.ADMIN]:
            session = self.ac.authenticate("admin", "admin_pass", portal)
            assert session is not None
            assert session.role == Role.ADMIN

    def test_session_capabilities_match_role(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        session = self.ac.authenticate("alice", "password123", Portal.PATIENT)
        assert Permission.DATA_READ.value in session.capabilities
        assert Permission.DATA_WRITE.value not in session.capabilities

    def test_session_expiry(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        session = self.ac.authenticate("alice", "password123", Portal.PATIENT)
        assert session.expires_at is not None
        # Sessions should expire in the future
        assert session.expires_at > datetime.now(timezone.utc)


class TestAccountLockout:
    """Test account lockout after failed auth attempts."""

    def setup_method(self):
        self.ac = AccessController()

    def test_failed_attempts_increment(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        self.ac.authenticate("alice", "wrong", Portal.PATIENT)
        account = self.ac.get_user("alice")
        assert account.failed_attempts == 1

    def test_successful_auth_resets_attempts(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        self.ac.authenticate("alice", "wrong", Portal.PATIENT)
        account = self.ac.get_user("alice")
        assert account.failed_attempts == 1

        self.ac.authenticate("alice", "password123", Portal.PATIENT)
        account = self.ac.get_user("alice")
        assert account.failed_attempts == 0

    def test_lockout_after_max_failures(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        for _ in range(MAX_FAILED_ATTEMPTS):
            self.ac.authenticate("alice", "wrong", Portal.PATIENT)

        account = self.ac.get_user("alice")
        assert account.is_locked() is True
        assert account.locked_until is not None

    def test_locked_account_raises_error(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        for _ in range(MAX_FAILED_ATTEMPTS):
            self.ac.authenticate("alice", "wrong", Portal.PATIENT)

        with pytest.raises(PermissionError, match="locked"):
            self.ac.authenticate("alice", "password123", Portal.PATIENT)

    def test_manual_lock_account(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        self.ac.lock_account("alice")
        account = self.ac.get_user("alice")
        assert account.is_locked() is True

    def test_manual_unlock_account(self):
        self.ac.create_user("alice", "password123", Role.VIEWER)
        self.ac.lock_account("alice")
        self.ac.unlock_account("alice")
        account = self.ac.get_user("alice")
        assert account.is_locked() is False
        assert account.failed_attempts == 0

    def test_lock_nonexistent_user_raises(self):
        with pytest.raises(KeyError):
            self.ac.lock_account("nobody")

    def test_unlock_nonexistent_user_raises(self):
        with pytest.raises(KeyError):
            self.ac.unlock_account("nobody")


class TestPermissionCheck:
    """Test permission checking with MFA requirements."""

    def setup_method(self):
        self.ac = AccessController()
        self.ac.create_user("viewer", "pass", Role.VIEWER)
        self.ac.create_user("operator", "pass", Role.OPERATOR)
        self.ac.create_user("admin", "pass", Role.ADMIN)

    def test_viewer_can_read(self):
        session = self.ac.authenticate("viewer", "pass", Portal.PATIENT)
        assert self.ac.check_permission(session, Permission.DATA_READ) is True

    def test_viewer_cannot_write(self):
        session = self.ac.authenticate("viewer", "pass", Portal.PATIENT)
        assert self.ac.check_permission(session, Permission.DATA_WRITE) is False

    def test_operator_can_write_with_mfa(self):
        session = self.ac.authenticate("operator", "pass", Portal.PROVIDER)
        # Without MFA, write operations are denied
        assert self.ac.check_permission(session, Permission.DATA_WRITE) is False

        # With MFA, write operations are allowed
        session.mfa_verified = True
        assert self.ac.check_permission(session, Permission.DATA_WRITE) is True

    def test_admin_full_access_with_mfa(self):
        session = self.ac.authenticate("admin", "pass", Portal.ADMIN)
        # Admin can read without MFA
        assert self.ac.check_permission(session, Permission.DATA_READ) is True
        # Admin needs MFA for write operations
        assert self.ac.check_permission(session, Permission.ADMIN_CONFIG) is False

        session.mfa_verified = True
        assert self.ac.check_permission(session, Permission.ADMIN_CONFIG) is True

    def test_expired_session_no_permission(self):
        session = Session(
            session_id="expired",
            user_id="u1",
            role=Role.ADMIN,
            portal=Portal.ADMIN,
            expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        assert self.ac.check_permission(session, Permission.DATA_READ) is False

    def test_denied_role_no_permission(self):
        session = Session(
            session_id="denied",
            user_id="u1",
            role=Role.DENIED,
            portal=Portal.PATIENT,
        )
        assert self.ac.check_permission(session, Permission.DATA_READ) is False


class TestMFA:
    """Test TOTP-based MFA verification."""

    def setup_method(self):
        self.ac = AccessController()

    def test_mfa_not_verified_by_default(self):
        self.ac.create_user("alice", "pass", Role.VIEWER)
        session = self.ac.authenticate("alice", "pass", Portal.PATIENT)
        assert session.mfa_verified is False

    def test_invalid_mfa_code(self):
        self.ac.create_user("alice", "pass", Role.VIEWER)
        session = self.ac.authenticate("alice", "pass", Portal.PATIENT)
        result = self.ac.verify_mfa(session.session_id, "000000")
        assert result is False
        assert session.mfa_verified is False

    def test_mfa_invalid_session(self):
        result = self.ac.verify_mfa("nonexistent_session", "000000")
        assert result is False

    def test_totp_generation_and_verification(self):
        """Generate a valid TOTP code and verify it."""
        import hmac as hmac_mod
        import struct
        import hashlib

        account = self.ac.create_user("alice", "pass", Role.VIEWER)
        session = self.ac.authenticate("alice", "pass", Portal.PATIENT)

        # Generate a valid TOTP code from the secret
        key = bytes.fromhex(account.totp_secret)
        current_step = int(time.time()) // 30
        time_bytes = struct.pack(">Q", current_step)
        h = hmac_mod.new(key, time_bytes, hashlib.sha1).digest()
        offset_val = h[-1] & 0x0F
        code_int = (
            ((h[offset_val] & 0x7F) << 24)
            | ((h[offset_val + 1] & 0xFF) << 16)
            | ((h[offset_val + 2] & 0xFF) << 8)
            | (h[offset_val + 3] & 0xFF)
        ) % 1000000
        valid_code = f"{code_int:06d}"

        # Verify the code
        result = self.ac.verify_mfa(session.session_id, valid_code)
        assert result is True
        assert session.mfa_verified is True


class TestSessionLifecycle:
    """Test session creation, retrieval, and termination."""

    def setup_method(self):
        self.ac = AccessController()

    def test_get_session(self):
        self.ac.create_user("alice", "pass", Role.VIEWER)
        session = self.ac.authenticate("alice", "pass", Portal.PATIENT)
        retrieved = self.ac.get_session(session.session_id)
        assert retrieved is not None
        assert retrieved.session_id == session.session_id

    def test_end_session(self):
        self.ac.create_user("alice", "pass", Role.VIEWER)
        session = self.ac.authenticate("alice", "pass", Portal.PATIENT)
        result = self.ac.end_session(session.session_id)
        assert result is True
        assert self.ac.get_session(session.session_id) is None

    def test_end_nonexistent_session(self):
        result = self.ac.end_session("nonexistent")
        assert result is False

    def test_get_nonexistent_session(self):
        assert self.ac.get_session("nonexistent") is None