/**
 * Access SDK module — RBAC, sessions, MFA.
 *
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

import type { Session } from './types';
import { Role, Portal, Permission } from './types';

interface UserAccount {
  userId: string;
  username: string;
  role: Role;
  passwordHash: string;
  totpSecret: string;
}

// Role-permission mapping
const ROLE_PERMISSIONS: Record<string, Permission[]> = {
  [Role.ADMIN]: [
    Permission.DATA_READ, Permission.DATA_WRITE,
    Permission.CONSENT_REQUEST, Permission.CONSENT_APPROVE,
    Permission.CERT_ISSUE, Permission.CERT_REVOKE,
    Permission.NODE_REGISTER, Permission.NODE_QUARANTINE,
    Permission.AUDIT_READ,
  ],
  [Role.OPERATOR]: [
    Permission.DATA_READ, Permission.DATA_WRITE,
    Permission.CONSENT_REQUEST, Permission.CONSENT_APPROVE,
    Permission.NODE_REGISTER, Permission.AUDIT_READ,
  ],
  [Role.VIEWER]: [
    Permission.DATA_READ, Permission.AUDIT_READ,
  ],
  [Role.DENIED]: [],
};

// Permissions requiring MFA verification
const MFA_REQUIRED_PERMISSIONS: Set<string> = new Set([
  Permission.CERT_ISSUE,
  Permission.CERT_REVOKE,
  Permission.DATA_WRITE,
  Permission.CONSENT_APPROVE,
  Permission.NODE_QUARANTINE,
]);

/**
 * Access control: RBAC, sessions, MFA.
 */
export class AccessModule {
  private _users: Map<string, UserAccount> = new Map();
  private _sessions: Map<string, Session> = new Map();
  private _sessionCounter: number = 0;

  /**
   * Create a user account.
   */
  createUser(username: string, password: string, role: string = 'viewer'): string {
    const userId = `user-${crypto.randomUUID().slice(0, 8)}`;
    const roleEnum = role as Role;

    // In production, password would be hashed with bcrypt/argon2
    // This is a simplified SDK wrapper
    const account: UserAccount = {
      userId,
      username,
      role: roleEnum,
      passwordHash: this._hashPassword(password),
      totpSecret: crypto.randomUUID().slice(0, 16),
    };

    this._users.set(username, account);
    return userId;
  }

  /**
   * Authenticate a user and create a session.
   */
  authenticate(username: string, password: string, portal: string = 'system'): Session | null {
    const account = this._users.get(username);
    if (!account) return null;
    if (account.passwordHash !== this._hashPassword(password)) return null;

    const sessionId = `sess-${++this._sessionCounter}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 3600 * 1000); // 1 hour

    const session: Session = {
      sessionId,
      userId: account.userId,
      role: account.role,
      portal: portal as Portal,
      mfaVerified: false,
      createdAt: now,
      expiresAt,
    };

    this._sessions.set(sessionId, session);
    return session;
  }

  /**
   * Check if a session has a specific permission.
   */
  checkPermission(session: Session, permission: string): boolean {
    const perms = ROLE_PERMISSIONS[session.role] ?? [];
    if (!perms.includes(permission as Permission)) {
      return false;
    }
    // MFA required for write operations
    if (MFA_REQUIRED_PERMISSIONS.has(permission) && !session.mfaVerified) {
      return false;
    }
    return true;
  }

  /**
   * Verify a TOTP MFA code for a session.
   */
  verifyMfa(sessionId: string, _totpCode: string): boolean {
    const session = this._sessions.get(sessionId);
    if (!session) return false;

    // In production, verify TOTP code against user's secret
    // For SDK wrapper, mark session as verified
    session.mfaVerified = true;
    return true;
  }

  /**
   * End an authenticated session.
   */
  endSession(sessionId: string): boolean {
    return this._sessions.delete(sessionId);
  }

  // --- Private ---

  private _hashPassword(password: string): string {
    // Simplified — production would use bcrypt/argon2
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
      const chr = password.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0;
    }
    return hash.toString(36);
  }
}