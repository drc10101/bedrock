/**
 * Bedrock SDK — Core types.
 *
 * All domain types shared across SDK modules.
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/** UUID v7 node identifier. */
export interface NodeID {
  uuid: string;
  timestamp: Date;
}

/** Node in the Bedrock network. */
export interface Node {
  nodeId: NodeID;
  name: string;
  state: NodeState;
}

/** Node lifecycle states. */
export enum NodeState {
  ACTIVE = 'active',
  SUSPECT = 'suspect',
  QUARANTINED = 'quarantined',
  HEALING = 'healing',
  REVOKED = 'revoked',
}

/** Capability scope defining what data categories a node can access. */
export interface CapabilityScope {
  nodeId: string;
  categories: DataCategory[];
}

/** Data categories for silo scoping. */
export enum DataCategory {
  IDENTITY = 'identity',
  MEDICAL = 'medical',
  TRANSACTION = 'transaction',
  PORTFOLIO = 'portfolio',
  INTELLIGENCE = 'intelligence',
  AUTH = 'auth',
  AUDIT = 'audit',
}

/** Certificate for a node. */
export interface Certificate {
  serialNumber: string;
  nodeUuid: string;
  nodeName: string;
  status: CertificateStatus;
  issuedAt: Date;
  expiresAt: Date;
  publicKeyHash: string;
}

export enum CertificateStatus {
  ACTIVE = 'active',
  EXPIRED = 'expired',
  REVOKED = 'revoked',
}

export enum LicenseTier {
  DEVELOPER = 'developer',
  STARTER = 'starter',
  BUSINESS = 'business',
  ENTERPRISE = 'enterprise',
}

/** Attestation policy strictness. */
export enum AttestationPolicy {
  PERMISSIVE = 'permissive',
  STRICT = 'strict',
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/** Result of an encryption operation. */
export interface EncryptionResult {
  ciphertext: string;
  silo: string;
  recordId: string;
  scope: string;
  operation: string;
  keyVersion: number;
}

/** ECDH key pair for E2EE operations. */
export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

// ---------------------------------------------------------------------------
// Data Separation
// ---------------------------------------------------------------------------

/** Consent status. */
export enum ConsentStatus {
  PENDING = 'pending',
  APPROVED = 'approved',
  DENIED = 'denied',
  REVOKED = 'revoked',
  EXPIRED = 'expired',
}

/** Consent event returned from consent operations. */
export interface ConsentEvent {
  consentId: string;
  requestingNodeId: string;
  sourceSilo: string;
  targetSilo: string;
  categories: string[];
  scope: string;
  status: ConsentStatus;
  expiresAt: Date;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/** Audit chain entry. */
export interface AuditEntry {
  index: number;
  timestamp: string;
  action: string;
  actorId: string;
  targetId: string;
  silo: string;
  details: Record<string, unknown> | null;
  entryHash: string;
  prevHash: string;
}

// ---------------------------------------------------------------------------
// Access Control
// ---------------------------------------------------------------------------

/** RBAC roles. */
export enum Role {
  ADMIN = 'admin',
  OPERATOR = 'operator',
  VIEWER = 'viewer',
  DENIED = 'denied',
}

/** Portal scopes. */
export enum Portal {
  ADMIN = 'admin',
  PROVIDER = 'provider',
  PATIENT = 'patient',
  SYSTEM = 'system',
}

/** Permissions. */
export enum Permission {
  DATA_READ = 'data.read',
  DATA_WRITE = 'data.write',
  CONSENT_REQUEST = 'consent.request',
  CONSENT_APPROVE = 'consent.approve',
  CERT_ISSUE = 'cert.issue',
  CERT_REVOKE = 'cert.revoke',
  NODE_REGISTER = 'node.register',
  NODE_QUARANTINE = 'node.quarantine',
  AUDIT_READ = 'audit.read',
}

/** Authenticated session. */
export interface Session {
  sessionId: string;
  userId: string;
  role: Role;
  portal: Portal;
  mfaVerified: boolean;
  createdAt: Date;
  expiresAt: Date;
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** TLS configuration. */
export interface TLSConfig {
  certPath: string;
  keyPath: string;
  caCertPath: string;
  minVersion: TLSVersion;
  verifyClient: boolean;

  isDeveloperMode(): boolean;
  isProductionMode(): boolean;
}

export enum TLSVersion {
  TLS_1_2 = '1.2',
  TLS_1_3 = '1.3',
}

/** Downgrade detection result. */
export enum DowngradeStatus {
  SECURE = 'secure',
  DOWNGRADE = 'downgrade',
  UNKNOWN = 'unknown',
}

/** Rate limit result. */
export enum RateLimitResult {
  ALLOWED = 'allowed',
  THROTTLED = 'throttled',
  BLOCKED = 'blocked',
}

// ---------------------------------------------------------------------------
// Mesh
// ---------------------------------------------------------------------------

/** Attack signal types. */
export enum SignalType {
  CREDENTIAL_STUFFING = 'credential_stuffing',
  UNUSUAL_VOLUME = 'unusual_volume',
  PORT_SCAN = 'port_scan',
  BRUTE_FORCE = 'brute_force',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  ATTESTATION_FAILURE = 'attestation_failure',
  SILENT_NODE = 'silent_node',
  MAN_IN_THE_MIDDLE = 'man_in_the_middle',
}

/** Healing result. */
export interface HealingResult {
  success: boolean;
  reason: string;
  newState: NodeState;
}

// ---------------------------------------------------------------------------
// Client Configuration
// ---------------------------------------------------------------------------

/** BedrockClient configuration. */
export interface BedrockConfig {
  mode: 'developer' | 'production';
  licenseKey?: string;
  /** Base URL for the Bedrock API server. Required for remote operations. */
  apiUrl?: string;
}

/** Default configuration for developer mode. */
export const DEFAULT_DEV_CONFIG: BedrockConfig = {
  mode: 'developer',
};

/** Default configuration for production mode. */
export const DEFAULT_PROD_CONFIG: BedrockConfig = {
  mode: 'production',
};