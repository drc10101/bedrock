/**
 * Bedrock SDK — Identity-based security framework for TypeScript/JavaScript.
 *
 * Every node is a user. Everything between is encrypted at rest.
 *
 * Trade Secret — InFill Systems, LLC. All rights reserved.
 */

export { BedrockClient } from './client';
export { IdentityModule } from './identity';
export { EncryptionModule } from './encryption';
export { DataModule } from './data';
export { AuditModule } from './audit';
export { AccessModule } from './access';
export { TransportModule } from './transport';

export type {
  NodeID, Node, CapabilityScope, Certificate, EncryptionResult,
  KeyPair, ConsentEvent, AuditEntry, Session, BedrockConfig,
  TLSConfig, HealingResult,
} from './types';

export {
  NodeState, DataCategory, CertificateStatus, LicenseTier,
  AttestationPolicy, ConsentStatus, Role, Portal, Permission,
  TLSVersion, DowngradeStatus, RateLimitResult, SignalType,
  DEFAULT_DEV_CONFIG, DEFAULT_PROD_CONFIG,
} from './types';