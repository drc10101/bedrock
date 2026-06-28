/**
 * Bedrock TypeScript SDK — Module exports.
 *
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

export { BedrockClient } from './client';
export { IdentityModule } from './identity';
export { EncryptionModule } from './encryption';
export type { KeyVersion, SiloKeyResult } from './encryption';
export { DataModule } from './data';
export { AuditModule } from './audit';
export { AccessModule } from './access';
export { TransportModule, TransportTLS, MeshModule } from './transport';
export { LicensingModule } from './licensing';
export type { LicenseValidationResult, LicenseDetails } from './licensing';
export { SiloModule } from './silo';
export type { SiloConfig, SiloEntry } from './silo';
export type { AttestationResult, AttestationClaim } from './identity';
export * from './types';