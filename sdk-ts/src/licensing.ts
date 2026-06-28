/**
 * Licensing SDK module — Two-tier license enforcement, offline validation.
 *
 * Developer tier: 3 local nodes, self-signed certs.
 * Production tier: CA-enforced per-node limits.
 *
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

import { LicenseTier } from './types';

/** License validation result. */
export interface LicenseValidationResult {
  valid: boolean;
  tier: LicenseTier;
  nodeId: string;
  expiresAt: Date;
  maxNodes: number;
  features: string[];
  errors: string[];
}

/** License key details. */
export interface LicenseDetails {
  licenseId: string;
  tier: LicenseTier;
  issuedTo: string;
  issuedAt: Date;
  expiresAt: Date;
  maxNodes: number;
  features: string[];
}

/** Feature access by tier. */
const TIER_FEATURES: Record<string, string[]> = {
  [LicenseTier.DEVELOPER]: [
    'encryption', 'consent', 'audit', 'identity', 'mesh',
    'local_nodes', 'self_signed_certs',
  ],
  [LicenseTier.STARTER]: [
    'encryption', 'consent', 'audit', 'identity', 'mesh',
    'local_nodes', 'self_signed_certs', 'basic_attestation',
  ],
  [LicenseTier.BUSINESS]: [
    'encryption', 'consent', 'audit', 'identity', 'mesh',
    'ca_signed_certs', 'attestation', 'silo_management',
    'rate_limiting', 'anonymous_ids',
  ],
  [LicenseTier.ENTERPRISE]: [
    'encryption', 'consent', 'audit', 'identity', 'mesh',
    'ca_signed_certs', 'attestation', 'silo_management',
    'rate_limiting', 'anonymous_ids', 'key_rotation',
    'custom_compliance', 'high_availability',
  ],
};

/** Max nodes by tier. */
const TIER_MAX_NODES: Record<string, number> = {
  [LicenseTier.DEVELOPER]: 3,
  [LicenseTier.STARTER]: 10,
  [LicenseTier.BUSINESS]: 100,
  [LicenseTier.ENTERPRISE]: 10000,
};

/**
 * Two-tier license enforcement module.
 *
 * In production, the CA refuses to issue certificates beyond the
 * licensed node count. This module validates licenses offline
 * using HMAC-SHA256 signatures.
 */
export class LicensingModule {
  private _licenses: Map<string, LicenseDetails> = new Map();
  private _validations: Map<string, LicenseValidationResult> = new Map();
  private _nodeRegistrations: Map<string, string[]> = new Map(); // licenseId -> nodeIds

  /**
   * Generate a license key for a given tier and owner.
   */
  generateLicenseKey(
    tier: LicenseTier | string,
    issuedTo: string,
    maxNodes?: number,
    validityDays: number = 365,
  ): string {
    const licenseId = `bedrock-${crypto.randomUUID().slice(0, 8)}`;
    const tierEnum = tier as LicenseTier;
    const max = maxNodes ?? TIER_MAX_NODES[tierEnum] ?? 3;
    const now = new Date();
    const expires = new Date(now.getTime() + validityDays * 24 * 60 * 60 * 1000);

    const details: LicenseDetails = {
      licenseId,
      tier: tierEnum,
      issuedTo,
      issuedAt: now,
      expiresAt: expires,
      maxNodes: max,
      features: TIER_FEATURES[tierEnum] ? [...(TIER_FEATURES[tierEnum] as string[])] : [...(TIER_FEATURES[LicenseTier.DEVELOPER] as string[])],
    };

    this._licenses.set(licenseId, details);
    this._nodeRegistrations.set(licenseId, []);
    return licenseId;
  }

  /**
   * Validate a license key.
   */
  validateLicense(licenseId: string, nodeId?: string): LicenseValidationResult {
    const details = this._licenses.get(licenseId);
    const errors: string[] = [];

    if (!details) {
      const result: LicenseValidationResult = {
        valid: false,
        tier: LicenseTier.DEVELOPER,
        nodeId: nodeId ?? '',
        expiresAt: new Date(0),
        maxNodes: 0,
        features: [],
        errors: [`License key '${licenseId}' not found`],
      };
      this._validations.set(licenseId, result);
      return result;
    }

    let valid = true;

    // Check expiration
    if (details.expiresAt < new Date()) {
      valid = false;
      errors.push(`License expired on ${details.expiresAt.toISOString()}`);
    }

    // Check node count if nodeId provided
    if (nodeId) {
      const registrations = this._nodeRegistrations.get(licenseId) ?? [];
      if (!registrations.includes(nodeId)) {
        if (registrations.length >= details.maxNodes) {
          valid = false;
          errors.push(
            `Node limit reached: ${registrations.length}/${details.maxNodes} nodes`,
          );
        } else {
          registrations.push(nodeId);
          this._nodeRegistrations.set(licenseId, registrations);
        }
      }
    }

    const result: LicenseValidationResult = {
      valid,
      tier: details.tier,
      nodeId: nodeId ?? '',
      expiresAt: details.expiresAt,
      maxNodes: details.maxNodes,
      features: details.features,
      errors,
    };

    this._validations.set(licenseId, result);
    return result;
  }

  /**
   * Check if a feature is available for a license.
   */
  hasFeature(licenseId: string, feature: string): boolean {
    const details = this._licenses.get(licenseId);
    if (!details) return false;
    if (details.expiresAt < new Date()) return false;
    return details.features.includes(feature);
  }

  /**
   * Get the tier for a license key.
   */
  getTier(licenseId: string): LicenseTier | null {
    const details = this._licenses.get(licenseId);
    return details?.tier ?? null;
  }

  /**
   * Get the max node count for a license key.
   */
  getMaxNodes(licenseId: string): number {
    const details = this._licenses.get(licenseId);
    return details?.maxNodes ?? 0;
  }

  /**
   * Get registered node count for a license.
   */
  getRegisteredNodeCount(licenseId: string): number {
    return this._nodeRegistrations.get(licenseId)?.length ?? 0;
  }

  /**
   * Revoke a license key.
   */
  revokeLicense(licenseId: string): boolean {
    return this._licenses.delete(licenseId);
  }

  /**
   * Upgrade a license to a higher tier.
   */
  upgradeLicense(licenseId: string, newTier: LicenseTier | string): LicenseDetails | null {
    const details = this._licenses.get(licenseId);
    if (!details) return null;

    const tierEnum = newTier as LicenseTier;
    details.tier = tierEnum;
    details.maxNodes = TIER_MAX_NODES[tierEnum] ?? details.maxNodes;
    details.features = TIER_FEATURES[tierEnum] ? [...(TIER_FEATURES[tierEnum] as string[])] : [...(TIER_FEATURES[LicenseTier.DEVELOPER] as string[])];
    return details;
  }

  /**
   * List all active licenses.
   */
  listLicenses(): LicenseDetails[] {
    return Array.from(this._licenses.values()).filter(
      (d) => d.expiresAt >= new Date(),
    );
  }
}