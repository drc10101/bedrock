/**
 * Data SDK module — Silo configuration, consent-gated access, anonymous IDs.
 *
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

import { ConsentStatus } from './types';

/** Consent record with full lifecycle tracking. */
interface ConsentRecord {
  consentId: string;
  requestingNodeId: string;
  sourceSilo: string;
  targetSilo: string;
  categories: string[];
  scope: string;
  reason: string;
  status: ConsentStatus;
  dataOwnerId: string | null;
  approverId: string | null;
  denierId: string | null;
  denialReason: string | null;
  expiresAt: Date | null;
  createdAt: Date;
  approvedAt: Date | null;
  revokedAt: Date | null;
}

/** Anonymous ID mapping with silo binding. */
interface AnonIdMapping {
  anonymousId: string;
  realId: string;
  silo: string;
  createdAt: Date;
  lastResolved: Date | null;
  resolveCount: number;
}

/**
 * Data separation and consent management.
 */
export class DataModule {
  private _consents: Map<string, ConsentRecord> = new Map();
  private _anonIds: Map<string, AnonIdMapping> = new Map();
  private _realToAnon: Map<string, Map<string, string>> = new Map();
  private _consentCounter: number = 0;

  // --- Consent ---

  /**
   * Request cross-silo data access consent.
   */
  requestConsent(
    requestingNodeId: string,
    sourceSilo: string,
    targetSilo: string,
    categories: string[],
    scope: string = 'read',
    reason: string = '',
  ): string {
    const consentId = `consent-${++this._consentCounter}`;
    const record: ConsentRecord = {
      consentId,
      requestingNodeId,
      sourceSilo,
      targetSilo,
      categories,
      scope,
      reason,
      status: ConsentStatus.PENDING,
      dataOwnerId: null,
      approverId: null,
      denierId: null,
      denialReason: null,
      expiresAt: null,
      createdAt: new Date(),
      approvedAt: null,
      revokedAt: null,
    };
    this._consents.set(consentId, record);
    return consentId;
  }

  /**
   * Approve a pending consent request.
   */
  approveConsent(consentId: string, dataOwnerId: string, ttlSeconds: number = 3600): boolean {
    const record = this._consents.get(consentId);
    if (!record || record.status !== ConsentStatus.PENDING) {
      return false;
    }
    record.status = ConsentStatus.APPROVED;
    record.dataOwnerId = dataOwnerId;
    record.approverId = dataOwnerId;
    record.expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    record.approvedAt = new Date();
    return true;
  }

  /**
   * Deny a pending consent request.
   */
  denyConsent(consentId: string, denierId: string, reason: string = ''): boolean {
    const record = this._consents.get(consentId);
    if (!record || record.status !== ConsentStatus.PENDING) {
      return false;
    }
    record.status = ConsentStatus.DENIED;
    record.denierId = denierId;
    record.denialReason = reason;
    return true;
  }

  /**
   * Check if a consent request is approved and valid.
   */
  checkConsent(consentId: string): boolean {
    const record = this._consents.get(consentId);
    if (!record) return false;
    if (record.status !== ConsentStatus.APPROVED) return false;
    if (record.expiresAt && record.expiresAt < new Date()) return false;
    return true;
  }

  /**
   * Get consent details.
   */
  getConsent(consentId: string): ConsentRecord | undefined {
    return this._consents.get(consentId);
  }

  /**
   * Revoke a previously approved consent.
   */
  revokeConsent(consentId: string): boolean {
    const record = this._consents.get(consentId);
    if (!record) return false;
    record.status = ConsentStatus.REVOKED;
    record.revokedAt = new Date();
    return true;
  }

  /**
   * List consents filtered by status.
   */
  listConsents(status?: ConsentStatus): ConsentRecord[] {
    const records = Array.from(this._consents.values());
    if (status) {
      return records.filter((r) => r.status === status);
    }
    return records;
  }

  // --- Anonymous IDs ---

  /**
   * Create an anonymous ID mapping for a real identity, bound to a silo.
   */
  createAnonymousId(realId: string, silo: string): string {
    const anonymousId = `anon-${crypto.randomUUID().slice(0, 16)}`;
    const mapping: AnonIdMapping = {
      anonymousId,
      realId,
      silo,
      createdAt: new Date(),
      lastResolved: null,
      resolveCount: 0,
    };
    this._anonIds.set(anonymousId, mapping);

    if (!this._realToAnon.has(realId)) {
      this._realToAnon.set(realId, new Map());
    }
    this._realToAnon.get(realId)!.set(silo, anonymousId);

    return anonymousId;
  }

  /**
   * Resolve an anonymous ID back to the real identity.
   */
  resolveAnonymousId(anonymousId: string): string | null {
    const mapping = this._anonIds.get(anonymousId);
    if (!mapping) return null;
    mapping.resolveCount++;
    mapping.lastResolved = new Date();
    return mapping.realId;
  }

  /**
   * Get anonymous ID for a real identity in a specific silo.
   */
  getAnonymousId(realId: string, silo: string): string | null {
    const siloMap = this._realToAnon.get(realId);
    return siloMap?.get(silo) ?? null;
  }

  /**
   * List all silo bindings for a real identity.
   */
  listSiloBindings(realId: string): Array<{ silo: string; anonymousId: string }> {
    const siloMap = this._realToAnon.get(realId);
    if (!siloMap) return [];
    const result: Array<{ silo: string; anonymousId: string }> = [];
    siloMap.forEach((anonId, silo) => {
      result.push({ silo, anonymousId: anonId });
    });
    return result;
  }

  /**
   * Remove all anonymous ID mappings for an identity (right to be forgotten).
   */
  removeIdentity(realId: string): boolean {
    const siloMap = this._realToAnon.get(realId);
    if (siloMap) {
      siloMap.forEach((anonId) => {
        this._anonIds.delete(anonId);
      });
      this._realToAnon.delete(realId);
    }
    return true;
  }

  /**
   * Get the resolve count for an anonymous ID.
   */
  getResolveCount(anonymousId: string): number {
    return this._anonIds.get(anonymousId)?.resolveCount ?? 0;
  }
}