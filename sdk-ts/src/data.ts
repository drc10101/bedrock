/**
 * Data SDK module — Silo configuration, consent-gated access, anonymous IDs.
 *
 * Trade Secret — InFill Systems, LLC. All rights reserved.
 */

import type { ConsentEvent } from './types';
import { ConsentStatus } from './types';

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
  expiresAt: Date | null;
  createdAt: Date;
}

interface AnonIdMapping {
  anonymousId: string;
  realId: string;
  silo: string;
}

/**
 * Data separation and consent management.
 */
export class DataModule {
  private _consents: Map<string, ConsentRecord> = new Map();
  private _anonIds: Map<string, AnonIdMapping> = new Map();
  private _realToAnon: Map<string, Map<string, string>> = new Map();
  private _consentCounter: number = 0;

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
      expiresAt: null,
      createdAt: new Date(),
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
    record.expiresAt = new Date(Date.now() + ttlSeconds * 1000);
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
   * Revoke a previously approved consent.
   */
  revokeConsent(consentId: string): boolean {
    const record = this._consents.get(consentId);
    if (!record) return false;
    record.status = ConsentStatus.REVOKED;
    return true;
  }

  /**
   * Create an anonymous ID mapping for a real identity.
   */
  createAnonymousId(realId: string, silo: string): string {
    const anonymousId = `anon-${crypto.randomUUID().slice(0, 16)}`;
    const mapping: AnonIdMapping = { anonymousId, realId, silo };
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
    return mapping?.realId ?? null;
  }

  /**
   * Remove all anonymous ID mappings for an identity (right to be forgotten).
   */
  removeIdentity(realId: string): boolean {
    const siloMap = this._realToAnon.get(realId);
    if (siloMap) {
      for (const anonId of siloMap.values()) {
        this._anonIds.delete(anonId);
      }
      this._realToAnon.delete(realId);
    }
    return true;
  }
}