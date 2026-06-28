/**
 * Audit SDK module — Write events, verify integrity, export for compliance.
 *
 * Uses SHA-256 hash chain for tamper-evident logging.
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

import type { AuditEntry } from './types';

/**
 * Tamper-evident audit chain.
 */
export class AuditModule {
  private _chain: AuditEntry[] = [];

  /**
   * Log an event to the audit chain.
   */
  async log(
    action: string,
    actorId: string,
    targetId: string,
    silo: string,
    details?: Record<string, unknown>,
  ): Promise<string> {
    const index = this._chain.length;
    const timestamp = new Date().toISOString();
    const prevHash = index > 0 ? this._chain[index - 1]!.entryHash : '0'.repeat(64);

    const entryHash = await this._computeHash(
      `${index}:${timestamp}:${action}:${actorId}:${targetId}:${silo}:${prevHash}`,
    );

    const entry: AuditEntry = {
      index,
      timestamp,
      action,
      actorId,
      targetId,
      silo,
      details: details ?? null,
      entryHash,
      prevHash,
    };

    this._chain.push(entry);
    return entryHash;
  }

  /**
   * Verify the entire audit chain integrity.
   */
  async verify(): Promise<boolean> {
    for (let i = 0; i < this._chain.length; i++) {
      const entry = this._chain[i]!;
      const expectedPrevHash = i === 0 ? '0'.repeat(64) : this._chain[i - 1]!.entryHash;
      if (entry.prevHash !== expectedPrevHash) {
        return false;
      }
      const computedHash = await this._computeHash(
        `${entry.index}:${entry.timestamp}:${entry.action}:${entry.actorId}:${entry.targetId}:${entry.silo}:${entry.prevHash}`,
      );
      if (entry.entryHash !== computedHash) {
        return false;
      }
    }
    return true;
  }

  /**
   * Query audit entries.
   */
  query(filters?: {
    action?: string;
    actorId?: string;
    silo?: string;
    limit?: number;
  }): AuditEntry[] {
    let results = [...this._chain];

    if (filters?.action) {
      results = results.filter((e) => e.action === filters.action);
    }
    if (filters?.actorId) {
      results = results.filter((e) => e.actorId === filters.actorId);
    }
    if (filters?.silo) {
      results = results.filter((e) => e.silo === filters.silo);
    }
    if (filters?.limit) {
      results = results.slice(0, filters.limit);
    }

    return results;
  }

  /**
   * Export the audit chain as JSONL.
   */
  export(): string {
    return this._chain.map((e) => JSON.stringify(e)).join('\n');
  }

  /**
   * Get the current head hash.
   */
  get headHash(): string | null {
    if (this._chain.length === 0) return null;
    return this._chain[this._chain.length - 1]!.entryHash;
  }

  /**
   * Get the genesis hash.
   */
  get tailHash(): string | null {
    if (this._chain.length === 0) return null;
    return this._chain[0]!.entryHash;
  }

  // --- Private ---

  private async _computeHash(data: string): Promise<string> {
    const encoded = new TextEncoder().encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
}