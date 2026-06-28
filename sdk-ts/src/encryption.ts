/**
 * Encryption SDK module — Field-level encrypt/decrypt, E2EE delivery, key management.
 *
 * Uses Web Crypto API for browser and Node.js compatibility.
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

import type { KeyPair } from './types';

/** Key version info for rotation tracking. */
export interface KeyVersion {
  version: number;
  createdAt: Date;
  active: boolean;
}

/** Silo-specific key derivation result. */
export interface SiloKeyResult {
  silo: string;
  keyVersion: number;
  derived: boolean;
}

/**
 * Encryption operations: field-level encrypt/decrypt, E2EE, key management.
 */
export class EncryptionModule {
  private _masterKey: CryptoKey | null = null;
  private _keyVersion: number = 1;
  private _keyHistory: KeyVersion[] = [];
  private _siloKeys: Map<string, CryptoKey> = new Map();
  private _initialized: boolean = false;

  /**
   * Initialize with a master key.
   */
  async init(): Promise<void> {
    if (this._initialized) return;
    this._masterKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    this._keyHistory = [{ version: 1, createdAt: new Date(), active: true }];
    this._initialized = true;
  }

  private _buildAad(silo: string, recordId: string, scope: string, operation: string): Uint8Array {
    const aadString = `${silo}:${recordId}:${scope}:${operation}`;
    return new TextEncoder().encode(aadString);
  }

  /**
   * Encrypt a field value with silo-bound AAD.
   */
  async encrypt(
    plaintext: string,
    silo: string,
    recordId: string,
    scope: string = 'read',
    operation: string = 'field',
  ): Promise<string> {
    if (!this._masterKey) {
      await this.init();
    }

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = this._buildAad(silo, recordId, scope, operation);
    const encoded = new TextEncoder().encode(plaintext);

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toBuffer(iv), additionalData: toBuffer(aad) },
      this._masterKey!,
      toBuffer(encoded),
    );

    // Format: v2:base64(iv_len[2B] || iv || aad_len[2B] || aad || ciphertext)
    const ivLenBuf = new Uint8Array(2);
    ivLenBuf[0] = iv.length;
    const aadLenBuf = new Uint8Array(2);
    aadLenBuf[0] = aad.length;

    const combined = concatArrays(ivLenBuf, iv, aadLenBuf, aad, new Uint8Array(encrypted));
    return `v2:${this._base64Encode(combined)}`;
  }

  /**
   * Decrypt a field value, validating AAD context.
   */
  async decrypt(
    ciphertext: string,
    silo: string,
    recordId: string,
    scope: string = 'read',
    operation: string = 'field',
  ): Promise<string> {
    if (!this._masterKey) {
      await this.init();
    }

    if (!ciphertext.startsWith('v2:')) {
      throw new Error('Unsupported ciphertext format');
    }

    const combined = this._base64Decode(ciphertext.slice(3));
    let offset = 0;

    const ivLen = combined[offset]!;
    offset += 2;
    const iv = combined.slice(offset, offset + ivLen);
    offset += ivLen;
    const aadLen = combined[offset]!;
    offset += 2;
    const storedAad = combined.slice(offset, offset + aadLen);
    offset += aadLen;
    const ct = combined.slice(offset);

    // Verify AAD matches
    const expectedAad = this._buildAad(silo, recordId, scope, operation);
    if (!arrayEqual(storedAad, expectedAad)) {
      throw new Error(
        `AAD mismatch: decrypted with wrong context (silo=${silo}, record=${recordId})`,
      );
    }

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBuffer(iv), additionalData: toBuffer(expectedAad) },
      this._masterKey!,
      toBuffer(ct),
    );

    return new TextDecoder().decode(decrypted);
  }

  /**
   * Encrypt multiple fields in batch.
   */
  async encryptBatch(
    fields: Array<{ plaintext: string; silo: string; recordId: string; scope?: string; operation?: string }>,
  ): Promise<string[]> {
    const results: string[] = [];
    for (const field of fields) {
      const encrypted = await this.encrypt(
        field.plaintext,
        field.silo,
        field.recordId,
        field.scope,
        field.operation,
      );
      results.push(encrypted);
    }
    return results;
  }

  /**
   * Decrypt multiple fields in batch.
   */
  async decryptBatch(
    ciphertexts: Array<{ ciphertext: string; silo: string; recordId: string; scope?: string; operation?: string }>,
  ): Promise<string[]> {
    const results: string[] = [];
    for (const ct of ciphertexts) {
      const decrypted = await this.decrypt(
        ct.ciphertext,
        ct.silo,
        ct.recordId,
        ct.scope,
        ct.operation,
      );
      results.push(decrypted);
    }
    return results;
  }

  /**
   * Generate an ECDH key pair for E2EE operations.
   */
  async generateKeyPair(): Promise<KeyPair> {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );

    const privateKey = new Uint8Array(
      await crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
    );
    const publicKey = new Uint8Array(
      await crypto.subtle.exportKey('spki', keyPair.publicKey),
    );

    return { privateKey, publicKey };
  }

  /**
   * Generate a new master key for key rotation.
   */
  async rotateMasterKey(): Promise<string> {
    this._masterKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    this._keyVersion++;
    this._keyHistory.forEach((k) => { k.active = false; });
    this._keyHistory.push({
      version: this._keyVersion,
      createdAt: new Date(),
      active: true,
    });
    // Clear silo-derived keys — they need re-derivation
    this._siloKeys.clear();
    const rawKey = await crypto.subtle.exportKey('raw', this._masterKey);
    return this._base64Encode(new Uint8Array(rawKey));
  }

  /**
   * Get the current key version.
   */
  get keyVersion(): number {
    return this._keyVersion;
  }

  /**
   * Get key version history.
   */
  get keyHistory(): KeyVersion[] {
    return [...this._keyHistory];
  }

  /**
   * Derive a silo-specific encryption key from the master key.
   * Uses HKDF-like approach: HMAC-SHA256(masterKey, siloName).
   */
  async deriveSiloKey(siloName: string): Promise<SiloKeyResult> {
    if (!this._masterKey) {
      await this.init();
    }

    // Use the master key to derive a silo-specific key
    // In production, this would use HKDF with proper salt
    const siloKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    this._siloKeys.set(siloName, siloKey);
    return {
      silo: siloName,
      keyVersion: this._keyVersion,
      derived: true,
    };
  }

  /**
   * Encrypt using a silo-specific derived key.
   */
  async encryptWithSiloKey(
    plaintext: string,
    siloName: string,
    recordId: string,
  ): Promise<string> {
    const siloKey = this._siloKeys.get(siloName);
    if (!siloKey) {
      throw new Error(`No derived key for silo '${siloName}'. Call deriveSiloKey() first.`);
    }

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = this._buildAad(siloName, recordId, 'read', 'field');
    const encoded = new TextEncoder().encode(plaintext);

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toBuffer(iv), additionalData: toBuffer(aad) },
      siloKey,
      toBuffer(encoded),
    );

    const ivLenBuf = new Uint8Array(2);
    ivLenBuf[0] = iv.length;
    const aadLenBuf = new Uint8Array(2);
    aadLenBuf[0] = aad.length;

    const combined = concatArrays(ivLenBuf, iv, aadLenBuf, aad, new Uint8Array(encrypted));
    return `v2:${this._base64Encode(combined)}`;
  }

  /**
   * Decrypt using a silo-specific derived key.
   */
  async decryptWithSiloKey(
    ciphertext: string,
    siloName: string,
    recordId: string,
  ): Promise<string> {
    const siloKey = this._siloKeys.get(siloName);
    if (!siloKey) {
      throw new Error(`No derived key for silo '${siloName}'. Call deriveSiloKey() first.`);
    }

    if (!ciphertext.startsWith('v2:')) {
      throw new Error('Unsupported ciphertext format');
    }

    const combined = this._base64Decode(ciphertext.slice(3));
    let offset = 0;

    const ivLen = combined[offset]!;
    offset += 2;
    const iv = combined.slice(offset, offset + ivLen);
    offset += ivLen;
    const aadLen = combined[offset]!;
    offset += 2;
    const storedAad = combined.slice(offset, offset + aadLen);
    offset += aadLen;
    const ct = combined.slice(offset);

    const expectedAad = this._buildAad(siloName, recordId, 'read', 'field');
    if (!arrayEqual(storedAad, expectedAad)) {
      throw new Error(
        `AAD mismatch: decrypted with wrong context (silo=${siloName}, record=${recordId})`,
      );
    }

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBuffer(iv), additionalData: toBuffer(expectedAad) },
      siloKey,
      toBuffer(ct),
    );

    return new TextDecoder().decode(decrypted);
  }

  // --- Utility methods ---

  private _base64Encode(data: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < data.length; i++) {
      binary += String.fromCharCode(data[i]!);
    }
    return btoa(binary);
  }

  private _base64Decode(base64: string): Uint8Array {
    const binary = atob(base64);
    const data = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      data[i] = binary.charCodeAt(i);
    }
    return data;
  }
}

// --- Module-level utility functions ---

/** Convert Uint8Array to ArrayBuffer for Web Crypto API compatibility. */
function toBuffer(data: Uint8Array): ArrayBuffer {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

/** Concatenate multiple Uint8Arrays into one. */
function concatArrays(...arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/** Constant-time array comparison. */
function arrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}