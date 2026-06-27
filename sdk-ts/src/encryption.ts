/**
 * Encryption SDK module — Field-level encrypt/decrypt, E2EE delivery, key management.
 *
 * Uses Web Crypto API for browser and Node.js compatibility.
 * Trade Secret — InFill Systems, LLC. All rights reserved.
 */

import type { KeyPair } from './types';

/**
 * Encryption operations: field-level encrypt/decrypt, E2EE, key management.
 */
export class EncryptionModule {
  private _masterKey: CryptoKey | null = null;
  private _keyVersion: number = 1;

  /**
   * Initialize with a master key.
   */
  async init(): Promise<void> {
    this._masterKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
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
      { name: 'AES-GCM', iv, additionalData: aad },
      this._masterKey!,
      encoded,
    );

    // Format: v2:base64(iv_len[2B] || iv || aad_len[2B] || aad || ciphertext)
    const ivLen = new Uint8Array(2);
    ivLen[0] = iv.length;
    const aadLen = new Uint8Array(2);
    aadLen[0] = aad.length;

    const combined = new Uint8Array([
      ...ivLen, ...iv, ...aadLen, ...aad,
      ...new Uint8Array(encrypted),
    ]);
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

    const ivLen = combined[offset];
    offset += 2;
    const iv = combined.slice(offset, offset + ivLen);
    offset += ivLen;
    const aadLen = combined[offset];
    offset += 2;
    const storedAad = combined.slice(offset, offset + aadLen);
    offset += aadLen;
    const ct = combined.slice(offset);

    // Verify AAD matches
    const expectedAad = this._buildAad(silo, recordId, scope, operation);
    if (!this._arrayEqual(storedAad, expectedAad)) {
      throw new Error(
        `AAD mismatch: decrypted with wrong context (silo=${silo}, record=${recordId})`,
      );
    }

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: expectedAad },
      this._masterKey!,
      ct,
    );

    return new TextDecoder().decode(decrypted);
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
    const rawKey = await crypto.subtle.exportKey('raw', this._masterKey);
    return this._base64Encode(new Uint8Array(rawKey));
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

  private _arrayEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}