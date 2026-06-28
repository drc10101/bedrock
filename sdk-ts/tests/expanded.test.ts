/**
 * Tests for the expanded Bedrock TypeScript SDK modules:
 * Licensing, Silos, Attestation, Consent lifecycle, Key derivation, Batch ops.
 *
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

import {
  BedrockClient,
  LicensingModule,
  SiloModule,
  IdentityModule,
  EncryptionModule,
  DataModule,
  AuditModule,
  AccessModule,
  TransportModule,
  LicenseTier,
  NodeState,
  AttestationPolicy,
  ConsentStatus,
} from '../src';

// ---------------------------------------------------------------------------
// Licensing Module
// ---------------------------------------------------------------------------

describe('LicensingModule', () => {
  let licensing: LicensingModule;

  beforeEach(() => {
    licensing = new LicensingModule();
  });

  test('generate a developer license key', () => {
    const key = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'test-dev');
    expect(key).toMatch(/^bedrock-/);
    expect(licensing.getTier(key)).toBe(LicenseTier.DEVELOPER);
    expect(licensing.getMaxNodes(key)).toBe(3);
  });

  test('generate a business license key', () => {
    const key = licensing.generateLicenseKey(LicenseTier.BUSINESS, 'test-biz');
    expect(licensing.getTier(key)).toBe(LicenseTier.BUSINESS);
    expect(licensing.getMaxNodes(key)).toBe(100);
  });

  test('generate an enterprise license key', () => {
    const key = licensing.generateLicenseKey(LicenseTier.ENTERPRISE, 'test-ent');
    expect(licensing.getTier(key)).toBe(LicenseTier.ENTERPRISE);
    expect(licensing.getMaxNodes(key)).toBe(10000);
  });

  test('validate a valid license key', () => {
    const key = licensing.generateLicenseKey(LicenseTier.BUSINESS, 'test-biz');
    const result = licensing.validateLicense(key);
    expect(result.valid).toBe(true);
    expect(result.tier).toBe(LicenseTier.BUSINESS);
    expect(result.maxNodes).toBe(100);
  });

  test('validate with node registration', () => {
    const key = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'test-dev');
    const result1 = licensing.validateLicense(key, 'node-1');
    expect(result1.valid).toBe(true);
    expect(result1.nodeId).toBe('node-1');
    expect(licensing.getRegisteredNodeCount(key)).toBe(1);

    const result2 = licensing.validateLicense(key, 'node-2');
    expect(result2.valid).toBe(true);
    expect(licensing.getRegisteredNodeCount(key)).toBe(2);
  });

  test('reject registration beyond node limit', () => {
    const key = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'test-dev');
    licensing.validateLicense(key, 'node-1');
    licensing.validateLicense(key, 'node-2');
    licensing.validateLicense(key, 'node-3');
    // 4th node should fail — developer tier allows 3 nodes
    const result = licensing.validateLicense(key, 'node-4');
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([expect.stringContaining('Node limit reached')]),
    );
  });

  test('same node can re-validate without counting again', () => {
    const key = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'test-dev');
    licensing.validateLicense(key, 'node-1');
    licensing.validateLicense(key, 'node-1');
    expect(licensing.getRegisteredNodeCount(key)).toBe(1);
  });

  test('invalidate expired license', () => {
    const key = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'test-dev', 3, -1);
    const result = licensing.validateLicense(key);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  test('check feature access', () => {
    const devKey = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'dev');
    expect(licensing.hasFeature(devKey, 'encryption')).toBe(true);
    expect(licensing.hasFeature(devKey, 'ca_signed_certs')).toBe(false);
    expect(licensing.hasFeature(devKey, 'key_rotation')).toBe(false);

    const entKey = licensing.generateLicenseKey(LicenseTier.ENTERPRISE, 'ent');
    expect(licensing.hasFeature(entKey, 'encryption')).toBe(true);
    expect(licensing.hasFeature(entKey, 'ca_signed_certs')).toBe(true);
    expect(licensing.hasFeature(entKey, 'key_rotation')).toBe(true);
  });

  test('upgrade a license tier', () => {
    const key = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'dev');
    expect(licensing.getTier(key)).toBe(LicenseTier.DEVELOPER);
    expect(licensing.getMaxNodes(key)).toBe(3);

    const upgraded = licensing.upgradeLicense(key, LicenseTier.BUSINESS);
    expect(upgraded).not.toBeNull();
    expect(upgraded!.tier).toBe(LicenseTier.BUSINESS);
    expect(licensing.getTier(key)).toBe(LicenseTier.BUSINESS);
    expect(licensing.getMaxNodes(key)).toBe(100);
  });

  test('revoke a license key', () => {
    const key = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'dev');
    expect(licensing.revokeLicense(key)).toBe(true);
    expect(licensing.validateLicense(key).valid).toBe(false);
  });

  test('list active licenses', () => {
    licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'dev1');
    licensing.generateLicenseKey(LicenseTier.BUSINESS, 'biz1');
    const active = licensing.listLicenses();
    expect(active.length).toBe(2);
  });

  test('validate unknown license key', () => {
    const result = licensing.validateLicense('unknown-key');
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([expect.stringContaining('not found')]),
    );
  });
});

// ---------------------------------------------------------------------------
// Silo Module
// ---------------------------------------------------------------------------

describe('SiloModule', () => {
  let silo: SiloModule;

  beforeEach(() => {
    silo = new SiloModule();
  });

  test('create a silo', () => {
    const config = silo.createSilo('identity', 'Identity Data', ['identity', 'auth']);
    expect(config.name).toBe('identity');
    expect(config.displayName).toBe('Identity Data');
    expect(config.categories).toEqual(['identity', 'auth']);
    expect(config.encrypted).toBe(true);
  });

  test('reject duplicate silo name', () => {
    silo.createSilo('identity', 'Identity Data', ['identity']);
    expect(() => silo.createSilo('identity', 'Duplicate', ['identity'])).toThrow(
      /already exists/,
    );
  });

  test('check silo existence', () => {
    expect(silo.siloExists('identity')).toBe(false);
    silo.createSilo('identity', 'Identity Data', ['identity']);
    expect(silo.siloExists('identity')).toBe(true);
  });

  test('get silo config', () => {
    silo.createSilo('medical', 'Medical Records', ['medical']);
    const config = silo.getSilo('medical');
    expect(config).not.toBeUndefined();
    expect(config!.displayName).toBe('Medical Records');
  });

  test('list silos', () => {
    silo.createSilo('identity', 'Identity', ['identity']);
    silo.createSilo('medical', 'Medical', ['medical']);
    silo.createSilo('auth', 'Auth', ['auth']);
    expect(silo.listSilos()).toEqual(['identity', 'medical', 'auth']);
  });

  test('store and retrieve entries', () => {
    silo.createSilo('identity', 'Identity', ['identity']);
    silo.store('identity', 'identity', 'encrypted-blob-1', 'patient-001');
    silo.store('identity', 'identity', 'encrypted-blob-2', 'patient-001');
    silo.store('identity', 'identity', 'encrypted-blob-3', 'patient-002');

    const entries = silo.retrieve('identity', 'patient-001');
    expect(entries.length).toBe(2);
    expect(entries[0].recordId).toBe('patient-001');
  });

  test('query entries by category', () => {
    silo.createSilo('medical', 'Medical', ['medical', 'auth']);
    silo.store('medical', 'medical', 'data-1', 'rec-001');
    silo.store('medical', 'auth', 'data-2', 'rec-001');
    silo.store('medical', 'medical', 'data-3', 'rec-002');

    const medical = silo.query('medical', 'medical');
    expect(medical.length).toBe(2);
  });

  test('query with limit', () => {
    silo.createSilo('identity', 'Identity', ['identity']);
    for (let i = 0; i < 10; i++) {
      silo.store('identity', 'identity', `data-${i}`, `rec-${i}`);
    }
    const limited = silo.query('identity', undefined, 3);
    expect(limited.length).toBe(3);
  });

  test('delete record (right to be forgotten)', () => {
    silo.createSilo('identity', 'Identity', ['identity']);
    silo.store('identity', 'identity', 'data-1', 'patient-001');
    silo.store('identity', 'identity', 'data-2', 'patient-001');

    const deleted = silo.deleteRecord('identity', 'patient-001');
    expect(deleted).toBe(2);
    expect(silo.entryCount('identity')).toBe(0);
  });

  test('drop a silo', () => {
    silo.createSilo('identity', 'Identity', ['identity']);
    silo.store('identity', 'identity', 'data-1', 'rec-001');
    expect(silo.dropSilo('identity')).toBe(true);
    expect(silo.siloExists('identity')).toBe(false);
  });

  test('store in nonexistent silo throws', () => {
    expect(() => silo.store('nope', 'identity', 'data', 'rec')).toThrow(/does not exist/);
  });

  test('total entries across silos', () => {
    silo.createSilo('identity', 'Identity', ['identity']);
    silo.createSilo('medical', 'Medical', ['medical']);
    silo.store('identity', 'identity', 'd1', 'r1');
    silo.store('identity', 'identity', 'd2', 'r2');
    silo.store('medical', 'medical', 'd3', 'r3');
    expect(silo.totalEntries()).toBe(3);
  });

  test('entry count per silo', () => {
    silo.createSilo('identity', 'Identity', ['identity']);
    silo.store('identity', 'identity', 'd1', 'r1');
    silo.store('identity', 'identity', 'd2', 'r2');
    expect(silo.entryCount('identity')).toBe(2);
    expect(silo.entryCount('nonexistent')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Identity — Attestation
// ---------------------------------------------------------------------------

describe('IdentityModule — Attestation', () => {
  let identity: IdentityModule;

  beforeEach(() => {
    identity = new IdentityModule();
  });

  test('set and get attestation policy', () => {
    expect(identity.getAttestationPolicy()).toBe(AttestationPolicy.PERMISSIVE);
    identity.setAttestationPolicy(AttestationPolicy.STRICT);
    expect(identity.getAttestationPolicy()).toBe(AttestationPolicy.STRICT);
  });

  test('submit and verify attestation claim', () => {
    const node = identity.register('patient-1');
    identity.submitClaim(node.nodeId.uuid, 'email', 'patient@example.com');
    identity.submitClaim(node.nodeId.uuid, 'role', 'patient');

    const result = identity.verifyAttestation(node.nodeId.uuid);
    expect(result.verified).toBe(true);
    expect(result.claims.email).toBe('patient@example.com');
    expect(result.claims.role).toBe('patient');
  });

  test('attestation fails for unknown node', () => {
    const result = identity.verifyAttestation('unknown-id');
    expect(result.verified).toBe(false);
  });

  test('check attestation status', () => {
    const node = identity.register('provider-1');
    identity.submitClaim(node.nodeId.uuid, 'license', 'MD-12345');
    identity.verifyAttestation(node.nodeId.uuid);
    expect(identity.isAttested(node.nodeId.uuid)).toBe(true);
    expect(identity.isAttested('unknown-id')).toBe(false);
  });

  test('get attestation result', () => {
    const node = identity.register('admin-1');
    identity.submitClaim(node.nodeId.uuid, 'department', 'IT');
    const result = identity.verifyAttestation(node.nodeId.uuid);
    const retrieved = identity.getAttestation(node.nodeId.uuid);
    expect(retrieved).toEqual(result);
  });

  test('list nodes', () => {
    identity.register('node-a');
    identity.register('node-b');
    identity.register('node-c');
    const nodes = identity.listNodes();
    expect(nodes.length).toBe(3);
  });

  test('set node state', () => {
    const node = identity.register('node-1');
    expect(node.state).toBe(NodeState.ACTIVE);
    const updated = identity.setNodeState(node.nodeId.uuid, NodeState.SUSPECT);
    expect(updated!.state).toBe(NodeState.SUSPECT);
  });

  test('has capability check', () => {
    const node = identity.register('node-1');
    identity.createScope(node.nodeId.uuid, ['identity', 'medical']);
    expect(identity.hasCapability(node.nodeId.uuid, 'identity')).toBe(true);
    expect(identity.hasCapability(node.nodeId.uuid, 'financial')).toBe(false);
    expect(identity.hasCapability('unknown', 'identity')).toBe(false);
  });

  test('get scope', () => {
    const node = identity.register('node-1');
    const scope = identity.createScope(node.nodeId.uuid, ['identity']);
    const retrieved = identity.getScope(node.nodeId.uuid);
    expect(retrieved).toEqual(scope);
  });
});

// ---------------------------------------------------------------------------
// Encryption — Batch & Silo Keys
// ---------------------------------------------------------------------------

describe('EncryptionModule — Batch & Silo Keys', () => {
  let encryption: EncryptionModule;

  beforeEach(() => {
    encryption = new EncryptionModule();
  });

  test('encrypt and decrypt batch', async () => {
    const fields = [
      { plaintext: 'John', silo: 'identity', recordId: 'p-001' },
      { plaintext: 'SSN-123-45-6789', silo: 'identity', recordId: 'p-001' },
      { plaintext: 'diabetes', silo: 'medical', recordId: 'p-001' },
    ];

    const ciphertexts = await encryption.encryptBatch(fields);
    expect(ciphertexts.length).toBe(3);
    expect(ciphertexts[0]).toMatch(/^v2:/);

    const decrypted = await encryption.decryptBatch([
      { ciphertext: ciphertexts[0], silo: 'identity', recordId: 'p-001' },
      { ciphertext: ciphertexts[1], silo: 'identity', recordId: 'p-001' },
      { ciphertext: ciphertexts[2], silo: 'medical', recordId: 'p-001' },
    ]);

    expect(decrypted).toEqual(['John', 'SSN-123-45-6789', 'diabetes']);
  });

  test('derive and use silo-specific key', async () => {
    const result = await encryption.deriveSiloKey('medical');
    expect(result.silo).toBe('medical');
    expect(result.keyVersion).toBe(1);
    expect(result.derived).toBe(true);

    const encrypted = await encryption.encryptWithSiloKey('blood pressure 120/80', 'medical', 'p-001');
    expect(encrypted).toMatch(/^v2:/);

    const decrypted = await encryption.decryptWithSiloKey(encrypted, 'medical', 'p-001');
    expect(decrypted).toBe('blood pressure 120/80');
  });

  test('silo key decrypt with wrong silo fails', async () => {
    await encryption.deriveSiloKey('medical');
    await encryption.deriveSiloKey('identity');

    const encrypted = await encryption.encryptWithSiloKey('secret data', 'medical', 'p-001');
    await expect(
      encryption.decryptWithSiloKey(encrypted, 'identity', 'p-001'),
    ).rejects.toThrow(/AAD mismatch/);
  });

  test('silo key without derivation throws', async () => {
    await expect(
      encryption.encryptWithSiloKey('data', 'unknown-silo', 'p-001'),
    ).rejects.toThrow(/No derived key/);
  });

  test('key version tracking', async () => {
    await encryption.init();
    expect(encryption.keyVersion).toBe(1);
    expect(encryption.keyHistory.length).toBe(1);

    await encryption.rotateMasterKey();
    expect(encryption.keyVersion).toBe(2);
    expect(encryption.keyHistory.length).toBe(2);
    expect(encryption.keyHistory[0]!.active).toBe(false);
    expect(encryption.keyHistory[1]!.active).toBe(true);
  });

  test('key rotation clears silo keys', async () => {
    const result = await encryption.deriveSiloKey('medical');
    expect(result.derived).toBe(true);

    await encryption.rotateMasterKey();

    // After rotation, silo keys must be re-derived
    await expect(
      encryption.encryptWithSiloKey('data', 'medical', 'p-001'),
    ).rejects.toThrow(/No derived key/);
  });
});

// ---------------------------------------------------------------------------
// Data — Consent Lifecycle
// ---------------------------------------------------------------------------

describe('DataModule — Consent Lifecycle', () => {
  let data: DataModule;

  beforeEach(() => {
    data = new DataModule();
  });

  test('deny consent flow', () => {
    const consentId = data.requestConsent('provider-1', 'identity', 'medical', ['medical'], 'read', 'treatment');
    expect(data.checkConsent(consentId)).toBe(false);

    const denied = data.denyConsent(consentId, 'patient-1', 'Patient declined');
    expect(denied).toBe(true);

    const record = data.getConsent(consentId);
    expect(record!.status).toBe(ConsentStatus.DENIED);
    expect(record!.denierId).toBe('patient-1');
    expect(record!.denialReason).toBe('Patient declined');
  });

  test('deny nonexistent consent returns false', () => {
    expect(data.denyConsent('unknown', 'patient-1', 'no')).toBe(false);
  });

  test('deny already approved consent returns false', () => {
    const consentId = data.requestConsent('provider-1', 'identity', 'medical', ['medical']);
    data.approveConsent(consentId, 'patient-1');
    expect(data.denyConsent(consentId, 'patient-1', 'too late')).toBe(false);
  });

  test('consent expiry', () => {
    const consentId = data.requestConsent('provider-1', 'identity', 'medical', ['medical']);
    data.approveConsent(consentId, 'patient-1', 1); // 1 second TTL

    const record = data.getConsent(consentId);
    expect(record!.expiresAt).not.toBeNull();
  });

  test('list consents by status', () => {
    const c1 = data.requestConsent('p-1', 'identity', 'medical', ['medical']);
    const c2 = data.requestConsent('p-2', 'identity', 'medical', ['medical']);
    data.approveConsent(c1, 'owner-1');

    const pending = data.listConsents(ConsentStatus.PENDING);
    expect(pending.length).toBe(1);

    const approved = data.listConsents(ConsentStatus.APPROVED);
    expect(approved.length).toBe(1);
  });

  test('anonymous ID with silo binding', () => {
    const anonId = data.createAnonymousId('patient-1', 'medical');
    expect(anonId).toMatch(/^anon-/);

    const resolved = data.resolveAnonymousId(anonId);
    expect(resolved).toBe('patient-1');

    const siloAnonId = data.getAnonymousId('patient-1', 'medical');
    expect(siloAnonId).toBe(anonId);
  });

  test('list silo bindings', () => {
    data.createAnonymousId('patient-1', 'medical');
    data.createAnonymousId('patient-1', 'identity');

    const bindings = data.listSiloBindings('patient-1');
    expect(bindings.length).toBe(2);
  });

  test('resolve count tracking', () => {
    const anonId = data.createAnonymousId('patient-1', 'medical');
    expect(data.getResolveCount(anonId)).toBe(0);

    data.resolveAnonymousId(anonId);
    data.resolveAnonymousId(anonId);
    expect(data.getResolveCount(anonId)).toBe(2);
  });

  test('remove identity cleans up all silo bindings', () => {
    data.createAnonymousId('patient-1', 'medical');
    data.createAnonymousId('patient-1', 'identity');

    data.removeIdentity('patient-1');

    expect(data.listSiloBindings('patient-1').length).toBe(0);
    expect(data.getAnonymousId('patient-1', 'medical')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Full Integration — Licensing + Silos + Encryption + Consent
// ---------------------------------------------------------------------------

describe('Full Integration — Licensed Silo Workflow', () => {
  let client: BedrockClient;
  let licensing: LicensingModule;

  beforeEach(async () => {
    client = new BedrockClient({ mode: 'developer' });
    await client.init();
    licensing = new LicensingModule();
  });

  test('licensed workflow: register nodes, encrypt, consent, audit', async () => {
    // Generate license
    const licenseKey = licensing.generateLicenseKey(LicenseTier.BUSINESS, 'test-org');
    const validation = licensing.validateLicense(licenseKey);
    expect(validation.valid).toBe(true);
    expect(licensing.hasFeature(licenseKey, 'silo_management')).toBe(true);

    // Register nodes
    const patient = client.identity.register('patient-1');
    const provider = client.identity.register('provider-1');

    // Encrypt patient data
    const encrypted = await client.encryption.encrypt('Jane Doe', 'identity', patient.nodeId.uuid);
    const decrypted = await client.encryption.decrypt(encrypted, 'identity', patient.nodeId.uuid);
    expect(decrypted).toBe('Jane Doe');

    // Request and approve consent
    const consentId = client.data.requestConsent(
      provider.nodeId.uuid,
      'identity',
      'medical',
      ['medical'],
      'read',
      'treatment',
    );
    const approved = client.data.approveConsent(consentId, patient.nodeId.uuid);
    expect(approved).toBe(true);

    // Audit trail
    await client.audit.log('consent.approved', provider.nodeId.uuid, patient.nodeId.uuid, 'identity');
    const verified = await client.verifyIntegrity();
    expect(verified).toBe(true);
  });

  test('silo workflow with encryption and consent', async () => {
    const silo = new SiloModule();

    // Create silos
    silo.createSilo('identity', 'Identity Data', ['identity', 'auth']);
    silo.createSilo('medical', 'Medical Records', ['medical']);

    // Encrypt and store in silo
    const encrypted = await client.encryption.encrypt('blood type A+', 'medical', 'p-001');
    silo.store('medical', 'medical', encrypted, 'p-001');

    // Consent-gated access
    const consentId = client.data.requestConsent(
      'researcher-1', 'identity', 'medical', ['medical'], 'read', 'research',
    );
    client.data.approveConsent(consentId, 'p-001');

    expect(client.data.checkConsent(consentId)).toBe(true);

    // Retrieve and decrypt
    const entries = silo.retrieve('medical', 'p-001');
    expect(entries.length).toBe(1);
    const decrypted = await client.encryption.decrypt(entries[0]!.data, 'medical', 'p-001');
    expect(decrypted).toBe('blood type A+');
  });

  test('license tier enforcement on node count', () => {
    const devKey = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'dev-org');

    // Developer tier allows 3 nodes
    expect(licensing.validateLicense(devKey, 'node-1').valid).toBe(true);
    expect(licensing.validateLicense(devKey, 'node-2').valid).toBe(true);
    expect(licensing.validateLicense(devKey, 'node-3').valid).toBe(true);
    expect(licensing.validateLicense(devKey, 'node-4').valid).toBe(false); // exceeds limit
  });

  test('license upgrade unlocks features', () => {
    const key = licensing.generateLicenseKey(LicenseTier.DEVELOPER, 'dev-org');
    expect(licensing.hasFeature(key, 'ca_signed_certs')).toBe(false);

    licensing.upgradeLicense(key, LicenseTier.BUSINESS);
    expect(licensing.hasFeature(key, 'ca_signed_certs')).toBe(true);
  });
});