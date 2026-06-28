/**
 * SDK Integration Tests — End-to-end workflows through the TypeScript SDK.
 *
 * Tests that BedrockClient correctly wires all modules together
 * for realistic healthcare, banking, and multi-silo scenarios.
 *
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

import {
  BedrockClient,
  NodeState,
  DataCategory,
  SignalType,
  Portal,
  Role,
  Permission,
  CertificateStatus,
} from '../src';

// ---------------------------------------------------------------------------
// Workflow 1: Healthcare — Register provider, encrypt PHI, consent, audit
// ---------------------------------------------------------------------------

describe('Healthcare Workflow', () => {
  let client: BedrockClient;

  beforeAll(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('full healthcare flow: register, encrypt, consent, audit', async () => {
    // Register a provider node
    const provider = client.identity.register('provider-alice');
    expect(provider.name).toBe('provider-alice');
    expect(provider.nodeId).toBeDefined();

    // Issue a certificate
    const cert = client.identity.issueCertificate(
      provider.nodeId.uuid, 'provider-alice', 'sha256:provider-public-key',
    );
    expect(cert.status).toBe(CertificateStatus.ACTIVE);

    // Create a capability scope
    const scope = client.identity.createScope(
      provider.nodeId.uuid, ['identity', 'medical'],
    );
    expect(scope.categories).toContain(DataCategory.IDENTITY);
    expect(scope.categories).toContain(DataCategory.MEDICAL);

    // Encrypt a patient's medical record
    const plaintext = 'BP: 120/80, HR: 72, Temp: 98.6F';
    const ciphertext = await client.encryption.encrypt(
      plaintext, 'medical', 'patient-001-vitals', 'read', 'field',
    );
    expect(ciphertext.startsWith('v2:')).toBe(true);
    expect(ciphertext).not.toBe(plaintext);

    // Decrypt it back
    const decrypted = await client.encryption.decrypt(
      ciphertext, 'medical', 'patient-001-vitals', 'read', 'field',
    );
    expect(decrypted).toBe(plaintext);

    // Wrong silo should fail
    await expect(
      client.encryption.decrypt(ciphertext, 'identity', 'patient-001-vitals', 'read', 'field'),
    ).rejects.toThrow(/AAD mismatch/);

    // Request cross-silo consent
    const consentId = client.data.requestConsent(
      provider.nodeId.uuid, 'medical', 'identity', ['identity'], 'read', 'Cross-reference patient identity',
    );
    expect(consentId).toBeDefined();

    // Approve consent
    expect(client.data.approveConsent(consentId, 'patient-001', 3600)).toBe(true);

    // Verify consent is valid
    expect(client.data.checkConsent(consentId)).toBe(true);

    // Audit the access
    const chainHash = await client.audit.log(
      'phi.access', provider.nodeId.uuid, 'patient-001', 'medical',
      { consentId, scope: 'read' },
    );
    expect(chainHash).toBeDefined();

    // Verify audit chain
    expect(await client.audit.verify()).toBe(true);

    // Query audit trail
    const entries = client.audit.query({ silo: 'medical' });
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries[0].action).toBe('phi.access');

    // Revoke consent
    expect(client.data.revokeConsent(consentId)).toBe(true);
    expect(client.data.checkConsent(consentId)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Workflow 2: Banking — Identity, transactions, RBAC
// ---------------------------------------------------------------------------

describe('Banking Workflow', () => {
  let client: BedrockClient;

  beforeAll(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('banking RBAC flow with MFA', async () => {
    // Create users with different roles
    client.access.createUser('admin-bank', 'secure123', Role.ADMIN);
    client.access.createUser('teller-bob', 'pass456', Role.OPERATOR);
    client.access.createUser('auditor-carol', 'view789', Role.VIEWER);

    // Authenticate admin and verify MFA
    const adminSession = client.access.authenticate('admin-bank', 'secure123', Portal.ADMIN);
    expect(adminSession).not.toBeNull();
    expect(adminSession!.role).toBe(Role.ADMIN);

    // MFA required for CERT_ISSUE
    expect(client.access.checkPermission(adminSession!, Permission.CERT_ISSUE)).toBe(false);
    client.access.verifyMfa(adminSession!.sessionId, '000000'); // Simplified — any code works
    expect(client.access.checkPermission(adminSession!, Permission.CERT_ISSUE)).toBe(true);

    // Teller can read/write but not issue certs even with MFA
    const tellerSession = client.access.authenticate('teller-bob', 'pass456', Portal.PROVIDER);
    client.access.verifyMfa(tellerSession!.sessionId, '000000');
    expect(client.access.checkPermission(tellerSession!, Permission.DATA_READ)).toBe(true);
    expect(client.access.checkPermission(tellerSession!, Permission.DATA_WRITE)).toBe(true);
    expect(client.access.checkPermission(tellerSession!, Permission.CERT_ISSUE)).toBe(false);

    // Viewer can only read
    const viewerSession = client.access.authenticate('auditor-carol', 'view789', Portal.SYSTEM);
    expect(client.access.checkPermission(viewerSession!, Permission.DATA_READ)).toBe(true);
    expect(client.access.checkPermission(viewerSession!, Permission.DATA_WRITE)).toBe(false);

    // Encrypt a transaction amount
    const amount = '$15,432.50';
    const encrypted = await client.encryption.encrypt(
      amount, 'transaction', 'txn-2026-001', 'read', 'field',
    );

    // Decrypt with correct context
    expect(
      await client.encryption.decrypt(encrypted, 'transaction', 'txn-2026-001', 'read', 'field'),
    ).toBe(amount);

    // Audit the transaction access
    await client.audit.log('transaction.read', tellerSession!.userId, 'txn-2026-001', 'transaction');
    expect(await client.audit.verify()).toBe(true);

    // Wrong password should fail
    const wrongAuth = client.access.authenticate('teller-bob', 'wrong-password', Portal.PROVIDER);
    expect(wrongAuth).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Workflow 3: Defense — Mesh, attestation, healing
// ---------------------------------------------------------------------------

describe('Defense Mesh Workflow', () => {
  let client: BedrockClient;

  beforeAll(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('mesh attack detection and healing', () => {
    // Register nodes
    const target = client.identity.register('high-value-target');
    const observer1 = client.identity.register('sensor-alpha');
    const observer2 = client.identity.register('sensor-beta');

    // Add to mesh
    client.transport.mesh.registerNode(target);
    client.transport.mesh.registerNode(observer1);
    client.transport.mesh.registerNode(observer2);

    // Add neighbor relationships
    client.transport.mesh.addNeighbor(target.nodeId.uuid, observer1.nodeId.uuid);
    client.transport.mesh.addNeighbor(target.nodeId.uuid, observer2.nodeId.uuid);

    // Flag the target with valid signal types
    client.transport.mesh.flagNode(
      observer1.nodeId.uuid, target.nodeId.uuid, SignalType.CREDENTIAL_STUFFING,
    );
    client.transport.mesh.flagNode(
      observer2.nodeId.uuid, target.nodeId.uuid, SignalType.UNUSUAL_VOLUME,
    );

    // Round 1: ACTIVE -> SUSPECT
    const q1 = client.transport.mesh.processFlags();
    expect(q1.length).toBe(0); // First round: only SUSPECT, not QUARANTINED yet

    // Round 2: SUSPECT -> QUARANTINED
    const q2 = client.transport.mesh.processFlags();
    expect(q2).toContain(target.nodeId.uuid);

    // Begin healing
    const healResult = client.transport.mesh.beginHealing(target.nodeId.uuid, 'Investigation complete');
    expect(healResult.success).toBe(true);
    expect(healResult.newState).toBe(NodeState.HEALING);

    // Complete healing
    const completeResult = client.transport.mesh.completeHealing(target.nodeId.uuid);
    expect(completeResult.success).toBe(true);
    expect(completeResult.newState).toBe(NodeState.ACTIVE);
  });
});

// ---------------------------------------------------------------------------
// Workflow 4: Multi-silo with anonymous IDs
// ---------------------------------------------------------------------------

describe('Multi-Silo Anonymous Workflow', () => {
  let client: BedrockClient;

  beforeAll(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('anonymous ID lifecycle with right to be forgotten', async () => {
    // Create anonymous IDs across silos
    const medAnon = client.data.createAnonymousId('patient-42', 'medical');
    const idAnon = client.data.createAnonymousId('patient-42', 'identity');
    const txnAnon = client.data.createAnonymousId('patient-42', 'transaction');

    // Each silo gets a different anonymous ID
    expect(medAnon).not.toBe(idAnon);
    expect(idAnon).not.toBe(txnAnon);

    // Resolve back to real identity
    expect(client.data.resolveAnonymousId(medAnon)).toBe('patient-42');
    expect(client.data.resolveAnonymousId(idAnon)).toBe('patient-42');

    // Encrypt data using anonymous IDs
    const data = 'Diagnosis: cleared';
    const encrypted = await client.encryption.encrypt(
      data, 'medical', medAnon, 'read', 'field',
    );
    expect(encrypted.startsWith('v2:')).toBe(true);

    // Decrypt with correct context
    const decrypted = await client.encryption.decrypt(
      encrypted, 'medical', medAnon, 'read', 'field',
    );
    expect(decrypted).toBe(data);

    // Right to be forgotten
    expect(client.data.removeIdentity('patient-42')).toBe(true);
    expect(client.data.resolveAnonymousId(medAnon)).toBeNull();
    expect(client.data.resolveAnonymousId(idAnon)).toBeNull();
    expect(client.data.resolveAnonymousId(txnAnon)).toBeNull();

    // Audit the deletion
    await client.audit.log(
      'identity.deleted', 'system', 'patient-42', 'identity',
      { reason: 'right_to_be_forgotten' },
    );
    expect(await client.audit.verify()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Workflow 5: Key rotation and chain continuity
// ---------------------------------------------------------------------------

describe('Key Rotation Workflow', () => {
  let client: BedrockClient;

  beforeAll(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('key rotation preserves chain', async () => {
    // Encrypt data with initial key
    const data = 'Confidential report v1';
    const v1 = await client.encryption.encrypt(
      data, 'audit', 'report-001', 'read', 'field',
    );

    // Audit some events
    await client.audit.log('data.write', 'admin', 'report-001', 'audit');
    await client.audit.log('data.read', 'analyst', 'report-001', 'audit');

    // Rotate master key
    const newKey = await client.encryption.rotateMasterKey();
    expect(newKey).toBeDefined();

    // Encrypt new data with rotated key
    const v2 = await client.encryption.encrypt(
      'Confidential report v2', 'audit', 'report-001', 'read', 'field',
    );

    expect(v1).not.toBe(v2);
    expect(v1.startsWith('v2:')).toBe(true);
    expect(v2.startsWith('v2:')).toBe(true);

    // Audit chain is still valid
    await client.audit.log('key.rotation', 'admin', 'master-key', 'audit');
    expect(await client.audit.verify()).toBe(true);

    // Verify chain has all entries
    const allEntries = client.audit.query({});
    expect(allEntries.length).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Workflow 6: Production mode configuration
// ---------------------------------------------------------------------------

describe('Production Mode Workflow', () => {
  test('production config', () => {
    const prodClient = new BedrockClient({ mode: 'production' });
    expect(prodClient.mode).toBe('production');
  });

  test('developer config', () => {
    const devClient = new BedrockClient({ mode: 'developer' });
    expect(devClient.mode).toBe('developer');
  });

  test('default is developer', () => {
    const defaultClient = new BedrockClient();
    expect(defaultClient.mode).toBe('developer');
  });

  test('production TLS config', () => {
    const client = new BedrockClient({ mode: 'developer' });
    const config = client.transport.tls.configureTLS(
      'production', '/certs/server.pem', '/certs/server.key', '/certs/ca.pem',
    );
    expect(config.isDeveloperMode).toBe(false);
    expect(config.minVersion).toBe('1.3');
    expect(config.verifyClient).toBe(true);
  });

  test('developer TLS config', () => {
    const client = new BedrockClient({ mode: 'developer' });
    const config = client.transport.tls.configureTLS('developer');
    expect(config.isDeveloperMode).toBe(true);
    expect(config.minVersion).toBe('1.2');
    expect(config.verifyClient).toBe(false);
  });

  test('downgrade detection: HTTP', () => {
    const client = new BedrockClient({ mode: 'developer' });
    client.transport.tls.configureTLS('developer');
    const result = client.transport.tls.detectDowngrade({ 'x-forwarded-proto': 'http' });
    expect(result).toBe('downgrade');
  });

  test('downgrade detection: TLS version', () => {
    const client = new BedrockClient({ mode: 'developer' });
    client.transport.tls.configureTLS('production');
    const result = client.transport.tls.detectDowngrade({
      'x-forwarded-proto': 'https',
      'x-tls-version': '1.2',
    });
    expect(result).toBe('downgrade');
  });

  test('downgrade detection: secure', () => {
    const client = new BedrockClient({ mode: 'developer' });
    client.transport.tls.configureTLS('developer');
    const result = client.transport.tls.detectDowngrade({
      'x-forwarded-proto': 'https',
      'x-tls-version': '1.3',
    });
    expect(result).toBe('secure');
  });
});

// ---------------------------------------------------------------------------
// Workflow 7: Certificate lifecycle
// ---------------------------------------------------------------------------

describe('Certificate Lifecycle', () => {
  let client: BedrockClient;

  beforeAll(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('certificate issue, revoke, error handling', async () => {
    // Register node and issue certificate
    const node = client.identity.register('lifecycle-node');
    const cert = client.identity.issueCertificate(
      node.nodeId.uuid, 'lifecycle-node', 'sha256:lifecycle-key',
    );
    expect(cert.status).toBe(CertificateStatus.ACTIVE);
    expect(cert.nodeUuid).toBe(node.nodeId.uuid);

    // Revoke the certificate
    const revoked = client.identity.revokeCertificate(node.nodeId.uuid, 'key compromised');
    expect(revoked.status).toBe(CertificateStatus.REVOKED);

    // Attempt to revoke nonexistent should throw
    expect(() =>
      client.identity.revokeCertificate('nonexistent-uuid', 'test'),
    ).toThrow(/No certificate found/);

    // Audit the revocation
    await client.audit.log(
      'cert.revoke', 'admin', node.nodeId.uuid, 'identity',
      { reason: 'key compromised' },
    );
    expect(await client.audit.verify()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Workflow 8: Rate limiting
// ---------------------------------------------------------------------------

describe('Rate Limiting', () => {
  let client: BedrockClient;

  beforeAll(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('rate limit allows normal traffic', () => {
    const result = client.transport.tls.checkRateLimit('node-1');
    expect(result).toBe('allowed');
  });

  test('rate limit tracks different keys independently', () => {
    const r1 = client.transport.tls.checkRateLimit('node-1');
    const r2 = client.transport.tls.checkRateLimit('node-2');
    expect(r1).toBe('allowed');
    expect(r2).toBe('allowed');
  });
});