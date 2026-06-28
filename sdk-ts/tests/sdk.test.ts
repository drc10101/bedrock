/**
 * Tests for the Bedrock TypeScript SDK.
 *
 * Validates all modules: Identity, Encryption, Data, Audit, Access, Transport.
 * SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
 */

import {
  BedrockClient,
  NodeState,
  DataCategory,
  ConsentStatus,
  Role,
  Portal,
  Permission,
  DowngradeStatus,
  TLSVersion,
  SignalType,
} from '../src/index';

// ---------------------------------------------------------------------------
// Identity Module
// ---------------------------------------------------------------------------

describe('IdentityModule', () => {
  let client: BedrockClient;

  beforeEach(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('register a new node', () => {
    const node = client.identity.register('test-node');
    expect(node.nodeId.uuid).toBeDefined();
    expect(node.nodeId.uuid).toMatch(/^[0-9a-f]{8}-/);
    expect(node.name).toBe('test-node');
  });

  test('get a node by ID', () => {
    const node = client.identity.register('lookup-node');
    const found = client.identity.get(node.nodeId.uuid);
    expect(found).toBeDefined();
    expect(found!.name).toBe('lookup-node');
  });

  test('get returns undefined for unknown node', () => {
    const found = client.identity.get('nonexistent');
    expect(found).toBeUndefined();
  });

  test('unregister a node', () => {
    const node = client.identity.register('remove-node');
    const result = client.identity.unregister(node.nodeId.uuid);
    expect(result).toBe(true);
    expect(client.identity.get(node.nodeId.uuid)).toBeUndefined();
  });

  test('issue a certificate', () => {
    const node = client.identity.register('cert-node');
    const cert = client.identity.issueCertificate(
      node.nodeId.uuid,
      'cert-node',
      'sha256:abc123',
    );
    expect(cert.serialNumber).toMatch(/^cert-/);
    expect(cert.nodeUuid).toBe(node.nodeId.uuid);
    expect(cert.publicKeyHash).toBe('sha256:abc123');
  });

  test('revoke a certificate', () => {
    const node = client.identity.register('revoke-node');
    const cert = client.identity.issueCertificate(
      node.nodeId.uuid,
      'revoke-node',
      'sha256:xyz',
    );
    const revoked = client.identity.revokeCertificate(node.nodeId.uuid, 'compromised');
    expect(revoked.status).toBeDefined();
  });

  test('create a capability scope', () => {
    const scope = client.identity.createScope('node-123', [
      DataCategory.IDENTITY,
      DataCategory.MEDICAL,
    ]);
    expect(scope.nodeId).toBe('node-123');
    expect(scope.categories).toContain(DataCategory.IDENTITY);
    expect(scope.categories).toContain(DataCategory.MEDICAL);
  });
});

// ---------------------------------------------------------------------------
// Encryption Module
// ---------------------------------------------------------------------------

describe('EncryptionModule', () => {
  let client: BedrockClient;

  beforeEach(async () => {
    client = new BedrockClient({ mode: 'developer' });
    await client.init();
  });

  test('encrypt and decrypt a field value', async () => {
    const plaintext = 'sensitive patient data';
    const ciphertext = await client.encryption.encrypt(
      plaintext,
      'medical',
      'record-001',
      'read',
      'field',
    );
    expect(ciphertext).toMatch(/^v2:/);

    const decrypted = await client.encryption.decrypt(
      ciphertext,
      'medical',
      'record-001',
      'read',
      'field',
    );
    expect(decrypted).toBe(plaintext);
  });

  test('decrypt with wrong silo fails', async () => {
    const ciphertext = await client.encryption.encrypt(
      'secret',
      'medical',
      'rec-1',
      'read',
      'field',
    );

    await expect(
      client.encryption.decrypt(ciphertext, 'identity', 'rec-1', 'read', 'field'),
    ).rejects.toThrow('AAD mismatch');
  });

  test('decrypt with wrong record ID fails', async () => {
    const ciphertext = await client.encryption.encrypt(
      'secret',
      'medical',
      'rec-1',
      'read',
      'field',
    );

    await expect(
      client.encryption.decrypt(ciphertext, 'medical', 'rec-2', 'read', 'field'),
    ).rejects.toThrow('AAD mismatch');
  });

  test('generate an ECDH key pair', async () => {
    const keyPair = await client.encryption.generateKeyPair();
    expect(keyPair.privateKey).toBeDefined();
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey.length).toBeGreaterThan(0);
    expect(keyPair.publicKey.length).toBeGreaterThan(0);
  });

  test('rotate master key', async () => {
    const key1 = await client.encryption.rotateMasterKey();
    expect(key1).toBeDefined();
    expect(typeof key1).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// Data Module
// ---------------------------------------------------------------------------

describe('DataModule', () => {
  let client: BedrockClient;

  beforeEach(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('request and approve consent', () => {
    const consentId = client.data.requestConsent(
      'node-1',
      'medical',
      'identity',
      ['identity'],
      'read',
      'Cross-silo lookup',
    );
    expect(consentId).toMatch(/^consent-/);

    const approved = client.data.approveConsent(consentId, 'owner-1', 3600);
    expect(approved).toBe(true);

    const valid = client.data.checkConsent(consentId);
    expect(valid).toBe(true);
  });

  test('check consent returns false for unknown consent', () => {
    expect(client.data.checkConsent('nonexistent')).toBe(false);
  });

  test('revoke consent', () => {
    const consentId = client.data.requestConsent(
      'node-1', 'medical', 'identity', ['identity'],
    );
    client.data.approveConsent(consentId, 'owner-1');

    const revoked = client.data.revokeConsent(consentId);
    expect(revoked).toBe(true);
    expect(client.data.checkConsent(consentId)).toBe(false);
  });

  test('create and resolve anonymous ID', () => {
    const anonId = client.data.createAnonymousId('patient-123', 'medical');
    expect(anonId).toMatch(/^anon-/);

    const resolved = client.data.resolveAnonymousId(anonId);
    expect(resolved).toBe('patient-123');
  });

  test('remove identity (right to be forgotten)', () => {
    const anonId = client.data.createAnonymousId('patient-456', 'medical');
    expect(client.data.resolveAnonymousId(anonId)).toBe('patient-456');

    const removed = client.data.removeIdentity('patient-456');
    expect(removed).toBe(true);
    expect(client.data.resolveAnonymousId(anonId)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Audit Module
// ---------------------------------------------------------------------------

describe('AuditModule', () => {
  let client: BedrockClient;

  beforeEach(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('log an event and retrieve it', async () => {
    const hash = await client.audit.log(
      'data.read',
      'node-1',
      'record-1',
      'medical',
    );
    expect(hash).toMatch(/^[0-9a-f]{64}$/);

    const entries = client.audit.query({ action: 'data.read' });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.action).toBe('data.read');
    expect(entries[0]!.actorId).toBe('node-1');
  });

  test('verify chain integrity', async () => {
    await client.audit.log('data.read', 'node-1', 'rec-1', 'medical');
    await client.audit.log('data.write', 'node-2', 'rec-2', 'identity');
    await client.audit.log('consent.approve', 'node-3', 'rec-3', 'audit');

    const valid = await client.audit.verify();
    expect(valid).toBe(true);
  });

  test('query with filters', async () => {
    await client.audit.log('data.read', 'node-1', 'rec-1', 'medical');
    await client.audit.log('data.write', 'node-2', 'rec-2', 'identity');
    await client.audit.log('data.read', 'node-3', 'rec-3', 'medical');

    const medical = client.audit.query({ silo: 'medical' });
    expect(medical).toHaveLength(2);

    const reads = client.audit.query({ action: 'data.read' });
    expect(reads).toHaveLength(2);
  });

  test('export chain as JSONL', async () => {
    await client.audit.log('data.read', 'node-1', 'rec-1', 'medical');
    const exported = client.audit.export();
    expect(exported).toContain('data.read');
    expect(exported).toContain('node-1');
  });

  test('head and tail hash', async () => {
    await client.audit.log('first', 'n1', 'r1', 's1');
    await client.audit.log('second', 'n2', 'r2', 's2');

    const head = client.audit.headHash;
    const tail = client.audit.tailHash;
    expect(head).toBeDefined();
    expect(tail).toBeDefined();
    expect(head).not.toBe(tail);
  });
});

// ---------------------------------------------------------------------------
// Access Module
// ---------------------------------------------------------------------------

describe('AccessModule', () => {
  let client: BedrockClient;

  beforeEach(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('create user and authenticate', () => {
    const userId = client.access.createUser('alice', 'password123', 'admin');
    expect(userId).toMatch(/^user-/);

    const session = client.access.authenticate('alice', 'password123', 'admin');
    expect(session).not.toBeNull();
    expect(session!.userId).toBe(userId);
    expect(session!.role).toBe(Role.ADMIN);
  });

  test('authenticate with wrong password fails', () => {
    client.access.createUser('bob', 'pass456', 'operator');
    const session = client.access.authenticate('bob', 'wrong');
    expect(session).toBeNull();
  });

  test('check permissions — admin has full access', () => {
    client.access.createUser('admin', 'pass', 'admin');
    const session = client.access.authenticate('admin', 'pass', 'admin')!;
    client.access.verifyMfa(session.sessionId, '123456');

    expect(client.access.checkPermission(session, Permission.CERT_ISSUE)).toBe(true);
    expect(client.access.checkPermission(session, Permission.DATA_READ)).toBe(true);
    expect(client.access.checkPermission(session, Permission.NODE_QUARANTINE)).toBe(true);
  });

  test('check permissions — viewer is limited', () => {
    client.access.createUser('viewer', 'pass', 'viewer');
    const session = client.access.authenticate('viewer', 'pass', 'system')!;

    expect(client.access.checkPermission(session, Permission.DATA_READ)).toBe(true);
    expect(client.access.checkPermission(session, Permission.DATA_WRITE)).toBe(false);
  });

  test('MFA required for write operations', () => {
    client.access.createUser('operator', 'pass', 'operator');
    const session = client.access.authenticate('operator', 'pass', 'provider')!;

    // Before MFA — read allowed, write blocked
    expect(client.access.checkPermission(session, Permission.DATA_READ)).toBe(true);
    expect(client.access.checkPermission(session, Permission.DATA_WRITE)).toBe(false);

    // After MFA — write allowed
    client.access.verifyMfa(session.sessionId, '123456');
    expect(client.access.checkPermission(session, Permission.DATA_WRITE)).toBe(true);
  });

  test('end session', () => {
    client.access.createUser('charlie', 'pass', 'viewer');
    const session = client.access.authenticate('charlie', 'pass')!;
    const ended = client.access.endSession(session.sessionId);
    expect(ended).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Transport Module — TLS
// ---------------------------------------------------------------------------

describe('TransportModule — TLS', () => {
  let client: BedrockClient;

  beforeEach(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('configure TLS in developer mode', () => {
    const config = client.transport.tls.configureTLS('developer');
    expect(config.isDeveloperMode).toBe(true);
    expect(config.minVersion).toBe(TLSVersion.TLS_1_2);
    expect(config.verifyClient).toBe(false);
  });

  test('configure TLS in production mode', () => {
    const config = client.transport.tls.configureTLS(
      'production',
      '/certs/cert.pem',
      '/certs/key.pem',
      '/certs/ca.pem',
    );
    expect(config.isDeveloperMode).toBe(false);
    expect(config.minVersion).toBe(TLSVersion.TLS_1_3);
    expect(config.verifyClient).toBe(true);
  });

  test('detect downgrade — HTTP is a downgrade', () => {
    client.transport.tls.configureTLS('developer');
    const result = client.transport.tls.detectDowngrade({
      'x-forwarded-proto': 'http',
    });
    expect(result).toBe(DowngradeStatus.DOWNGRADE);
  });

  test('detect downgrade — HTTPS with valid TLS is secure', () => {
    client.transport.tls.configureTLS('developer');
    const result = client.transport.tls.detectDowngrade({
      'x-forwarded-proto': 'https',
      'x-tls-version': '1.3',
    });
    expect(result).toBe(DowngradeStatus.SECURE);
  });
});

// ---------------------------------------------------------------------------
// Transport Module — Mesh
// ---------------------------------------------------------------------------

describe('TransportModule — Mesh', () => {
  let client: BedrockClient;

  beforeEach(() => {
    client = new BedrockClient({ mode: 'developer' });
  });

  test('register nodes in mesh', () => {
    const node = client.identity.register('mesh-node');
    client.transport.mesh.registerNode(node);
    // No error means success
    expect(true).toBe(true);
  });

  test('flag node and reach consensus', () => {
    const target = client.identity.register('target');
    const observer1 = client.identity.register('obs-1');
    const observer2 = client.identity.register('obs-2');

    client.transport.mesh.registerNode(target);
    client.transport.mesh.registerNode(observer1);
    client.transport.mesh.registerNode(observer2);

    client.transport.mesh.flagNode(
      observer1.nodeId.uuid, target.nodeId.uuid, SignalType.BRUTE_FORCE,
    );
    client.transport.mesh.flagNode(
      observer2.nodeId.uuid, target.nodeId.uuid, SignalType.CREDENTIAL_STUFFING,
    );

    const hasConsensus = client.transport.mesh.checkConsensus(target.nodeId.uuid);
    expect(hasConsensus).toBe(true);
  });

  test('process flags transitions node to suspect then quarantined', () => {
    const target = client.identity.register('target');
    const obs1 = client.identity.register('obs-1');
    const obs2 = client.identity.register('obs-2');

    client.transport.mesh.registerNode(target);
    client.transport.mesh.registerNode(obs1);
    client.transport.mesh.registerNode(obs2);

    // First flag round: ACTIVE → SUSPECT
    client.transport.mesh.flagNode(obs1.nodeId.uuid, target.nodeId.uuid, SignalType.PORT_SCAN);
    client.transport.mesh.flagNode(obs2.nodeId.uuid, target.nodeId.uuid, SignalType.UNUSUAL_VOLUME);

    const firstRound = client.transport.mesh.processFlags();
    expect(firstRound).toHaveLength(0); // Not quarantined yet

    // Second flag round: SUSPECT → QUARANTINED
    client.transport.mesh.flagNode(obs1.nodeId.uuid, target.nodeId.uuid, SignalType.BRUTE_FORCE);
    client.transport.mesh.flagNode(obs2.nodeId.uuid, target.nodeId.uuid, SignalType.PRIVILEGE_ESCALATION);

    const secondRound = client.transport.mesh.processFlags();
    expect(secondRound).toContain(target.nodeId.uuid);
  });

  test('begin and complete healing', () => {
    const node = client.identity.register('healing-node');
    client.transport.mesh.registerNode(node);

    // Force node into QUARANTINED state via flag processing
    const obs1 = client.identity.register('o1');
    const obs2 = client.identity.register('o2');
    client.transport.mesh.registerNode(obs1);
    client.transport.mesh.registerNode(obs2);

    client.transport.mesh.flagNode(obs1.nodeId.uuid, node.nodeId.uuid, SignalType.SILENT_NODE);
    client.transport.mesh.flagNode(obs2.nodeId.uuid, node.nodeId.uuid, SignalType.ATTESTATION_FAILURE);
    client.transport.mesh.processFlags(); // ACTIVE → SUSPECT
    client.transport.mesh.flagNode(obs1.nodeId.uuid, node.nodeId.uuid, SignalType.BRUTE_FORCE);
    client.transport.mesh.flagNode(obs2.nodeId.uuid, node.nodeId.uuid, SignalType.PORT_SCAN);
    client.transport.mesh.processFlags(); // SUSPECT → QUARANTINED

    // Begin healing
    const healResult = client.transport.mesh.beginHealing(node.nodeId.uuid, 'recovery');
    expect(healResult.success).toBe(true);
    expect(healResult.newState).toBe(NodeState.HEALING);

    // Complete healing
    const completeResult = client.transport.mesh.completeHealing(node.nodeId.uuid);
    expect(completeResult.success).toBe(true);
    expect(completeResult.newState).toBe(NodeState.ACTIVE);
  });
});

// ---------------------------------------------------------------------------
// BedrockClient integration
// ---------------------------------------------------------------------------

describe('BedrockClient', () => {
  test('initializes in developer mode by default', () => {
    const client = new BedrockClient();
    expect(client.mode).toBe('developer');
  });

  test('initializes in production mode', () => {
    const client = new BedrockClient({ mode: 'production' });
    expect(client.mode).toBe('production');
  });

  test('all modules are accessible', () => {
    const client = new BedrockClient();
    expect(client.identity).toBeDefined();
    expect(client.encryption).toBeDefined();
    expect(client.data).toBeDefined();
    expect(client.audit).toBeDefined();
    expect(client.access).toBeDefined();
    expect(client.transport).toBeDefined();
  });

  test('full workflow: register → encrypt → consent → audit', async () => {
    const client = new BedrockClient({ mode: 'developer' });
    await client.init();

    // Register a node
    const node = client.identity.register('workflow-node');
    expect(node.name).toBe('workflow-node');

    // Encrypt data
    const ciphertext = await client.encryption.encrypt(
      'patient BP: 120/80',
      'medical',
      'record-001',
      'read',
      'field',
    );
    expect(ciphertext).toMatch(/^v2:/);

    // Request and approve consent
    const consentId = client.data.requestConsent(
      node.nodeId.uuid,
      'medical',
      'identity',
      ['identity'],
      'read',
    );
    client.data.approveConsent(consentId, 'owner-1');
    expect(client.data.checkConsent(consentId)).toBe(true);

    // Audit the access
    await client.audit.log('data.read', node.nodeId.uuid, 'record-001', 'medical');

    // Verify chain
    const valid = await client.verifyIntegrity();
    expect(valid).toBe(true);
  });

  test('decrypt rejects unsupported format', async () => {
    const client = new BedrockClient({ mode: 'developer' });
    await client.init();

    await expect(
      client.encryption.decrypt('invalid-ciphertext', 'silo', 'rec', 'read', 'field'),
    ).rejects.toThrow('Unsupported ciphertext format');
  });

  test('revoke certificate for unknown node throws', () => {
    const client = new BedrockClient();
    expect(() => client.identity.revokeCertificate('unknown-uuid')).toThrow('No certificate found');
  });

  test('approve already-approved consent returns false', () => {
    const client = new BedrockClient();
    const id = client.data.requestConsent('n1', 'medical', 'identity', ['identity']);
    client.data.approveConsent(id, 'owner');
    expect(client.data.approveConsent(id, 'owner2')).toBe(false);
  });

  test('approve nonexistent consent returns false', () => {
    const client = new BedrockClient();
    expect(client.data.approveConsent('nonexistent', 'owner')).toBe(false);
  });

  test('audit empty chain head/tail is null', () => {
    const client = new BedrockClient();
    expect(client.audit.headHash).toBeNull();
    expect(client.audit.tailHash).toBeNull();
  });

  test('TLS detect downgrade with unknown headers', () => {
    const client = new BedrockClient();
    client.transport.tls.configureTLS('developer');
    const result = client.transport.tls.detectDowngrade({});
    expect(result).toBe(DowngradeStatus.UNKNOWN);
  });

  test('TLS detect downgrade: TLS version below minimum', () => {
    const client = new BedrockClient();
    client.transport.tls.configureTLS('production');
    const result = client.transport.tls.detectDowngrade({
      'x-forwarded-proto': 'https',
      'x-tls-version': '1.1',
    });
    expect(result).toBe(DowngradeStatus.DOWNGRADE);
  });

  test('TLS detect downgrade: TLS version at minimum is secure', () => {
    const client = new BedrockClient();
    client.transport.tls.configureTLS('production');
    const result = client.transport.tls.detectDowngrade({
      'x-forwarded-proto': 'https',
      'x-tls-version': '1.3',
    });
    expect(result).toBe(DowngradeStatus.SECURE);
  });

  test('mesh beginHealing for nonexistent node fails', () => {
    const client = new BedrockClient();
    const result = client.transport.mesh.beginHealing('nonexistent');
    expect(result.success).toBe(false);
    expect(result.reason).toBe('Node not found');
  });

  test('mesh completeHealing for nonexistent node fails', () => {
    const client = new BedrockClient();
    const result = client.transport.mesh.completeHealing('nonexistent');
    expect(result.success).toBe(false);
    expect(result.reason).toBe('Node not found');
  });

  test('mesh beginHealing for active node fails', () => {
    const client = new BedrockClient();
    const node = client.identity.register('active-node');
    client.transport.mesh.registerNode(node);
    const result = client.transport.mesh.beginHealing(node.nodeId.uuid);
    expect(result.success).toBe(false);
    expect(result.reason).toContain('not quarantined');
  });

  test('TLS not configured throws on detectDowngrade', () => {
    const client = new BedrockClient();
    expect(() => client.transport.tls.detectDowngrade({})).toThrow('TLS not configured');
  });
});