# Bedrock TypeScript SDK

Identity-based security framework for TypeScript/JavaScript. Every node is a user. Everything between is encrypted at rest.

**Licensed under BSL-1.1 — See [LICENSE](../LICENSE) for details.**

## Installation

```bash
npm install @bedrock/sdk
```

## Quick Start

```typescript
import { BedrockClient } from '@bedrock/sdk';

const client = new BedrockClient({ mode: 'developer' });
await client.init(); // Initialize crypto subsystem

// Register a node
const node = client.identity.register('my-service');

// Encrypt data
const ciphertext = await client.encryption.encrypt(
  'sensitive data',
  'medical',   // silo
  'record-001', // record ID
  'read',       // scope
  'field',      // operation
);

// Decrypt
const plaintext = await client.encryption.decrypt(ciphertext, 'medical', 'record-001', 'read', 'field');

// Request consent for cross-silo access
const consentId = client.data.requestConsent(node.nodeId.uuid, 'medical', 'identity', ['identity']);
client.data.approveConsent(consentId, 'owner-1');

// Audit everything
await client.audit.log('data.read', node.nodeId.uuid, 'record-001', 'medical');

// Verify chain integrity
const valid = await client.verifyIntegrity();
```

## Modules

### Identity
- `register(name)` — Create a node
- `get(nodeId)` — Look up a node
- `unregister(nodeId)` — Remove a node
- `issueCertificate(nodeUuid, name, publicKeyHash)` — Issue a certificate
- `revokeCertificate(nodeUuid, reason)` — Revoke a certificate
- `createScope(nodeId, categories)` — Create a capability scope

### Encryption
- `encrypt(plaintext, silo, recordId, scope, operation)` — Field-level encrypt
- `decrypt(ciphertext, silo, recordId, scope, operation)` — Field-level decrypt
- `generateKeyPair()` — Generate ECDH key pair for E2EE
- `rotateMasterKey()` — Rotate the master encryption key

### Data
- `requestConsent(requestor, sourceSilo, targetSilo, categories, scope, reason)` — Request cross-silo access
- `approveConsent(consentId, dataOwner, ttl)` — Approve a consent request
- `checkConsent(consentId)` — Check if consent is valid
- `revokeConsent(consentId)` — Revoke consent
- `createAnonymousId(realId, silo)` — Create an anonymous mapping
- `resolveAnonymousId(anonId)` — Resolve anonymous ID back to real identity
- `removeIdentity(realId)` — Remove all mappings (right to be forgotten)

### Audit
- `log(action, actorId, targetId, silo, details?)` — Log an event
- `verify()` — Verify entire chain integrity
- `query(filters?)` — Query with action/actor/silo filters
- `export()` — Export chain as JSONL

### Access
- `createUser(username, password, role)` — Create a user account
- `authenticate(username, password, portal)` — Authenticate and create session
- `checkPermission(session, permission)` — Check if session has permission
- `verifyMfa(sessionId, code)` — Verify MFA code
- `endSession(sessionId)` — End a session

### Transport
- `tls.configureTLS(mode, certPath, keyPath, caCertPath)` — Configure TLS
- `tls.detectDowngrade(headers)` — Detect TLS downgrade attacks
- `mesh.registerNode(node, scope?)` — Register a node in the mesh
- `mesh.flagNode(source, target, signalType)` — Flag a node for suspicious behavior
- `mesh.processFlags()` — Process flags and quarantine nodes
- `mesh.beginHealing(nodeId, reason)` — Begin healing a quarantined node
- `mesh.completeHealing(nodeId)` — Restore a healed node to active

## Configuration

```typescript
// Developer mode — self-signed certs, 3 nodes max, TLS 1.2
const client = new BedrockClient({ mode: 'developer' });

// Production mode — CA-signed certs, unlimited nodes, TLS 1.3
const client = new BedrockClient({ mode: 'production' });
```

## License

Proprietary. See LICENSE file.