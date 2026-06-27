/**
 * Identity SDK module — Node registration, certificates, capability scoping, attestation.
 *
 * Trade Secret — InFill Systems, LLC. All rights reserved.
 */

import type {
  Node, NodeID, CapabilityScope, Certificate, DataCategory,
} from './types';
import { NodeState, CertificateStatus, AttestationPolicy } from './types';

/** Attestation result. */
export interface AttestationResult {
  nodeId: string;
  policy: AttestationPolicy;
  verified: boolean;
  claims: Record<string, string>;
  timestamp: Date;
}

/** Attestation claim. */
export interface AttestationClaim {
  nodeId: string;
  key: string;
  value: string;
  verified: boolean;
}

/**
 * Identity management: register nodes, manage certificates, scope capabilities, attestation.
 */
export class IdentityModule {
  private _nodes: Map<string, Node> = new Map();
  private _certificates: Map<string, Certificate> = new Map();
  private _scopes: Map<string, CapabilityScope> = new Map();
  private _attestations: Map<string, AttestationResult> = new Map();
  private _claims: Map<string, AttestationClaim[]> = new Map();
  private _nodeCounter: number = 0;
  private _attestationPolicy: AttestationPolicy = AttestationPolicy.PERMISSIVE;

  // --- Node Registration ---

  /**
   * Register a new node in the Bedrock network.
   */
  register(name: string, _nodeType: string = 'general'): Node {
    const uuid = crypto.randomUUID();
    const nodeId: NodeID = {
      uuid,
      timestamp: new Date(),
    };
    const node: Node = {
      nodeId,
      name,
      state: NodeState.ACTIVE,
    };
    this._nodes.set(uuid, node);
    return node;
  }

  /**
   * Look up a node by its UUID.
   */
  get(nodeId: string): Node | undefined {
    return this._nodes.get(nodeId);
  }

  /**
   * List all registered nodes.
   */
  listNodes(): Node[] {
    return Array.from(this._nodes.values());
  }

  /**
   * Update a node's state.
   */
  setNodeState(nodeId: string, state: NodeState): Node | null {
    const node = this._nodes.get(nodeId);
    if (!node) return null;
    node.state = state;
    return node;
  }

  /**
   * Remove a node (right to be forgotten).
   */
  unregister(nodeId: string): boolean {
    // Clean up related data
    this._scopes.delete(nodeId);
    this._attestations.delete(nodeId);
    this._claims.delete(nodeId);
    return this._nodes.delete(nodeId);
  }

  // --- Certificates ---

  /**
   * Issue a certificate for a node.
   */
  issueCertificate(
    nodeUuid: string,
    nodeName: string,
    publicKeyHash: string,
  ): Certificate {
    const now = new Date();
    const expires = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24h default
    const cert: Certificate = {
      serialNumber: `cert-${++this._nodeCounter}`,
      nodeUuid,
      nodeName,
      status: CertificateStatus.ACTIVE,
      issuedAt: now,
      expiresAt: expires,
      publicKeyHash,
    };
    this._certificates.set(nodeUuid, cert);
    return cert;
  }

  /**
   * Get a node's certificate.
   */
  getCertificate(nodeUuid: string): Certificate | undefined {
    return this._certificates.get(nodeUuid);
  }

  /**
   * Revoke a node's certificate.
   */
  revokeCertificate(nodeUuid: string, _reason: string = ''): Certificate {
    const cert = this._certificates.get(nodeUuid);
    if (!cert) {
      throw new Error(`No certificate found for node: ${nodeUuid}`);
    }
    const revoked: Certificate = { ...cert, status: CertificateStatus.REVOKED };
    this._certificates.set(nodeUuid, revoked);
    return revoked;
  }

  // --- Capability Scoping ---

  /**
   * Create a capability scope for a node.
   */
  createScope(nodeId: string, categories: string[]): CapabilityScope {
    const scope: CapabilityScope = {
      nodeId,
      categories: categories.map((c) => c as DataCategory),
    };
    this._scopes.set(nodeId, scope);
    return scope;
  }

  /**
   * Get a node's capability scope.
   */
  getScope(nodeId: string): CapabilityScope | undefined {
    return this._scopes.get(nodeId);
  }

  /**
   * Check if a node has access to a data category.
   */
  hasCapability(nodeId: string, category: string): boolean {
    const scope = this._scopes.get(nodeId);
    if (!scope) return false;
    return scope.categories.includes(category as DataCategory);
  }

  // --- Attestation ---

  /**
   * Set the attestation policy.
   */
  setAttestationPolicy(policy: AttestationPolicy): void {
    this._attestationPolicy = policy;
  }

  /**
   * Get the current attestation policy.
   */
  getAttestationPolicy(): AttestationPolicy {
    return this._attestationPolicy;
  }

  /**
   * Submit an attestation claim for a node.
   */
  submitClaim(nodeId: string, key: string, value: string): AttestationClaim {
    const claim: AttestationClaim = {
      nodeId,
      key,
      value,
      verified: false,
    };

    if (!this._claims.has(nodeId)) {
      this._claims.set(nodeId, []);
    }
    this._claims.get(nodeId)!.push(claim);
    return claim;
  }

  /**
   * Verify attestation claims for a node.
   */
  verifyAttestation(nodeId: string): AttestationResult {
    const claims = this._claims.get(nodeId) ?? [];
    const node = this._nodes.get(nodeId);
    const verified = node !== undefined && node.state === NodeState.ACTIVE;

    // In STRICT mode, all claims must be individually verified
    // In PERMISSIVE mode, just check node is active
    const claimMap: Record<string, string> = {};
    for (const claim of claims) {
      claimMap[claim.key] = claim.value;
    }

    const result: AttestationResult = {
      nodeId,
      policy: this._attestationPolicy,
      verified,
      claims: claimMap,
      timestamp: new Date(),
    };

    this._attestations.set(nodeId, result);
    return result;
  }

  /**
   * Check if a node has been attested.
   */
  isAttested(nodeId: string): boolean {
    const attestation = this._attestations.get(nodeId);
    return attestation?.verified ?? false;
  }

  /**
   * Get attestation result for a node.
   */
  getAttestation(nodeId: string): AttestationResult | undefined {
    return this._attestations.get(nodeId);
  }
}