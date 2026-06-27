/**
 * Identity SDK module — Node registration, certificates, capability scoping.
 *
 * Trade Secret — InFill Systems, LLC. All rights reserved.
 */

import type {
  Node, NodeID, CapabilityScope, Certificate, DataCategory,
} from './types';
import { NodeState } from './types';

/**
 * Identity management: register nodes, manage certificates, scope capabilities.
 */
export class IdentityModule {
  private _nodes: Map<string, Node> = new Map();
  private _certificates: Map<string, Certificate> = new Map();
  private _nodeCounter: number = 0;

  /**
   * Register a new node in the Bedrock network.
   */
  register(name: string): Node {
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
   * Remove a node (right to be forgotten).
   */
  unregister(nodeId: string): boolean {
    return this._nodes.delete(nodeId);
  }

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
      status: { value: 'active' } as any,
      issuedAt: now,
      expiresAt: expires,
      publicKeyHash,
    };
    this._certificates.set(nodeUuid, cert);
    return cert;
  }

  /**
   * Revoke a node's certificate.
   */
  revokeCertificate(nodeUuid: string, reason: string = ''): Certificate {
    const cert = this._certificates.get(nodeUuid);
    if (!cert) {
      throw new Error(`No certificate found for node: ${nodeUuid}`);
    }
    const revoked: Certificate = { ...cert, status: { value: 'revoked' } as any };
    this._certificates.set(nodeUuid, revoked);
    return revoked;
  }

  /**
   * Create a capability scope for a node.
   */
  createScope(nodeId: string, categories: string[]): CapabilityScope {
    return {
      nodeId,
      categories: categories.map((c) => c as DataCategory),
    };
  }
}