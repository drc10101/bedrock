/**
 * Transport SDK module — TLS config, E2EE messaging, mesh networking.
 *
 * Trade Secret — InFill Systems, LLC. All rights reserved.
 */

import type {
  Node, TLSConfig, HealingResult, CapabilityScope,
} from './types';
import {
  NodeState,
  TLSVersion,
  DowngradeStatus,
  RateLimitResult,
  SignalType,
  DataCategory,
} from './types';

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

interface TLSConfigInternal {
  certPath: string;
  keyPath: string;
  caCertPath: string;
  minVersion: TLSVersion;
  verifyClient: boolean;
  isDeveloperMode: boolean;
}

/**
 * TLS configuration and downgrade detection.
 */
export class TransportTLS {
  private _config: TLSConfigInternal | null = null;

  /**
   * Configure TLS.
   */
  configureTLS(
    mode: 'developer' | 'production' = 'developer',
    certPath: string = '',
    keyPath: string = '',
    caCertPath: string = '',
  ): TLSConfigInternal {
    const isDev = mode === 'developer';
    this._config = {
      certPath,
      keyPath,
      caCertPath,
      minVersion: isDev ? TLSVersion.TLS_1_2 : TLSVersion.TLS_1_3,
      verifyClient: !isDev,
      isDeveloperMode: isDev,
    };
    return this._config;
  }

  /**
   * Detect TLS downgrade attacks from request headers.
   * Use lowercase header keys.
   */
  detectDowngrade(headers: Record<string, string>): DowngradeStatus {
    if (!this._config) {
      throw new Error('TLS not configured. Call configureTLS() first.');
    }

    const proto = headers['x-forwarded-proto'] ?? '';
    const tlsVersion = headers['x-tls-version'] ?? '';

    // Plain HTTP = downgrade
    if (proto === 'http') {
      return DowngradeStatus.DOWNGRADE;
    }

    // TLS version below minimum = downgrade
    if (tlsVersion) {
      const versionNum = parseFloat(tlsVersion);
      const minNum = parseFloat(this._config.minVersion);
      if (versionNum < minNum) {
        return DowngradeStatus.DOWNGRADE;
      }
    }

    // HTTPS with valid TLS version = secure
    if (proto === 'https' || tlsVersion) {
      return DowngradeStatus.SECURE;
    }

    return DowngradeStatus.UNKNOWN;
  }

  /**
   * Check rate limit for a node or IP.
   */
  checkRateLimit(key: string): RateLimitResult {
    // Simplified — production would use a sliding window counter
    return RateLimitResult.ALLOWED;
  }
}

// ---------------------------------------------------------------------------
// Mesh
// ---------------------------------------------------------------------------

interface MeshNode {
  node: Node;
  scope: CapabilityScope | null;
  neighbors: Set<string>;
}

/**
 * Self-healing mesh for node isolation and rerouting.
 */
export class MeshModule {
  private _nodes: Map<string, MeshNode> = new Map();
  private _flags: Map<string, Array<{ sourceId: string; signalType: SignalType }>> = new Map();
  private _consensusThreshold: number = 2;

  /**
   * Register a node in the mesh.
   */
  registerNode(node: Node, scope?: CapabilityScope): void {
    this._nodes.set(node.nodeId.uuid, {
      node,
      scope: scope ?? null,
      neighbors: new Set(),
    });
  }

  /**
   * Add a neighbor connection between two nodes.
   */
  addNeighbor(nodeId: string, neighborId: string): void {
    const meshNode = this._nodes.get(nodeId);
    if (meshNode) {
      meshNode.neighbors.add(neighborId);
    }
  }

  /**
   * Flag a node for suspicious behavior.
   */
  flagNode(sourceId: string, targetId: string, signalType: string, details?: Record<string, unknown>): void {
    if (!this._flags.has(targetId)) {
      this._flags.set(targetId, []);
    }
    this._flags.get(targetId)!.push({
      sourceId,
      signalType: signalType as SignalType,
    });
  }

  /**
   * Check if consensus threshold is reached for a node.
   */
  checkConsensus(nodeId: string): boolean {
    const flags = this._flags.get(nodeId) ?? [];
    // Count unique sources
    const sources = new Set(flags.map((f) => f.sourceId));
    return sources.size >= this._consensusThreshold;
  }

  /**
   * Process pending flags and transition node states.
   * Returns list of node IDs that were quarantined.
   */
  processFlags(): string[] {
    const quarantined: string[] = [];

    for (const [nodeId, flags] of this._flags.entries()) {
      const sources = new Set(flags.map((f) => f.sourceId));
      if (sources.size < this._consensusThreshold) continue;

      const meshNode = this._nodes.get(nodeId);
      if (!meshNode) continue;

      // ACTIVE → SUSPECT → QUARANTINED
      const currentState = meshNode.node.state;
      if (currentState === NodeState.ACTIVE) {
        meshNode.node = { ...meshNode.node, state: NodeState.SUSPECT };
      } else if (currentState === NodeState.SUSPECT) {
        meshNode.node = { ...meshNode.node, state: NodeState.QUARANTINED };
        quarantined.push(nodeId);
      }
    }

    return quarantined;
  }

  /**
   * Begin healing a quarantined node.
   */
  beginHealing(nodeId: string, reason: string = ''): HealingResult {
    const meshNode = this._nodes.get(nodeId);
    if (!meshNode) {
      return { success: false, reason: 'Node not found', newState: NodeState.QUARANTINED };
    }

    if (meshNode.node.state !== NodeState.QUARANTINED) {
      return {
        success: false,
        reason: `Node is in ${meshNode.node.state} state, not quarantined`,
        newState: meshNode.node.state,
      };
    }

    meshNode.node = { ...meshNode.node, state: NodeState.HEALING };
    return { success: true, reason: 'Healing initiated', newState: NodeState.HEALING };
  }

  /**
   * Complete healing and restore a node to active.
   */
  completeHealing(nodeId: string): HealingResult {
    const meshNode = this._nodes.get(nodeId);
    if (!meshNode) {
      return { success: false, reason: 'Node not found', newState: NodeState.QUARANTINED };
    }

    if (meshNode.node.state !== NodeState.HEALING) {
      return {
        success: false,
        reason: `Node is in ${meshNode.node.state} state, not healing`,
        newState: meshNode.node.state,
      };
    }

    meshNode.node = { ...meshNode.node, state: NodeState.ACTIVE };
    this._flags.delete(nodeId); // Clear flags on successful healing
    return { success: true, reason: 'Healing complete', newState: NodeState.ACTIVE };
  }
}

// ---------------------------------------------------------------------------
// Transport Module (combined)
// ---------------------------------------------------------------------------

/**
 * Transport: TLS config, downgrade detection, mesh networking.
 */
export class TransportModule {
  public readonly tls: TransportTLS;
  public readonly mesh: MeshModule;

  constructor() {
    this.tls = new TransportTLS();
    this.mesh = new MeshModule();
  }
}