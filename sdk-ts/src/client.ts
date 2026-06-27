/**
 * BedrockClient — Central entry point for the Bedrock TypeScript SDK.
 *
 * Provides a unified API wrapping all modules with developer-friendly
 * defaults, validation, and error handling.
 *
 * Trade Secret — InFill Systems, LLC. All rights reserved.
 */

import type { BedrockConfig, Node, Certificate, CapabilityScope, KeyPair, ConsentEvent, AuditEntry, Session, TLSConfig as TLSConfigType, HealingResult } from './types';
import { DEFAULT_DEV_CONFIG, DEFAULT_PROD_CONFIG } from './types';
import { IdentityModule } from './identity';
import { EncryptionModule } from './encryption';
import { DataModule } from './data';
import { AuditModule } from './audit';
import { AccessModule } from './access';
import { TransportModule } from './transport';

export class BedrockClient {
  private readonly _config: BedrockConfig;
  private readonly _identityModule: IdentityModule;
  private readonly _encryptionModule: EncryptionModule;
  private readonly _dataModule: DataModule;
  private readonly _auditModule: AuditModule;
  private readonly _accessModule: AccessModule;
  private readonly _transportModule: TransportModule;
  private _initialized: boolean = false;

  constructor(config?: BedrockConfig) {
    this._config = config ?? DEFAULT_DEV_CONFIG;

    this._identityModule = new IdentityModule();
    this._encryptionModule = new EncryptionModule();
    this._dataModule = new DataModule();
    this._auditModule = new AuditModule();
    this._accessModule = new AccessModule();
    this._transportModule = new TransportModule();
  }

  /**
   * Initialize the client. Must be called before encryption operations.
   * Generates the master key and prepares crypto subsystem.
   */
  async init(): Promise<void> {
    if (this._initialized) return;
    await this._encryptionModule.init();
    this._initialized = true;
  }

  /** Current operating mode. */
  get mode(): string {
    return this._config.mode;
  }

  /** Identity management: register nodes, manage certificates, scope capabilities. */
  get identity(): IdentityModule {
    return this._identityModule;
  }

  /** Encryption: field-level encrypt/decrypt, E2EE delivery, key management. */
  get encryption(): EncryptionModule {
    return this._encryptionModule;
  }

  /** Data separation: silo config, consent-gated access, anonymous IDs. */
  get data(): DataModule {
    return this._dataModule;
  }

  /** Audit chain: write events, verify integrity, export for compliance. */
  get audit(): AuditModule {
    return this._auditModule;
  }

  /** Access control: RBAC, sessions, MFA. */
  get access(): AccessModule {
    return this._accessModule;
  }

  /** Transport: TLS config, E2EE messaging, mesh networking. */
  get transport(): TransportModule {
    return this._transportModule;
  }

  /**
   * Verify the entire audit chain integrity.
   */
  async verifyIntegrity(): Promise<boolean> {
    return this._auditModule.verify();
  }
}