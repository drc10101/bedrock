"""
BedrockClient — Central entry point for the Bedrock SDK.

Provides a unified API wrapping all Core modules with developer-friendly
defaults, validation, and error handling.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

from typing import Optional

from bedrock.config import CoreConfig
from bedrock.identity.node import NodeID, NodeState
from bedrock.identity.registration import NodeRegistry
from bedrock.identity.capabilities import CapabilityScope, DataCategory
from bedrock.identity.attestation import AttestationManager, AttestationPolicy
from bedrock.identity.certificates import CertificateManager, LicenseTier
from bedrock.encryption.engine import FieldEncryptor, E2EEDeliverer, KeyManager
from bedrock.data_separation.consent import ConsentGate
from bedrock.data_separation.silo import SiloManager
from bedrock.data_separation.anonymous_id import IDMappingTable
from bedrock.audit.chain import AuditChain
from bedrock.access_control.controller import AccessController, Role, Portal
from bedrock.transport.security import TransportLayer
from bedrock.mesh.healing import SelfHealingMesh

from bedrock_sdk.identity import IdentityModule
from bedrock_sdk.encryption import EncryptionModule
from bedrock_sdk.data import DataModule
from bedrock_sdk.audit import AuditModule
from bedrock_sdk.access import AccessModule
from bedrock_sdk.transport import TransportModule


class BedrockClient:
    """Unified Bedrock SDK client.

    Wraps all Core modules behind a clean, developer-friendly API.
    Initialize with a license mode and the client configures sensible
    defaults for development or production use.

    Usage::

        # Developer mode (3 local nodes, self-signed certs)
        client = BedrockClient(mode="developer")

        # Production mode (CA-signed certs, full enforcement)
        client = BedrockClient(mode="production")

        # Custom configuration
        config = CoreConfig(...)
        client = BedrockClient(config=config)
    """

    def __init__(
        self,
        mode: str = "developer",
        config: Optional[CoreConfig] = None,
        license_key: str = "",
    ):
        """Initialize the Bedrock SDK client.

        Args:
            mode: "developer" or "production". Developer mode allows
                3 local nodes with self-signed certificates. Production
                mode requires CA-signed certificates and enforces all
                security policies.
            config: Optional CoreConfig for advanced configuration.
                If provided, mode is derived from config.licensing.tier.
            license_key: License key for production mode.
        """
        if config is not None:
            self._config = config
            self._mode = config.licensing.tier
        else:
            self._config = CoreConfig()
            self._mode = mode
            self._config.licensing.tier = mode

        self._license_key = license_key

        # Initialize Core components
        self._registry = NodeRegistry()
        self._key_manager = KeyManager()
        self._master_key = self._key_manager.generate_master_key()
        self._encryptor = FieldEncryptor(
            key_manager=self._key_manager,
            master_key=self._master_key,
        )
        self._e2ee = E2EEDeliverer()
        self._consent_gate = ConsentGate()
        self._audit_chain = AuditChain()
        self._access_controller = AccessController()
        self._transport = TransportLayer()
        self._mesh = SelfHealingMesh()
        self._silo_manager = SiloManager()
        self._id_table = IDMappingTable()

        # Certificate manager based on mode
        if self._mode == "production":
            self._cert_manager = CertificateManager(
                license_tier=LicenseTier.BUSINESS
            )
            self._attestation = AttestationManager(
                policy=AttestationPolicy.STRICT
            )
        else:
            self._cert_manager = CertificateManager(
                license_tier=LicenseTier.DEVELOPER
            )
            self._attestation = AttestationManager(
                policy=AttestationPolicy.PERMISSIVE
            )

        # Initialize SDK modules
        self._identity = IdentityModule(
            registry=self._registry,
            cert_manager=self._cert_manager,
            attestation=self._attestation,
            mode=self._mode,
        )
        self._encryption = EncryptionModule(
            encryptor=self._encryptor,
            e2ee=self._e2ee,
            key_manager=self._key_manager,
            master_key=self._master_key,
        )
        self._data = DataModule(
            consent_gate=self._consent_gate,
            id_table=self._id_table,
        )
        self._audit = AuditModule(
            chain=self._audit_chain,
        )
        self._access = AccessModule(
            controller=self._access_controller,
        )
        self._transport_module = TransportModule(
            transport=self._transport,
            mesh=self._mesh,
        )

    @property
    def mode(self) -> str:
        """Current operating mode: 'developer' or 'production'."""
        return self._mode

    @property
    def identity(self) -> "IdentityModule":
        """Identity management: register nodes, manage certificates, scope capabilities."""
        return self._identity

    @property
    def encryption(self) -> "EncryptionModule":
        """Encryption: field-level encrypt/decrypt, E2EE delivery, key management."""
        return self._encryption

    @property
    def data(self) -> "DataModule":
        """Data separation: silo config, consent-gated access, anonymous IDs."""
        return self._data

    @property
    def audit(self) -> "AuditModule":
        """Audit chain: write events, verify integrity, export for compliance."""
        return self._audit

    @property
    def access(self) -> "AccessModule":
        """Access control: RBAC, sessions, MFA."""
        return self._access

    @property
    def transport(self) -> "TransportModule":
        """Transport: TLS config, E2EE messaging, mesh networking."""
        return self._transport_module

    def verify_integrity(self) -> bool:
        """Verify the entire audit chain integrity.

        Returns:
            True if all chain hashes are valid and unmodified.
        """
        return self._audit_chain.verify()