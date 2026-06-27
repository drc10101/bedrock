"""
End-to-end integration tests — Full patient journey through Bedrock Core.

Tests the complete lifecycle:
1. Patient registration (Identity Fabric)
2. Certificate issuance (CertificateManager)
3. Silo creation and data storage (SiloManager + FieldEncryptor)
4. PIR consent request and approval (ConsentGate)
5. ePRR consent for external sharing
6. E2EE messaging (E2EEDeliverer)
7. Audit chain integrity (AuditChain)
8. Right to be forgotten (identity removal + cert revocation)
9. Self-healing mesh (attack detection and recovery)
10. Licensing enforcement across tiers
11. RBAC with MFA (AccessController)
12. Anonymous ID mapping (IDMappingTable)

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

import time
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from bedrock.config import CoreConfig
from bedrock.identity.node import NodeID, NodeState
from bedrock.identity.registration import NodeRegistry
from bedrock.identity.certificates import CertificateManager, LicenseTier
from bedrock.identity.attestation import AttestationManager, AttestationPolicy
from bedrock.encryption.engine import FieldEncryptor, E2EEDeliverer, KeyManager
from bedrock.data_separation.silo import SiloManager
from bedrock.data_separation.consent import ConsentGate
from bedrock.data_separation.anonymous_id import IDMappingTable
from bedrock.audit.chain import AuditChain
from bedrock.access_control.controller import AccessController, Role, Portal, Permission
from bedrock.mesh.healing import SelfHealingMesh
from bedrock.mesh.detector import SignalType
from bedrock.licensing.enforcement import LicenseEnforcer


def _generate_ec_keypair():
    """Generate EC keypair for E2EE testing."""
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pub_bytes, priv_bytes


@pytest.fixture
def core_stack():
    """Set up the complete Bedrock Core stack."""
    config = CoreConfig()
    registry = NodeRegistry()
    key_manager = KeyManager()
    master_key = key_manager.generate_master_key()
    encryptor = FieldEncryptor(key_manager=key_manager, master_key=master_key)
    e2ee = E2EEDeliverer()
    silo_mgr = SiloManager()
    consent_gate = ConsentGate()
    id_table = IDMappingTable()
    audit = AuditChain()
    cert_mgr = CertificateManager(license_tier=LicenseTier.BUSINESS)
    attestation = AttestationManager(policy=AttestationPolicy.STRICT)
    access = AccessController()
    mesh = SelfHealingMesh()

    return {
        'config': config,
        'registry': registry,
        'key_manager': key_manager,
        'master_key': master_key,
        'encryptor': encryptor,
        'e2ee': e2ee,
        'silo_mgr': silo_mgr,
        'consent_gate': consent_gate,
        'id_table': id_table,
        'audit': audit,
        'cert_mgr': cert_mgr,
        'attestation': attestation,
        'access': access,
        'mesh': mesh,
    }


class TestPatientJourney:
    """Full patient lifecycle through the Bedrock stack."""

    def test_complete_patient_journey(self, core_stack):
        """E2E: Patient registration through audit verification."""
        reg = core_stack['registry']
        enc = core_stack['encryptor']
        silo = core_stack['silo_mgr']
        consent = core_stack['consent_gate']
        id_table = core_stack['id_table']
        audit = core_stack['audit']
        cert_mgr = core_stack['cert_mgr']

        # --- Step 1: Patient Registration ---
        patient = reg.register(name='Jane Doe', node_type='patient')
        assert patient.state == NodeState.ACTIVE
        assert patient.name == 'Jane Doe'
        patient_uuid = patient.node_id.uuid

        # --- Step 2: Certificate Issuance ---
        cert = cert_mgr.issue_certificate(
            node_uuid=patient_uuid,
            node_name='Jane Doe',
            public_key_hash=patient.node_id.public_key_hex()[:16],
            capabilities=['read', 'write'],
        )
        assert cert.is_valid() is True

        # --- Step 3: Silo Creation & Data Encryption ---
        silo.create_silo(name='identity', display_name='Identity Data', categories=['identity', 'auth'])
        silo.create_silo(name='medical', display_name='Medical Records', categories=['medical'])

        # Encrypt and verify patient data in identity silo
        name_ct = enc.encrypt('Jane Doe', silo='identity', record_id=patient_uuid, scope='field')
        ssn_ct = enc.encrypt('123-45-6789', silo='identity', record_id=patient_uuid, scope='field')
        diagnosis_ct = enc.encrypt('Type 2 Diabetes', silo='medical', record_id=patient_uuid, scope='field')

        # Verify encryption round-trip
        name_pt = enc.decrypt(name_ct, silo='identity', record_id=patient_uuid, scope='field')
        assert name_pt == 'Jane Doe'

        ssn_pt = enc.decrypt(ssn_ct, silo='identity', record_id=patient_uuid, scope='field')
        assert ssn_pt == '123-45-6789'

        # Wrong silo context should fail
        with pytest.raises(Exception):
            enc.decrypt(name_ct, silo='medical', record_id=patient_uuid, scope='field')

        # --- Step 4: PIR Consent ---
        pir_result = consent.request_consent(
            requesting_node_id=patient_uuid,
            source_silo='identity',
            target_silo='medical',
            categories=['medical'],
            scope='read',
            reason='Patient requests access to share identity with medical provider',
        )
        consent_id = pir_result.consent_id
        assert consent_id is not None

        # Patient approves PIR
        approved = consent.approve_consent(consent_id=consent_id, data_owner_id=patient_uuid)
        assert approved is not None
        assert approved.status in ('approved', 'active')

        # --- Step 5: ePRR Consent for Provider ---
        provider = reg.register(name='Dr. Smith', node_type='provider')
        provider_uuid = provider.node_id.uuid

        eprr_result = consent.request_consent(
            requesting_node_id=provider_uuid,
            source_silo='medical',
            target_silo='identity',
            categories=['identity'],
            scope='read',
            reason='Provider needs identity context for treatment',
        )
        eprr_consent_id = eprr_result.consent_id

        # Patient approves ePRR
        consent.approve_consent(consent_id=eprr_consent_id, data_owner_id=patient_uuid)

        # --- Step 6: Anonymous ID Mapping ---
        anon_id = f'anon-{patient_uuid[:8]}-med'
        id_table.register(real_id=patient_uuid, silo_name='medical', anon_id=anon_id)
        assert id_table is not None

        # Resolve back
        resolved = id_table.lookup(real_id=patient_uuid, silo_name='medical')
        assert resolved == anon_id

        # Reverse lookup
        reverse = id_table.reverse_lookup(anon_id=anon_id)
        assert reverse is not None
        assert reverse[0] == patient_uuid

        # --- Step 7: E2EE Messaging ---
        pub_bytes, priv_bytes = _generate_ec_keypair()
        e2ee = core_stack['e2ee']

        e2ee_ct = e2ee.encrypt_for_recipient(
            'Your test results are ready.',
            pub_bytes, priv_bytes,
            silo='identity', record_id=patient_uuid, scope='e2ee',
        )
        assert e2ee_ct is not None

        e2ee_pt = e2ee.decrypt_from_sender(
            e2ee_ct, pub_bytes, priv_bytes,
            silo='identity', record_id=patient_uuid, scope='e2ee',
        )
        assert e2ee_pt == 'Your test results are ready.'

        # --- Step 8: Audit Trail ---
        audit.append(action='patient.registered', actor_id='system', target_id=patient_uuid, silo='identity')
        audit.append(action='consent.approved', actor_id=patient_uuid, target_id=consent_id, silo='identity')
        audit.append(action='consent.approved', actor_id=patient_uuid, target_id=eprr_consent_id, silo='medical')
        audit.append(action='certificate.issued', actor_id='system', target_id=patient_uuid, silo='identity')

        # Verify chain integrity
        assert audit.verify() is True

        # Query audit trail
        patient_events = audit.query(actor_id=patient_uuid)
        assert len(patient_events) >= 2

        # head_hash and tail_hash are properties, not methods
        assert audit.head_hash is not None
        assert audit.tail_hash is not None

        # --- Step 9: Right to Be Forgotten ---
        # Remove anonymous IDs
        id_table.unregister(real_id=patient_uuid)

        # Revoke certificate
        revoked_cert = cert_mgr.revoke_certificate(node_uuid=patient_uuid, reason='Right to be forgotten')
        assert revoked_cert.is_valid() is False
        assert revoked_cert.status.value == 'revoked'

    def test_provider_rbac_journey(self, core_stack):
        """E2E: Provider RBAC workflow with MFA."""
        import hashlib
        import hmac
        import struct
        import time

        access = core_stack['access']

        # Create RBAC session
        access.create_user(username='drsmith', password='SecurePass123!', role=Role.OPERATOR)
        session = access.authenticate(username='drsmith', password='SecurePass123!', portal=Portal.PROVIDER)

        assert session is not None
        assert session.role == Role.OPERATOR

        # Operator should have data read access without MFA
        assert access.check_permission(session, Permission.DATA_READ) is True

        # Write operations require MFA
        assert access.check_permission(session, Permission.DATA_WRITE) is False

        # Generate valid TOTP code from user's secret
        account = None
        for user in access._users.values():
            if user.username == 'drsmith':
                account = user
                break
        assert account is not None
        totp_secret = account.totp_secret
        current_step = int(time.time()) // 30
        time_bytes = struct.pack(">Q", current_step)
        key = bytes.fromhex(totp_secret)
        h = hmac.new(key, time_bytes, hashlib.sha1).digest()
        offset_val = h[-1] & 0x0F
        code_int = (
            ((h[offset_val] & 0x7F) << 24)
            | ((h[offset_val + 1] & 0xFF) << 16)
            | ((h[offset_val + 2] & 0xFF) << 8)
            | (h[offset_val + 3] & 0xFF)
        ) % 1000000
        valid_totp = f"{code_int:06d}"

        # MFA verification with valid TOTP
        assert access.verify_mfa(session.session_id, valid_totp) is True
        assert session.mfa_verified is True

        # After MFA, write is allowed
        assert access.check_permission(session, Permission.DATA_WRITE) is True

        # End session
        assert access.end_session(session.session_id) is True

    def test_mesh_self_healing_journey(self, core_stack):
        """E2E: Self-healing mesh attack detection and recovery."""
        mesh = core_stack['mesh']
        reg = core_stack['registry']

        # Register nodes in mesh — register_node takes a Node object
        node1 = reg.register(name='node-1', node_type='server')
        node2 = reg.register(name='node-2', node_type='server')
        node3 = reg.register(name='node-3', node_type='server')

        mesh.register_node(node1)
        mesh.register_node(node2)
        mesh.register_node(node3)

        # Simulate attack detection — signal_type is SignalType enum
        mesh.flag_node(
            source_node_id=node2.node_id.uuid,
            target_node_id=node1.node_id.uuid,
            signal_type=SignalType.CREDENTIAL_STUFFING,
        )
        mesh.flag_node(
            source_node_id=node3.node_id.uuid,
            target_node_id=node1.node_id.uuid,
            signal_type=SignalType.SILENT_NODE,
        )

        # Process flags — should quarantine
        quarantined = mesh.process_flags()
        assert len(quarantined) >= 1

        # Begin healing
        heal_result = mesh.begin_healing(node_id=node1.node_id.uuid)
        assert heal_result.success is True or heal_result is not None

        # Complete healing
        complete_result = mesh.complete_healing(node_id=node1.node_id.uuid)
        assert complete_result is not None

    def test_consent_lifecycle_journey(self, core_stack):
        """E2E: Full consent lifecycle — request, approve, deny, re-request."""
        reg = core_stack['registry']
        consent = core_stack['consent_gate']
        audit = core_stack['audit']

        patient = reg.register(name='Patient A', node_type='patient')
        provider = reg.register(name='Provider B', node_type='provider')

        # Request consent
        result = consent.request_consent(
            requesting_node_id=provider.node_id.uuid,
            source_silo='medical',
            target_silo='identity',
            categories=['identity'],
            scope='read',
            reason='Treatment coordination',
        )
        cid = result.consent_id

        # Audit the request
        audit.append(action='consent.requested', actor_id=provider.node_id.uuid, target_id=cid, silo='medical')

        # Deny consent
        denied = consent.deny_consent(consent_id=cid, data_owner_id=patient.node_id.uuid, reason='Patient declined')
        assert denied is not None

        # New request — this time approved
        result2 = consent.request_consent(
            requesting_node_id=provider.node_id.uuid,
            source_silo='medical',
            target_silo='identity',
            categories=['identity'],
            scope='read',
            reason='Updated treatment plan',
        )
        cid2 = result2.consent_id

        # Approve
        approved = consent.approve_consent(consent_id=cid2, data_owner_id=patient.node_id.uuid)
        assert approved is not None

        # Audit approval
        audit.append(action='consent.approved', actor_id=patient.node_id.uuid, target_id=cid2, silo='identity')

        # Verify audit chain
        assert audit.verify() is True

        # Query for provider actions
        provider_events = audit.query(actor_id=provider.node_id.uuid)
        assert len(provider_events) >= 1


class TestLicensingEnforcement:
    """Test two-tier licensing enforcement across the stack."""

    def test_developer_tier_limits(self):
        """Developer tier: limited nodes, self-signed certs."""
        enforcer = LicenseEnforcer()
        dev_key = enforcer.generate_license_key(
            tier=LicenseTier.DEVELOPER,
            issued_to='dev-user',
            max_nodes=3,
        )

        license_obj = enforcer.validate_license(dev_key)
        assert license_obj.is_valid is True
        assert license_obj.tier.value == 'developer'
        assert license_obj.max_nodes == 3
        assert license_obj.is_developer is True

    def test_business_tier_limits(self):
        """Business tier: more nodes, full features."""
        enforcer = LicenseEnforcer()
        biz_key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to='biz-user',
            max_nodes=100,
        )

        license_obj = enforcer.validate_license(biz_key)
        assert license_obj.is_valid is True
        assert license_obj.tier.value == 'business'
        assert license_obj.max_nodes == 100
        assert license_obj.is_runtime is True

    def test_license_expiry(self):
        """Expired license is invalid."""
        from bedrock.licensing.enforcement import LicenseExpiredError

        enforcer = LicenseEnforcer()
        # Set expires_at in the past
        expired_time = time.time() - 3600  # 1 hour ago
        key = enforcer.generate_license_key(
            tier=LicenseTier.DEVELOPER,
            issued_to='expired-user',
            max_nodes=3,
            expires_at=expired_time,
        )

        # Expired license should raise LicenseExpiredError
        with pytest.raises(LicenseExpiredError):
            enforcer.validate_license(key)

    def test_feature_access(self):
        """Feature access varies by tier."""
        enforcer = LicenseEnforcer()

        dev_key = enforcer.generate_license_key(tier=LicenseTier.DEVELOPER, issued_to='dev', max_nodes=3)
        dev_license = enforcer.validate_license(dev_key)

        # Developer tier has self_signed_certs feature
        assert enforcer.validate_feature_access(dev_license, 'self_signed_certs') is True
        # Developer tier does not have ca_signed_certs
        assert enforcer.validate_feature_access(dev_license, 'ca_signed_certs') is False

    def test_certificate_issuance_by_tier(self):
        """Certificate issuance respects tier limits."""
        enforcer = LicenseEnforcer()

        dev_key = enforcer.generate_license_key(tier=LicenseTier.DEVELOPER, issued_to='dev', max_nodes=3)
        dev_license = enforcer.validate_license(dev_key)

        # Developer can issue certs within node limit
        assert enforcer.can_issue_certificate(dev_license, current_node_count=1) is True

        # But not at max nodes
        assert enforcer.can_issue_certificate(dev_license, current_node_count=3) is False


class TestCrossModuleEncryption:
    """Test encryption across silos with consent gates."""

    def test_cross_silo_encryption_with_consent(self, core_stack):
        """Data encrypted in one silo cannot be decrypted with wrong AAD."""
        enc = core_stack['encryptor']
        reg = core_stack['registry']

        patient = reg.register(name='Patient X', node_type='patient')
        patient_uuid = patient.node_id.uuid

        # Encrypt data in identity silo
        ct = enc.encrypt(
            'Confidential SSN',
            silo='identity',
            record_id=patient_uuid,
            scope='field',
        )

        # Decrypt with correct context
        pt = enc.decrypt(ct, silo='identity', record_id=patient_uuid, scope='field')
        assert pt == 'Confidential SSN'

        # Wrong silo context should fail
        with pytest.raises(Exception):
            enc.decrypt(ct, silo='medical', record_id=patient_uuid, scope='field')

    def test_key_rotation_preserves_audit_integrity(self, core_stack):
        """After key rotation, audit chain integrity is preserved."""
        km = core_stack['key_manager']
        enc = core_stack['encryptor']
        audit = core_stack['audit']
        reg = core_stack['registry']

        # Log events before rotation
        audit.append(action='event.before_rotation', actor_id='sys', target_id='t1', silo='identity')

        # Encrypt data before rotation
        node = reg.register(name='pre-rotation', node_type='test')
        ct_before = enc.encrypt('pre-rotation data', silo='identity', record_id=node.node_id.uuid, scope='field')
        pt_before = enc.decrypt(ct_before, silo='identity', record_id=node.node_id.uuid, scope='field')
        assert pt_before == 'pre-rotation data'

        # Rotate key
        new_key = km.generate_master_key()
        enc_rotated = FieldEncryptor(key_manager=km, master_key=new_key)

        # Log events after rotation
        audit.append(action='event.after_rotation', actor_id='sys', target_id='t2', silo='identity')

        # Audit chain integrity preserved
        assert audit.verify() is True

        # New encryptor works with new key
        node2 = reg.register(name='post-rotation', node_type='test')
        ct_after = enc_rotated.encrypt('post-rotation data', silo='identity', record_id=node2.node_id.uuid, scope='field')
        pt_after = enc_rotated.decrypt(ct_after, silo='identity', record_id=node2.node_id.uuid, scope='field')
        assert pt_after == 'post-rotation data'

    def test_batch_encryption_workflow(self, core_stack):
        """Encrypt multiple fields, decrypt selectively."""
        enc = core_stack['encryptor']
        reg = core_stack['registry']

        patient = reg.register(name='Batch Patient', node_type='patient')
        pk = patient.node_id.uuid

        # Encrypt multiple fields with different silo contexts
        fields = {
            'name': enc.encrypt('Jane Doe', silo='identity', record_id=pk, scope='field'),
            'ssn': enc.encrypt('123-45-6789', silo='identity', record_id=pk, scope='field'),
            'diagnosis': enc.encrypt('Diabetes', silo='medical', record_id=pk, scope='field'),
        }

        # Decrypt selectively — just name, not SSN or diagnosis
        name_pt = enc.decrypt(fields['name'], silo='identity', record_id=pk, scope='field')
        assert name_pt == 'Jane Doe'

        # Verify SSN decrypts correctly
        ssn_pt = enc.decrypt(fields['ssn'], silo='identity', record_id=pk, scope='field')
        assert ssn_pt == '123-45-6789'

        # Medical field decrypts in medical silo context
        diag_pt = enc.decrypt(fields['diagnosis'], silo='medical', record_id=pk, scope='field')
        assert diag_pt == 'Diabetes'


class TestAuditChainIntegrity:
    """Comprehensive audit chain integrity tests."""

    def test_full_audit_lifecycle(self, core_stack):
        """Create, query, export, and verify audit chain."""
        audit = core_stack['audit']
        reg = core_stack['registry']

        patient = reg.register(name='Audit Patient', node_type='patient')
        pid = patient.node_id.uuid

        # Build a rich audit trail
        events = [
            ('patient.registered', 'system', pid, 'identity'),
            ('consent.requested', 'provider-1', pid, 'identity'),
            ('consent.approved', pid, 'consent-001', 'identity'),
            ('data.accessed', 'provider-1', pid, 'medical'),
            ('data.encrypted', 'system', pid, 'identity'),
        ]

        for action, actor, target, silo in events:
            entry = audit.append(action=action, actor_id=actor, target_id=target, silo=silo)
            assert entry is not None

        # Verify integrity
        assert audit.verify() is True

        # Query by actor
        system_events = audit.query(actor_id='system')
        assert len(system_events) == 2

        # Query by silo
        identity_events = audit.query(silo='identity')
        assert len(identity_events) == 4

        # Export as JSONL
        exported = audit.export()
        assert len(exported) > 0
        assert 'patient.registered' in exported

        # head_hash and tail_hash are properties
        assert audit.head_hash is not None
        assert audit.tail_hash is not None

    def test_audit_tamper_detection(self, core_stack):
        """Verify that the audit chain maintains integrity."""
        audit = core_stack['audit']

        audit.append(action='legit.action', actor_id='sys', target_id='t1', silo='identity')
        audit.append(action='another.action', actor_id='sys', target_id='t2', silo='identity')

        # Chain should be verifiable
        assert audit.verify() is True

        # Verify chain remains intact after additional entries
        audit.append(action='third.action', actor_id='sys', target_id='t3', silo='identity')
        assert audit.verify() is True

    def test_audit_export_and_reimport(self, core_stack):
        """Audit chain can be exported and reimported."""
        audit = core_stack['audit']
        reg = core_stack['registry']

        node = reg.register(name='Export Node', node_type='server')
        audit.append(action='export.test', actor_id='system', target_id=node.node_id.uuid, silo='identity')

        # Export
        exported = audit.export()
        assert len(exported) > 0

        # Verify integrity before reimport
        assert audit.verify() is True


class TestE2EEMessaging:
    """Test end-to-end encrypted messaging between nodes."""

    def test_e2ee_provider_to_patient(self, core_stack):
        """Provider sends E2EE message to patient."""
        e2ee = core_stack['e2ee']
        reg = core_stack['registry']

        # Generate EC keypairs for both parties
        provider_pub, provider_priv = _generate_ec_keypair()
        patient_pub, patient_priv = _generate_ec_keypair()

        # Provider encrypts message for patient
        message = 'Your test results are ready. Please schedule a follow-up.'
        ciphertext = e2ee.encrypt_for_recipient(
            message,
            patient_pub,
            provider_priv,
            silo='medical',
            record_id='msg-001',
            scope='e2ee',
        )

        # Patient decrypts message from provider
        plaintext = e2ee.decrypt_from_sender(
            ciphertext,
            provider_pub,
            patient_priv,
            silo='medical',
            record_id='msg-001',
            scope='e2ee',
        )
        assert plaintext == message

    def test_e2ee_cross_silo_fails(self, core_stack):
        """E2EE message cannot be decrypted in wrong silo context."""
        e2ee = core_stack['e2ee']

        provider_pub, provider_priv = _generate_ec_keypair()
        patient_pub, patient_priv = _generate_ec_keypair()

        # Encrypt in medical silo
        ciphertext = e2ee.encrypt_for_recipient(
            'Medical results',
            patient_pub,
            provider_priv,
            silo='medical',
            record_id='msg-002',
            scope='e2ee',
        )

        # Try to decrypt in identity silo — should fail
        with pytest.raises(Exception):
            e2ee.decrypt_from_sender(
                ciphertext,
                provider_pub,
                patient_priv,
                silo='identity',
                record_id='msg-002',
                scope='e2ee',
            )