"""Tests for Data Separation Layer — silos, anonymous IDs, consent gating."""

import pytest
from datetime import datetime, timezone, timedelta

from bedrock.data_separation.silo import Silo, SiloManager
from bedrock.data_separation.anonymous_id import AnonymousID, IDMappingTable
from bedrock.data_separation.consent import ConsentGate, ConsentEvent, ConsentStatus


class TestSilo:
    """Test Silo dataclass."""

    def test_silo_creation(self):
        silo = Silo(
            name="medical",
            display_name="Medical Records",
            hkdf_info="bedrock:silo:medical:v1",
            categories=["diagnosis", "prescriptions", "lab_results"],
            description="Protected health information",
        )
        assert silo.name == "medical"
        assert silo.encrypted is True
        assert silo.has_category("diagnosis") is True
        assert silo.has_category("bank_account") is False

    def test_silo_derive_key_info(self):
        silo = Silo(
            name="identity",
            display_name="Personal Information",
            hkdf_info="bedrock:silo:identity:v1",
        )
        assert silo.derive_key_info() == "bedrock:silo:identity:v1"

    def test_silo_default_values(self):
        silo = Silo(name="auth", display_name="Authentication", hkdf_info="bedrock:silo:auth:v1")
        assert silo.encrypted is True
        assert silo.categories == []
        assert silo.key_version == 1
        assert isinstance(silo.created_at, datetime)


class TestSiloManager:
    """Test SiloManager CRUD operations."""

    def setup_method(self):
        self.mgr = SiloManager()

    def test_create_silo(self):
        silo = self.mgr.create_silo(
            name="medical",
            display_name="Medical Records",
            categories=["diagnosis", "prescriptions"],
            description="Health data",
        )
        assert silo.name == "medical"
        assert silo.hkdf_info == "bedrock:silo:medical:v1"
        assert "diagnosis" in silo.categories

    def test_create_duplicate_silo_raises(self):
        self.mgr.create_silo(name="medical", display_name="Medical Records")
        with pytest.raises(ValueError, match="already exists"):
            self.mgr.create_silo(name="medical", display_name="Medical Records v2")

    def test_get_silo(self):
        self.mgr.create_silo(name="identity", display_name="PII")
        silo = self.mgr.get_silo("identity")
        assert silo is not None
        assert silo.name == "identity"

    def test_get_nonexistent_silo(self):
        assert self.mgr.get_silo("nonexistent") is None

    def test_list_silos(self):
        self.mgr.create_silo(name="medical", display_name="Medical")
        self.mgr.create_silo(name="identity", display_name="PII")
        self.mgr.create_silo(name="auth", display_name="Auth")
        silos = self.mgr.list_silos()
        assert len(silos) == 3
        names = {s.name for s in silos}
        assert names == {"medical", "identity", "auth"}

    def test_update_silo(self):
        self.mgr.create_silo(name="medical", display_name="Medical Records")
        updated = self.mgr.update_silo(
            name="medical",
            display_name="Protected Health Information",
            description="Updated description",
        )
        assert updated.display_name == "Protected Health Information"
        assert updated.description == "Updated description"

    def test_update_nonexistent_silo_raises(self):
        with pytest.raises(KeyError, match="not found"):
            self.mgr.update_silo(name="nonexistent", display_name="Nope")

    def test_delete_silo(self):
        self.mgr.create_silo(name="temp", display_name="Temporary")
        assert self.mgr.silo_exists("temp") is True
        self.mgr.delete_silo("temp")
        assert self.mgr.silo_exists("temp") is False

    def test_delete_nonexistent_silo_raises(self):
        with pytest.raises(KeyError, match="not found"):
            self.mgr.delete_silo("nonexistent")

    def test_get_silos_for_category(self):
        self.mgr.create_silo(
            name="medical",
            display_name="Medical",
            categories=["diagnosis", "prescriptions"],
        )
        self.mgr.create_silo(
            name="identity",
            display_name="PII",
            categories=["diagnosis", "name"],
        )
        result = self.mgr.get_silos_for_category("diagnosis")
        assert len(result) == 2

    def test_healthcare_silo_pattern(self):
        """Test the healthcare pattern from InFill: PII, Medical, Auth silos."""
        self.mgr.create_silo(
            name="pii",
            display_name="Personal Information",
            categories=["name", "address", "dob", "ssn"],
        )
        self.mgr.create_silo(
            name="medical",
            display_name="Medical Records",
            categories=["diagnosis", "prescriptions", "lab_results"],
        )
        self.mgr.create_silo(
            name="auth",
            display_name="Authentication",
            categories=["credentials", "sessions"],
        )
        assert len(self.mgr.list_silos()) == 3
        assert self.mgr.silo_exists("pii")
        assert self.mgr.silo_exists("medical")
        assert self.mgr.silo_exists("auth")


class TestAnonymousID:
    """Test anonymous ID generation and validation."""

    def test_generate_format(self):
        gen = AnonymousID()
        anon_id = gen.generate()
        parts = anon_id.split("-")
        assert len(parts) == 3
        assert all(p.isalpha() for p in parts)

    def test_generate_unique(self):
        gen = AnonymousID()
        ids = {gen.generate() for _ in range(100)}
        assert len(ids) == 100

    def test_combination_count(self):
        gen = AnonymousID()
        # Architecture spec requires 101M+ (originally 440M, adjusted to 531x375x509)
        assert gen.combination_count > 100_000_000

    def test_validate_correct_format(self):
        assert AnonymousID.validate("crimson-arctic-fox") is True

    def test_validate_incorrect_format(self):
        assert AnonymousID.validate("invalid") is False
        assert AnonymousID.validate("too-many-parts-here") is False
        assert AnonymousID.validate("has-123-numbers") is False

    def test_generate_unique_in_set(self):
        gen = AnonymousID()
        existing = {"alpha-whale-nexus"}
        new_id = gen.generate_unique(existing)
        assert new_id not in existing
        assert AnonymousID.validate(new_id)

    def test_generate_unique_exhaustion(self):
        gen = AnonymousID(adjectives=["red"], animals=["cat"], nouns=["hat"])
        existing = {"red-cat-hat"}
        with pytest.raises(RuntimeError, match="Failed to generate unique ID"):
            gen.generate_unique(existing)


class TestIDMappingTable:
    """Test cross-silo identity mapping."""

    def setup_method(self):
        self.table = IDMappingTable()
        self.gen = AnonymousID()

    def test_register_and_lookup(self):
        anon_id = self.gen.generate()
        self.table.register("patient-001", "medical", anon_id)
        result = self.table.lookup("patient-001", "medical")
        assert result == anon_id

    def test_register_multiple_silos(self):
        """Same person gets different anonymous IDs in different silos."""
        med_id = self.gen.generate()
        pii_id = self.gen.generate()
        self.table.register("patient-001", "medical", med_id)
        self.table.register("patient-001", "pii", pii_id)

        assert self.table.lookup("patient-001", "medical") == med_id
        assert self.table.lookup("patient-001", "pii") == pii_id
        assert med_id != pii_id  # Different IDs per silo

    def test_lookup_nonexistent(self):
        assert self.table.lookup("nobody", "medical") is None
        assert self.table.lookup("patient-001", "nonexistent_silo") is None

    def test_reverse_lookup(self):
        anon_id = self.gen.generate()
        self.table.register("patient-001", "medical", anon_id)
        result = self.table.reverse_lookup(anon_id)
        assert result == ("patient-001", "medical")

    def test_reverse_lookup_nonexistent(self):
        assert self.table.reverse_lookup("unknown-id") is None

    def test_duplicate_registration_idempotent(self):
        """Registering the same mapping twice is idempotent."""
        anon_id = self.gen.generate()
        self.table.register("patient-001", "medical", anon_id)
        self.table.register("patient-001", "medical", anon_id)  # No error
        assert self.table.count() == 1

    def test_duplicate_registration_conflict(self):
        """Registering a different person with the same anon_id raises."""
        anon_id = self.gen.generate()
        self.table.register("patient-001", "medical", anon_id)
        with pytest.raises(ValueError, match="already registered"):
            self.table.register("patient-002", "medical", anon_id)

    def test_get_silo_ids(self):
        med_id = self.gen.generate()
        pii_id = self.gen.generate()
        self.table.register("patient-001", "medical", med_id)
        self.table.register("patient-001", "pii", pii_id)
        silo_ids = self.table.get_silo_ids("patient-001")
        assert silo_ids == {"medical": med_id, "pii": pii_id}

    def test_link_cross_silo(self):
        med_id = self.gen.generate()
        pii_id = self.gen.generate()
        self.table.register("patient-001", "medical", med_id)
        self.table.register("patient-001", "pii", pii_id)

        link = self.table.link_cross_silo(
            "patient-001", "medical", "pii", "consent_abc123"
        )
        assert link["source_silo"] == "medical"
        assert link["target_silo"] == "pii"
        assert link["source_anon_id"] == med_id
        assert link["target_anon_id"] == pii_id
        assert link["consent_id"] == "consent_abc123"

    def test_link_cross_silo_missing_mapping(self):
        self.table.register("patient-001", "medical", self.gen.generate())
        # No PII mapping — link should return None
        link = self.table.link_cross_silo(
            "patient-001", "medical", "pii", "consent_abc123"
        )
        assert link is None

    def test_unregister(self):
        """Right-to-be-forgotten: remove all mappings for a person."""
        med_id = self.gen.generate()
        pii_id = self.gen.generate()
        self.table.register("patient-001", "medical", med_id)
        self.table.register("patient-001", "pii", pii_id)

        self.table.unregister("patient-001")
        assert self.table.count() == 0
        assert self.table.reverse_lookup(med_id) is None
        assert self.table.reverse_lookup(pii_id) is None

    def test_count(self):
        self.table.register("patient-001", "medical", self.gen.generate())
        self.table.register("patient-002", "medical", self.gen.generate())
        assert self.table.count() == 2
        assert self.table.count_silo("medical") == 2

    def test_count_silo(self):
        self.table.register("patient-001", "medical", self.gen.generate())
        self.table.register("patient-001", "pii", self.gen.generate())
        self.table.register("patient-002", "medical", self.gen.generate())
        assert self.table.count_silo("medical") == 2
        assert self.table.count_silo("pii") == 1


class TestConsentEvent:
    """Test ConsentEvent data model."""

    def test_consent_event_defaults(self):
        event = ConsentEvent(
            consent_id="consent_001",
            data_owner_id="",
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
            scope="read",
        )
        assert event.status == ConsentStatus.PENDING
        assert event.is_valid() is False  # PENDING is not valid

    def test_approved_consent_is_valid(self):
        event = ConsentEvent(
            consent_id="consent_001",
            data_owner_id="owner-123",
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
            scope="read",
            status=ConsentStatus.APPROVED,
            approved_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert event.is_valid() is True

    def test_expired_consent_is_invalid(self):
        event = ConsentEvent(
            consent_id="consent_001",
            data_owner_id="owner-123",
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
            scope="read",
            status=ConsentStatus.APPROVED,
            approved_at=datetime.now(timezone.utc) - timedelta(hours=2),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert event.is_valid() is False

    def test_revoked_consent_is_invalid(self):
        event = ConsentEvent(
            consent_id="consent_001",
            data_owner_id="owner-123",
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
            scope="read",
            status=ConsentStatus.REVOKED,
        )
        assert event.is_valid() is False

    def test_covers_scope_hierarchy(self):
        """Write consent implies read access."""
        event = ConsentEvent(
            consent_id="consent_001",
            data_owner_id="owner-123",
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
            scope="write",
        )
        assert event.covers_scope("write") is True
        assert event.covers_scope("read") is True
        assert event.covers_scope("consent") is False

    def test_read_does_not_imply_write(self):
        event = ConsentEvent(
            consent_id="consent_001",
            data_owner_id="owner-123",
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
            scope="read",
        )
        assert event.covers_scope("read") is True
        assert event.covers_scope("write") is False


class TestConsentGate:
    """Test consent-gated cross-silo access lifecycle."""

    def setup_method(self):
        self.gate = ConsentGate()

    def test_request_consent(self):
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
            reason="Research study",
        )
        assert event.status == ConsentStatus.PENDING
        assert event.consent_id.startswith("consent_")
        assert event.source_silo == "medical"
        assert event.target_silo == "pii"

    def test_approve_consent(self):
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
        )
        approved = self.gate.approve_consent(event.consent_id, "owner-123", ttl_seconds=3600)
        assert approved.status == ConsentStatus.APPROVED
        assert approved.data_owner_id == "owner-123"
        assert approved.approved_at is not None
        assert approved.expires_at is not None

    def test_approve_non_pending_raises(self):
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
        )
        self.gate.approve_consent(event.consent_id, "owner-123")
        with pytest.raises(ValueError, match="Cannot approve"):
            self.gate.approve_consent(event.consent_id, "owner-456")

    def test_deny_consent(self):
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
        )
        denied = self.gate.deny_consent(event.consent_id, "owner-123", reason="Not authorized")
        assert denied.status == ConsentStatus.DENIED

    def test_deny_non_pending_raises(self):
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
        )
        self.gate.deny_consent(event.consent_id, "owner-123")
        with pytest.raises(ValueError, match="Cannot deny"):
            self.gate.deny_consent(event.consent_id, "owner-456")

    def test_check_valid_consent(self):
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
        )
        self.gate.approve_consent(event.consent_id, "owner-123", ttl_seconds=3600)
        checked = self.gate.check_consent(event.consent_id)
        assert checked is not None
        assert checked.is_valid()

    def test_check_expired_consent(self):
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
        )
        # Approve with 1-second TTL, then wait for expiry
        self.gate.approve_consent(event.consent_id, "owner-123", ttl_seconds=1)
        import time
        time.sleep(1.1)
        checked = self.gate.check_consent(event.consent_id)
        assert checked is None  # Expired

    def test_check_nonexistent_consent(self):
        assert self.gate.check_consent("nonexistent") is None

    def test_revoke_consent(self):
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
        )
        self.gate.approve_consent(event.consent_id, "owner-123")
        revoked = self.gate.revoke_consent(event.consent_id)
        assert revoked.status == ConsentStatus.REVOKED
        assert revoked.revoked_at is not None

    def test_revoke_non_approved_raises(self):
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
        )
        with pytest.raises(ValueError, match="Cannot revoke"):
            self.gate.revoke_consent(event.consent_id)

    def test_full_lifecycle(self):
        """Request -> Approve -> Check -> Revoke -> Check fails."""
        event = self.gate.request_consent(
            requesting_node_id="node-abc",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis", "prescriptions"],
            scope="read",
            reason="Treatment coordination",
        )
        assert event.status == ConsentStatus.PENDING

        approved = self.gate.approve_consent(event.consent_id, "owner-123", ttl_seconds=3600)
        assert approved.status == ConsentStatus.APPROVED

        checked = self.gate.check_consent(event.consent_id)
        assert checked is not None
        assert checked.has_category("diagnosis") is True
        assert checked.has_category("lab_results") is False
        assert checked.covers_scope("read") is True

        self.gate.revoke_consent(event.consent_id)
        assert self.gate.check_consent(event.consent_id) is None

    def test_get_pending(self):
        self.gate.request_consent("node-a", "medical", "pii", ["diagnosis"])
        self.gate.request_consent("node-b", "identity", "auth", ["credentials"])
        pending = self.gate.get_pending()
        assert len(pending) == 2

    def test_get_approved(self):
        e1 = self.gate.request_consent("node-a", "medical", "pii", ["diagnosis"])
        self.gate.approve_consent(e1.consent_id, "owner-1")
        e2 = self.gate.request_consent("node-b", "identity", "auth", ["credentials"])
        # e2 still pending
        approved = self.gate.get_approved()
        assert len(approved) == 1

    def test_get_for_owner(self):
        e1 = self.gate.request_consent("node-a", "medical", "pii", ["diagnosis"])
        self.gate.approve_consent(e1.consent_id, "owner-1")
        e2 = self.gate.request_consent("node-b", "identity", "auth", ["name"])
        self.gate.approve_consent(e2.consent_id, "owner-1")
        owner_events = self.gate.get_for_owner("owner-1")
        assert len(owner_events) == 2

    def test_get_for_node(self):
        self.gate.request_consent("node-a", "medical", "pii", ["diagnosis"])
        self.gate.request_consent("node-a", "identity", "auth", ["name"])
        self.gate.request_consent("node-b", "medical", "pii", ["prescriptions"])
        node_events = self.gate.get_for_node("node-a")
        assert len(node_events) == 2

    def test_get_for_silo_pair(self):
        self.gate.request_consent("node-a", "medical", "pii", ["diagnosis"])
        self.gate.request_consent("node-b", "medical", "pii", ["prescriptions"])
        self.gate.request_consent("node-c", "identity", "auth", ["name"])
        pair_events = self.gate.get_for_silo_pair("medical", "pii")
        assert len(pair_events) == 2


class TestDataSeparationIntegration:
    """Integration test: SiloManager + AnonymousID + IDMappingTable + ConsentGate."""

    def test_full_cross_silo_workflow(self):
        """End-to-end: create silos, register identities, request and approve consent."""
        # 1. Set up silos
        mgr = SiloManager()
        mgr.create_silo("medical", "Medical Records", ["diagnosis", "prescriptions"])
        mgr.create_silo("pii", "Personal Information", ["name", "address", "dob"])
        mgr.create_silo("auth", "Authentication", ["credentials"])

        # 2. Create anonymous IDs
        gen = AnonymousID()
        table = IDMappingTable()
        med_id = gen.generate_unique(set())
        table.register("patient-001", "medical", med_id)
        pii_id = gen.generate_unique({med_id})
        table.register("patient-001", "pii", pii_id)

        # Verify different IDs per silo
        assert med_id != pii_id
        assert table.lookup("patient-001", "medical") == med_id
        assert table.lookup("patient-001", "pii") == pii_id

        # 3. Request cross-silo consent
        gate = ConsentGate()
        consent = gate.request_consent(
            requesting_node_id="research-node",
            source_silo="medical",
            target_silo="pii",
            categories=["diagnosis"],
            reason="Treatment coordination",
        )
        assert consent.status == ConsentStatus.PENDING

        # 4. Approve consent
        approved = gate.approve_consent(consent.consent_id, pii_id, ttl_seconds=3600)
        assert approved.is_valid()

        # 5. Link cross-silo data
        link = table.link_cross_silo(
            "patient-001", "medical", "pii", approved.consent_id
        )
        assert link["source_anon_id"] == med_id
        assert link["target_anon_id"] == pii_id
        assert link["consent_id"] == approved.consent_id

        # 6. Verify consent is still valid
        checked = gate.check_consent(consent.consent_id)
        assert checked is not None
        assert checked.is_valid()

        # 7. Revoke and verify
        gate.revoke_consent(consent.consent_id)
        assert gate.check_consent(consent_id=consent.consent_id) is None