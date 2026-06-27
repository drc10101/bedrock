"""Tests for Capability Scoping."""

from bedrock.identity.capabilities import CapabilityScope, DataCategory


class TestCapabilityScope:
    """Test node capability scoping."""

    def test_can_access_allowed_category(self):
        scope = CapabilityScope(
            node_id="node-1",
            categories=[DataCategory.IDENTITY, DataCategory.MEDICAL],
            operations=["read", "write"],
        )
        assert scope.can_access(DataCategory.IDENTITY) is True
        assert scope.can_access(DataCategory.MEDICAL) is True

    def test_cannot_access_disallowed_category(self):
        scope = CapabilityScope(
            node_id="node-1",
            categories=[DataCategory.IDENTITY],
        )
        assert scope.can_access(DataCategory.TRANSACTION) is False

    def test_can_write_with_write_permission(self):
        scope = CapabilityScope(
            node_id="node-1",
            categories=[DataCategory.IDENTITY],
            operations=["read", "write"],
        )
        assert scope.can_write(DataCategory.IDENTITY) is True

    def test_cannot_write_with_read_only(self):
        scope = CapabilityScope(
            node_id="node-1",
            categories=[DataCategory.IDENTITY],
            operations=["read"],
        )
        assert scope.can_write(DataCategory.IDENTITY) is False

    def test_default_operations_are_read_only(self):
        scope = CapabilityScope(node_id="node-1")
        assert scope.operations == ["read"]