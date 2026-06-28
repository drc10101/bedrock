"""
Bedrock Core API server tests.

Tests the FastAPI endpoints for frontend integration.
Uses FastAPI's TestClient (Starlette) for synchronous test execution.
"""

import json

import pytest
from fastapi.testclient import TestClient

from bedrock.config import CoreConfig
from bedrock.server import create_app, APIError
from bedrock.server.tls import TLSConfig


class TestAPIServer:
    """Test API server endpoints."""

    def setup_method(self):
        """Set up test client."""
        self.config = CoreConfig(environment="test", debug=True)
        self.api_keys = {
            "test-api-key": {
                "tier": "developer",
                "node_id": "test-node-001",
                "roles": ["patient", "provider"],
            }
        }
        app = create_app(
            config=self.config,
            api_keys=self.api_keys,
            tls_config=TLSConfig(enabled=False),
            db_path=":memory:",
            enable_metering=False,
        )
        self.client = TestClient(app)

    def _headers(self, api_key: str = "test-api-key") -> dict:
        return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    # ── Health endpoints (no auth) ──

    def test_health_endpoint(self):
        """GET /health returns health status."""
        response = self.client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "healthy" in data or "status" in data

    def test_health_detailed_requires_auth(self):
        """GET /health/detailed requires authentication."""
        response = self.client.get("/health/detailed")
        assert response.status_code == 401

    def test_health_detailed_with_auth(self):
        """GET /health/detailed returns detailed health with auth."""
        response = self.client.get("/health/detailed", headers=self._headers())
        assert response.status_code == 200
        data = response.json()
        assert "components" in data or "healthy" in data or "status" in data

    # ── Node registration ──

    def test_register_node(self):
        """POST /api/v1/nodes registers a new node."""
        response = self.client.post(
            "/api/v1/nodes",
            json={"name": "test-node", "node_type": "provider"},
            headers=self._headers(),
        )
        assert response.status_code == 201
        data = response.json()
        assert "node_id" in data
        assert data["name"] == "test-node"
        assert data["state"] == "active"

    def test_register_node_requires_auth(self):
        """POST /api/v1/nodes requires authentication."""
        response = self.client.post(
            "/api/v1/nodes",
            json={"name": "unauth-node"},
        )
        assert response.status_code == 401

    def test_register_node_default_values(self):
        """POST /api/v1/nodes uses defaults when fields missing."""
        response = self.client.post("/api/v1/nodes", json={}, headers=self._headers())
        assert response.status_code == 201
        data = response.json()
        assert data["name"].startswith("node-")
        assert data["state"] == "active"

    # ── Node listing and retrieval ──

    def test_list_nodes(self):
        """GET /api/v1/nodes lists all nodes."""
        # Register a node first
        self.client.post(
            "/api/v1/nodes",
            json={"name": "list-test-node"},
            headers=self._headers(),
        )
        response = self.client.get("/api/v1/nodes", headers=self._headers())
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert data["total"] >= 1

    def test_get_node(self):
        """GET /api/v1/nodes/{node_id} returns node details."""
        create_resp = self.client.post(
            "/api/v1/nodes",
            json={"name": "get-test-node"},
            headers=self._headers(),
        )
        node_id = create_resp.json()["node_id"]

        response = self.client.get(f"/api/v1/nodes/{node_id}", headers=self._headers())
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "get-test-node"

    def test_get_node_not_found(self):
        """GET /api/v1/nodes/{node_id} returns 404 for unknown node."""
        response = self.client.get("/api/v1/nodes/nonexistent", headers=self._headers())
        assert response.status_code == 404

    # ── Certificate endpoints ──

    def test_issue_certificate(self):
        """POST /api/v1/certificates issues a certificate."""
        # Register a node first
        node_resp = self.client.post(
            "/api/v1/nodes",
            json={"name": "cert-test", "node_type": "provider"},
            headers=self._headers(),
        )
        node_id = node_resp.json()["node_id"]

        response = self.client.post(
            "/api/v1/certificates",
            json={"node_uuid": node_id, "node_name": "cert-test"},
            headers=self._headers(),
        )
        assert response.status_code == 201
        data = response.json()
        assert "serial" in data
        assert data["node_uuid"] == node_id

    def test_revoke_certificate(self):
        """DELETE /api/v1/certificates/{node_id} returns 404 if no cert exists."""
        # Revoking a non-existent certificate returns 404
        response = self.client.delete(
            "/api/v1/certificates/nonexistent-node",
            headers=self._headers(),
        )
        assert response.status_code == 404

    # ── Silo endpoints ──

    def test_create_silo(self):
        """POST /api/v1/silos creates a data silo."""
        response = self.client.post(
            "/api/v1/silos",
            json={"name": "test-silo", "display_name": "Test Silo", "categories": ["medical"]},
            headers=self._headers(),
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test-silo"

    def test_list_silos(self):
        """GET /api/v1/silos lists all silos."""
        self.client.post(
            "/api/v1/silos",
            json={"name": "list-silo", "categories": ["financial"]},
            headers=self._headers(),
        )
        response = self.client.get("/api/v1/silos", headers=self._headers())
        assert response.status_code == 200
        data = response.json()
        assert "silos" in data
        assert data["total"] >= 1

    # ── Consent endpoints ──

    def test_request_consent(self):
        """POST /api/v1/consent requests consent."""
        response = self.client.post(
            "/api/v1/consent",
            json={
                "requesting_node_id": "node-1",
                "source_silo": "medical",
                "target_silo": "billing",
                "categories": ["diagnosis"],
                "scope": "read",
                "reason": "billing review",
            },
            headers=self._headers(),
        )
        assert response.status_code == 201
        data = response.json()
        assert "consent_id" in data
        assert data["status"] == "pending"

    def test_approve_consent(self):
        """PUT /api/v1/consent/{id}/approve approves consent."""
        # Request consent first
        consent_resp = self.client.post(
            "/api/v1/consent",
            json={
                "requesting_node_id": "node-1",
                "source_silo": "medical",
                "target_silo": "billing",
                "categories": ["diagnosis"],
                "scope": "read",
                "reason": "billing review",
            },
            headers=self._headers(),
        )
        consent_id = consent_resp.json()["consent_id"]

        response = self.client.put(
            f"/api/v1/consent/{consent_id}/approve",
            json={"data_owner_id": "owner-1"},
            headers=self._headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "approved"

    def test_deny_consent(self):
        """PUT /api/v1/consent/{id}/deny denies consent."""
        consent_resp = self.client.post(
            "/api/v1/consent",
            json={
                "requesting_node_id": "node-1",
                "source_silo": "medical",
                "target_silo": "billing",
                "categories": ["diagnosis"],
                "scope": "read",
                "reason": "billing review",
            },
            headers=self._headers(),
        )
        consent_id = consent_resp.json()["consent_id"]

        response = self.client.put(
            f"/api/v1/consent/{consent_id}/deny",
            json={"data_owner_id": "owner-1", "reason": "Not authorized"},
            headers=self._headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "denied"

    # ── Encryption endpoints ──

    def test_encrypt_field(self):
        """POST /api/v1/encrypt encrypts a field value."""
        response = self.client.post(
            "/api/v1/encrypt",
            json={"plaintext": "SSN-123-45-6789", "silo": "medical", "record_id": "p1", "scope": "ssn"},
            headers=self._headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert "ciphertext" in data
        assert data["silo"] == "medical"

    def test_decrypt_not_implemented(self):
        """POST /api/v1/decrypt returns 501 (requires key management)."""
        response = self.client.post(
            "/api/v1/decrypt",
            json={"ciphertext": "abc123"},
            headers=self._headers(),
        )
        assert response.status_code == 501

    # ── Audit endpoints ──

    def test_query_audit(self):
        """GET /api/v1/audit queries audit chain."""
        response = self.client.get("/api/v1/audit", headers=self._headers())
        assert response.status_code == 200
        data = response.json()
        assert "entries" in data
        assert "total" in data

    def test_query_audit_with_filters(self):
        """GET /api/v1/audit?actor_id=... filters results."""
        response = self.client.get(
            "/api/v1/audit?actor_id=test-node-001",
            headers=self._headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert "entries" in data

    def test_verify_audit(self):
        """GET /api/v1/audit/verify verifies chain integrity."""
        response = self.client.get("/api/v1/audit/verify", headers=self._headers())
        assert response.status_code == 200
        data = response.json()
        assert "verified" in data

    # ── License validation ──

    def test_validate_license(self):
        """POST /api/v1/license/validate validates a license key."""
        response = self.client.post(
            "/api/v1/license/validate",
            json={"license_key": "test-key"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "valid" in data

    # ── Usage metering ──

    def test_usage_endpoint(self):
        """GET /api/v1/usage returns usage summary."""
        response = self.client.get("/api/v1/usage", headers=self._headers())
        assert response.status_code == 200
        data = response.json()
        assert "usage" in data

    # ── Authentication ──

    def test_invalid_api_key(self):
        """Requests with invalid API key are rejected."""
        response = self.client.get(
            "/api/v1/nodes",
            headers={"Authorization": "Bearer invalid-key"},
        )
        assert response.status_code == 401

    def test_missing_auth_header(self):
        """Requests without auth header are rejected."""
        response = self.client.get("/api/v1/nodes")
        assert response.status_code == 401

    def test_health_no_auth_required(self):
        """GET /health does not require authentication."""
        response = self.client.get("/health")
        assert response.status_code == 200

    # ── Error handling ──

    def test_api_error_class(self):
        """APIError can be instantiated with message and status."""
        err = APIError("test error", 400)
        assert err.message == "test error"
        assert err.status == 400

    def test_authentication_error(self):
        """AuthenticationError has 401 status."""
        from bedrock.server.app import AuthenticationError

        err = AuthenticationError()
        assert err.status == 401

    def test_authorization_error(self):
        """AuthorizationError has 403 status."""
        from bedrock.server.app import AuthorizationError

        err = AuthorizationError()
        assert err.status == 403

    def test_not_found_error(self):
        """NotFoundError has 404 status."""
        from bedrock.server.app import NotFoundError

        err = NotFoundError("test")
        assert err.status == 404

    # ── Registration endpoint ──

    def test_register_returns_api_key(self):
        """POST /api/v1/register returns a new API key."""
        response = self.client.post("/api/v1/register")
        assert response.status_code == 201
        data = response.json()
        assert "api_key" in data
        assert data["api_key"]
        assert data["tier"] == "developer"
        assert "node_id" in data
        assert "roles" in data
        assert "read" in data["roles"]

    def test_register_key_works_for_auth(self):
        """A key from /register can authenticate to other endpoints."""
        reg_response = self.client.post("/api/v1/register")
        assert reg_response.status_code == 201
        new_key = reg_response.json()["api_key"]

        # Use the new key to list nodes
        response = self.client.get("/api/v1/nodes", headers=self._headers(new_key))
        assert response.status_code == 200

    def test_register_rate_limited(self):
        """Second registration within 60 seconds is rate limited."""
        first = self.client.post("/api/v1/register")
        assert first.status_code == 201

        second = self.client.post("/api/v1/register")
        assert second.status_code == 429

    def test_register_with_empty_body(self):
        """POST /api/v1/register with empty body still works."""
        response = self.client.post(
            "/api/v1/register", json={}
        )
        assert response.status_code == 201