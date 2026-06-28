"""
Bedrock Core API server tests.

Tests the HTTP API endpoints for frontend integration.
Uses http.server's test harness pattern.
"""

import json
import threading
import time
from http.server import HTTPServer
from unittest.mock import patch

import pytest

from bedrock.config import CoreConfig
from bedrock.server import BedrockAPIHandler, create_server, APIError
from bedrock.server.tls import TLSConfig


class TestAPIServer:
    """Test API server endpoints."""

    def setup_method(self):
        """Set up test server and client."""
        self.config = CoreConfig(environment="test", debug=True)
        self.api_keys = {
            "test-api-key": {
                "tier": "developer",
                "node_id": "test-node-001",
                "roles": ["patient", "provider"],
            }
        }
        self.server = create_server(
            host="127.0.0.1", port=0,  # Random available port
            config=self.config,
            api_keys=self.api_keys,
            tls_config=TLSConfig(enabled=False),  # No TLS for test client
            db_path=":memory:",  # In-memory SQLite for tests
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        time.sleep(0.1)  # Let server start

    def teardown_method(self):
        """Shut down test server."""
        self.server.shutdown()

    def _url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def _headers(self, api_key: str = "test-api-key") -> dict:
        return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def _get(self, path: str, api_key: str = "test-api-key"):
        """Make a GET request to the test server."""
        import urllib.request
        req = urllib.request.Request(self._url(path), headers=self._headers(api_key))
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def _post(self, path: str, data: dict, api_key: str = "test-api-key"):
        """Make a POST request to the test server."""
        import urllib.request
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            self._url(path), data=body, headers=self._headers(api_key), method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def _put(self, path: str, data: dict, api_key: str = "test-api-key"):
        """Make a PUT request to the test server."""
        import urllib.request
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            self._url(path), data=body, headers=self._headers(api_key), method="PUT"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    # ── Health ──

    def test_health_endpoint_no_auth(self):
        """Health endpoint should work without authentication."""
        import urllib.request
        req = urllib.request.Request(self._url("/health"))
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["status"] in ("healthy", "degraded")
            assert "components" in data

    def test_health_detailed_requires_auth(self):
        """Detailed health endpoint requires authentication."""
        import urllib.request
        req = urllib.request.Request(self._url("/health/detailed"))
        # No Authorization header
        try:
            with urllib.request.urlopen(req) as resp:
                # Should not get here — should be 401
                assert resp.status == 401, f"Expected 401, got {resp.status}"
        except urllib.error.HTTPError as e:
            assert e.code == 401, f"Expected 401, got {e.code}"

    def test_health_detailed_with_auth(self):
        """Detailed health endpoint works with authentication."""
        status, data = self._get("/health/detailed")
        # Without auth returns 401, with auth returns 200
        # Let's test with auth
        status, data = self._get("/health/detailed", api_key="test-api-key")
        assert status == 200
        assert "components" in data

    # ── Authentication ──

    def test_api_endpoints_require_auth(self):
        """Protected endpoints return 401 without auth."""
        import urllib.request
        req = urllib.request.Request(self._url("/api/v1/nodes"))
        try:
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 401
        except urllib.error.HTTPError as e:
            assert e.code == 401

    def test_invalid_api_key(self):
        """Invalid API key returns 401."""
        status, data = self._get("/api/v1/silos", api_key="invalid-key")
        assert status == 401

    # ── Node Registration ──

    def test_register_node(self):
        """POST /api/v1/nodes registers a new node."""
        status, data = self._post("/api/v1/nodes", {
            "name": "test-patient",
            "node_type": "patient",
        })
        assert status == 201
        assert "node_id" in data
        assert data["name"] == "test-patient"
        assert data["state"] == "active"

    # ── Certificate ──

    def test_issue_certificate(self):
        """POST /api/v1/certificates issues a certificate."""
        status, data = self._post("/api/v1/certificates", {
            "node_name": "cert-test",
            "node_type": "provider",
        })
        assert status == 201

    # ── Silos ──

    def test_create_silo(self):
        """POST /api/v1/silos creates a data silo."""
        status, data = self._post("/api/v1/silos", {
            "name": "medical-records",
            "display_name": "Medical Records",
            "categories": ["diagnosis", "medication"],
        })
        assert status == 201
        assert data["name"] == "medical-records"

    def test_list_silos(self):
        """GET /api/v1/silos lists data silos."""
        status, data = self._get("/api/v1/silos")
        assert status == 200
        assert "silos" in data
        assert "total" in data

    # ── Consent ──

    def test_request_consent(self):
        """POST /api/v1/consent creates a consent request."""
        status, data = self._post("/api/v1/consent", {
            "requesting_node_id": "provider-001",
            "source_silo": "medical",
            "target_silo": "identity",
            "categories": ["diagnosis"],
            "scope": "read",
            "reason": "treatment",
        })
        assert status == 201
        assert "consent_id" in data
        assert data["status"] == "pending"

    # ── Licensing ──

    def test_validate_license(self):
        """POST /api/v1/license/validate validates a license key."""
        # First generate a key
        from bedrock.licensing.enforcement import LicenseEnforcer, LicenseTier
        enforcer = LicenseEnforcer()
        key = enforcer.generate_license_key(tier=LicenseTier.DEVELOPER, issued_to="api-test")

        status, data = self._post("/api/v1/license/validate", {
            "license_key": key,
        })
        assert status == 200
        assert data["valid"] is True
        assert data["tier"] == "developer"

    # ── Audit ──

    def test_verify_audit(self):
        """GET /api/v1/audit/verify checks chain integrity."""
        status, data = self._get("/api/v1/audit/verify")
        assert status == 200
        assert "verified" in data

    # ── Error Handling ──

    def test_not_found(self):
        """Unknown endpoints return 404."""
        status, data = self._get("/api/v1/nonexistent")
        assert status == 404

    def test_invalid_json_body(self):
        """Malformed JSON returns 400."""
        import urllib.request
        body = b"not json"
        req = urllib.request.Request(
            self._url("/api/v1/nodes"), data=body,
            headers=self._headers(), method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 400
        except urllib.error.HTTPError as e:
            assert e.code == 400