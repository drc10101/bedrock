"""
Bedrock SDK client — entry point for connecting to Bedrock Core.

Provides BedrockClient with namespaced sub-clients for each subsystem.
"""

import json
import urllib.request
import urllib.error
from typing import Any

from bedrock_sdk.exceptions import (
    AuthenticationError,
    BedrockError,
    LicenseError,
    MeshError,
    NotFoundError,
    QuotaExceededError,
    ValidationError,
)

# Sub-client imports at bottom to avoid circular imports


class BedrockClient:
    """Main entry point for the Bedrock Python SDK.

    Connects to a Bedrock Core instance using a license key and provides
    namespaced access to all Bedrock subsystems.

    Args:
        base_url: Bedrock Core instance URL (e.g. "https://bedrock.example.com")
        license_key: Developer or Production license key
        timeout: Request timeout in seconds (default 30)

    Usage:
        client = BedrockClient(
            base_url="https://bedrock.example.com",
            license_key="BR-DEV-xxxx-xxxx",
        )
        node = client.nodes.register(name="my-app", node_type="application")
    """

    API_VERSION = "v1"

    def __init__(self, base_url: str, license_key: str, timeout: int = 30):
        # Strip trailing slash
        self.base_url = base_url.rstrip("/")
        self.license_key = license_key
        self.timeout = timeout

        # Sub-clients
        self.nodes = _NodeClient(self)
        self.certificates = _CertificateClient(self)
        self.silos = _SiloClient(self)
        self.consent = _ConsentClient(self)
        self.encryption = _EncryptionClient(self)
        self.audit = _AuditClient(self)
        self.mesh = _MeshClient(self)
        self.license = _LicenseClient(self)

    def _url(self, path: str) -> str:
        """Build full URL for an API path."""
        return f"{self.base_url}/api/{self.API_VERSION}{path}"

    def _headers(self) -> dict[str, str]:
        """Build request headers with auth."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.license_key}",
        }
        return headers

    def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated request to Bedrock Core.

        Returns parsed JSON response body.
        Raises BedrockError on failure.
        """
        url = self._url(path)
        data = json.dumps(body).encode() if body else None

        req = urllib.request.Request(url, data=data, method=method)
        for key, value in self._headers().items():
            req.add_header(key, value)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status in (200, 201):
                    raw = resp.read()
                    if raw:
                        return json.loads(raw)
                    return {"status": "ok"}
                return {"status": "ok"}
        except urllib.error.HTTPError as e:
            error_body = {}
            try:
                error_body = json.loads(e.read())
            except Exception:
                error_body = {"detail": str(e)}

            status = e.code
            message = error_body.get("error", error_body.get("detail", str(e)))

            if status == 401:
                raise AuthenticationError(message, status, error_body)
            elif status == 403:
                raise LicenseError(message, status, error_body)
            elif status == 404:
                raise NotFoundError(message, status, error_body)
            elif status == 422:
                raise ValidationError(message, status, error_body)
            elif status == 429:
                raise QuotaExceededError(message, status, error_body)
            else:
                raise BedrockError(message, status, error_body)
        except urllib.error.URLError as e:
            raise BedrockError(f"Connection failed: {e.reason}") from e

    def get(self, path: str) -> dict:
        return self.request("GET", path)

    def post(self, path: str, body: dict) -> dict:
        return self.request("POST", path, body)

    def put(self, path: str, body: dict) -> dict:
        return self.request("PUT", path, body)

    def delete(self, path: str) -> dict:
        return self.request("DELETE", path)


class _NodeClient:
    """Manage identity nodes in Bedrock."""

    def __init__(self, client: BedrockClient):
        self._client = client

    def register(self, name: str, node_type: str) -> dict:
        """Register a new node in the mesh."""
        return self._client.post("/nodes", {
            "name": name,
            "node_type": node_type,
        })

    def list(self) -> list[dict]:
        """List all registered nodes."""
        result = self._client.get("/nodes")
        return result.get("nodes", [])

    def get(self, node_uuid: str) -> dict:
        """Get a specific node by UUID."""
        return self._client.get(f"/nodes/{node_uuid}")


class _CertificateClient:
    """Manage node certificates."""

    def __init__(self, client: BedrockClient):
        self._client = client

    def issue(
        self,
        node_uuid: str,
        node_name: str,
        public_key_hash: str,
        capabilities: list[str] | None = None,
        ttl_hours: int = 8760,
    ) -> dict:
        """Issue a certificate for a node."""
        body = {
            "node_uuid": node_uuid,
            "node_name": node_name,
            "public_key_hash": public_key_hash,
            "ttl_hours": ttl_hours,
        }
        if capabilities:
            body["capabilities"] = capabilities
        return self._client.post("/certificates", body)

    def revoke(self, node_uuid: str, reason: str = "") -> dict:
        """Revoke a node's certificate."""
        return self._client.put(f"/certificates/{node_uuid}/revoke", {
            "reason": reason,
        })

    def check(self, node_uuid: str) -> dict:
        """Check if a node's certificate is valid."""
        return self._client.get(f"/certificates/{node_uuid}/check")


class _SiloClient:
    """Manage data separation silos."""

    def __init__(self, client: BedrockClient):
        self._client = client

    def create(self, name: str, display_name: str, categories: list[str]) -> dict:
        """Create a new data silo."""
        return self._client.post("/silos", {
            "name": name,
            "display_name": display_name,
            "categories": categories,
        })

    def list(self) -> list[dict]:
        """List all silos."""
        result = self._client.get("/silos")
        return result.get("silos", [])


class _ConsentClient:
    """Manage consent workflows."""

    def __init__(self, client: BedrockClient):
        self._client = client

    def request(
        self,
        requester_id: str,
        target_id: str,
        silo_id: str,
        purpose: str,
        scope: list[str],
        description: str = "",
    ) -> dict:
        """Request consent to access data."""
        return self._client.post("/consent", {
            "action": "request",
            "requester_id": requester_id,
            "target_id": target_id,
            "silo_id": silo_id,
            "purpose": purpose,
            "scope": scope,
            "description": description,
        })

    def approve(self, consent_id: str) -> dict:
        """Approve a consent request."""
        return self._client.put(f"/consent/{consent_id}", {
            "action": "approve",
        })

    def deny(self, consent_id: str) -> dict:
        """Deny a consent request."""
        return self._client.put(f"/consent/{consent_id}", {
            "action": "deny",
        })


class _EncryptionClient:
    """Encrypt and decrypt field-level data."""

    def __init__(self, client: BedrockClient):
        self._client = client

    def encrypt(
        self,
        plaintext: str,
        silo: str,
        record_id: str,
        scope: str,
        operation: str = "store",
    ) -> dict:
        """Encrypt a field value."""
        return self._client.post("/encrypt", {
            "plaintext": plaintext,
            "silo": silo,
            "record_id": record_id,
            "scope": scope,
            "operation": operation,
        })

    def decrypt(
        self,
        ciphertext: str,
        silo: str,
        record_id: str,
        scope: str,
        operation: str = "retrieve",
        key_version: int | None = None,
    ) -> dict:
        """Decrypt a field value."""
        body = {
            "ciphertext": ciphertext,
            "silo": silo,
            "record_id": record_id,
            "scope": scope,
            "operation": operation,
        }
        if key_version is not None:
            body["key_version"] = key_version
        return self._client.post("/decrypt", body)


class _AuditClient:
    """Query and verify the audit chain."""

    def __init__(self, client: BedrockClient):
        self._client = client

    def query(
        self,
        action: str | None = None,
        actor_id: str | None = None,
        target_id: str | None = None,
        silo: str | None = None,
        limit: int = 100,
    ) -> dict:
        """Query audit entries with optional filters."""
        params = {"limit": limit}
        if action:
            params["action"] = action
        if actor_id:
            params["actor_id"] = actor_id
        if target_id:
            params["target_id"] = target_id
        if silo:
            params["silo"] = silo

        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        return self._client.get(f"/audit?{query_string}")

    def verify(self, entry_hash: str | None = None) -> dict:
        """Verify audit chain integrity."""
        path = "/audit/verify"
        if entry_hash:
            path += f"?entry_hash={entry_hash}"
        return self._client.get(path)


class _MeshClient:
    """Interact with the Self-Healing Mesh."""

    def __init__(self, client: BedrockClient):
        self._client = client

    def get_state(self, node_uuid: str) -> dict:
        """Get a node's current mesh state."""
        return self._client.get(f"/mesh/nodes/{node_uuid}/state")

    def flag(self, source_uuid: str, target_uuid: str, signal_type: str, details: str = "") -> dict:
        """Flag a node for suspicious activity."""
        return self._client.post("/mesh/flag", {
            "source_uuid": source_uuid,
            "target_uuid": target_uuid,
            "signal_type": signal_type,
            "details": details,
        })

    def heal(self, node_uuid: str) -> dict:
        """Initiate healing for a quarantined node."""
        return self._client.post(f"/mesh/nodes/{node_uuid}/heal", {})


class _LicenseClient:
    """Validate and inspect license status."""

    def __init__(self, client: BedrockClient):
        self._client = client

    def validate(self) -> dict:
        """Validate the current license key."""
        return self._client.post("/license/validate", {
            "license_key": self._client.license_key,
        })

    def features(self) -> dict:
        """List features available under the current license."""
        result = self.validate()
        return result.get("features", {})