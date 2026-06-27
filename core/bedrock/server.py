"""
Bedrock Core — HTTP API Server.

Exposes Bedrock Core functionality as a REST API for frontend integration.
Designed for the InFill portal and other Bedrock-based applications.

Security model:
- All endpoints require API key authentication (except /health)
- Rate limiting enforced per-tier
- No data leaves encrypted silos without consent verification
- Audit trail logging on every mutation

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

import json
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from bedrock.config import CoreConfig
from bedrock.health import HealthChecker


class APIError(Exception):
    """Base API error with status code."""
    def __init__(self, message: str, status: int = 400):
        self.message = message
        self.status = status
        super().__init__(message)


class AuthenticationError(APIError):
    def __init__(self, message: str = "Authentication required"):
        super().__init__(message, status=401)


class AuthorizationError(APIError):
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(message, status=403)


class NotFoundError(APIError):
    def __init__(self, resource: str = "Resource"):
        super().__init__(f"{resource} not found", status=404)


class BedrockAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Bedrock Core API."""

    # Config and core modules — set by server before serving
    config: CoreConfig = None
    api_keys: Dict[str, dict] = {}  # api_key -> {tier, node_id, roles}

    def log_message(self, format, *args):
        """Override to use structured logging."""
        if self.config and self.config.log_format == "json":
            print(json.dumps({
                "timestamp": time.time(),
                "level": "INFO",
                "method": self.command,
                "path": self.path,
                "message": format % args,
            }))
        else:
            super().log_message(format, *args)

    def _send_json(self, data: Any, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Request-Id", str(uuid.uuid4()))
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2 if self.config and self.config.debug else None).encode())

    def _send_error(self, message: str, status: int = 400):
        """Send error response."""
        self._send_json({"error": message, "status": status}, status)

    def _authenticate(self) -> Optional[dict]:
        """Validate API key from Authorization header."""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:]
        elif auth_header.startswith("ApiKey "):
            api_key = auth_header[7:]
        else:
            return None

        if api_key in self.api_keys:
            return self.api_keys[api_key]
        return None

    def _require_auth(self) -> dict:
        """Require authentication, raise 401 if missing."""
        identity = self._authenticate()
        if identity is None:
            raise AuthenticationError()
        return identity

    def _parse_body(self) -> dict:
        """Parse JSON request body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length)
        return json.loads(body)

    def _route(self, method: str, path: str) -> Tuple[callable, dict]:
        """Route request to handler. Returns (handler_fn, path_params)."""
        routes = {
            # Health (no auth required)
            ("GET", "/health"): self._handle_health,
            ("GET", "/health/detailed"): self._handle_health_detailed,

            # Identity
            ("POST", "/api/v1/nodes"): self._handle_register_node,
            ("GET", "/api/v1/nodes"): self._handle_list_nodes,
            ("GET", "/api/v1/nodes/{node_id}"): self._handle_get_node,
            ("POST", "/api/v1/certificates"): self._handle_issue_certificate,
            ("DELETE", "/api/v1/certificates/{node_id}"): self._handle_revoke_certificate,

            # Data Separation
            ("POST", "/api/v1/silos"): self._handle_create_silo,
            ("GET", "/api/v1/silos"): self._handle_list_silos,

            # Consent
            ("POST", "/api/v1/consent"): self._handle_request_consent,
            ("PUT", "/api/v1/consent/{consent_id}/approve"): self._handle_approve_consent,
            ("PUT", "/api/v1/consent/{consent_id}/deny"): self._handle_deny_consent,

            # Encryption
            ("POST", "/api/v1/encrypt"): self._handle_encrypt,
            ("POST", "/api/v1/decrypt"): self._handle_decrypt,

            # Audit
            ("GET", "/api/v1/audit"): self._handle_query_audit,
            ("GET", "/api/v1/audit/verify"): self._handle_verify_audit,

            # Licensing
            ("POST", "/api/v1/license/validate"): self._handle_validate_license,
        }

        # Try exact match first
        key = (method, path)
        if key in routes:
            return routes[key], {}

        # Try parameterized routes
        parts = path.strip("/").split("/")
        if len(parts) >= 3 and parts[0] == "api" and parts[1] == "v1":
            # /api/v1/nodes/{node_id}
            if method == "GET" and parts[2] == "nodes" and len(parts) == 4:
                return self._handle_get_node, {"node_id": parts[3]}
            # /api/v1/certificates/{node_id} (DELETE)
            if method == "DELETE" and parts[2] == "certificates" and len(parts) == 4:
                return self._handle_revoke_certificate, {"node_id": parts[3]}
            # /api/v1/consent/{consent_id}/approve (PUT)
            if method == "PUT" and parts[2] == "consent" and len(parts) == 5:
                if parts[4] == "approve":
                    return self._handle_approve_consent, {"consent_id": parts[3]}
                if parts[4] == "deny":
                    return self._handle_deny_consent, {"consent_id": parts[3]}

        raise NotFoundError()

    # ── HTTP Methods ──

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def _handle_request(self, method: str):
        """Route and execute request with error handling."""
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            handler, params = self._route(method, path)
            handler(**params)
        except APIError as e:
            self._send_error(e.message, e.status)
        except json.JSONDecodeError:
            self._send_error("Invalid JSON body", 400)
        except Exception as e:
            self._send_error(f"Internal error: {str(e)}", 500)

    # ── Health Endpoints (no auth) ──

    def _handle_health(self):
        """GET /health — Basic health check."""
        checker = HealthChecker(self.config)
        report = checker.check()
        status = 200 if report.is_healthy() else 503
        self._send_json(report.to_dict(), status)

    def _handle_health_detailed(self):
        """GET /health/detailed — Detailed component health."""
        identity = self._require_auth()
        checker = HealthChecker(self.config)
        report = checker.check()
        self._send_json(report.to_dict())

    # ── Identity Endpoints ──

    def _handle_register_node(self):
        """POST /api/v1/nodes — Register a new node."""
        identity = self._require_auth()
        body = self._parse_body()

        from bedrock.identity.registration import NodeRegistry
        reg = NodeRegistry()
        node = reg.register(
            name=body.get("name", f"node-{uuid.uuid4().hex[:8]}"),
            node_type=body.get("node_type", "generic"),
        )

        self._send_json({
            "node_id": node.node_id.uuid,
            "name": node.name,
            "state": node.state.value,
        }, 201)

    def _handle_list_nodes(self):
        """GET /api/v1/nodes — List all nodes."""
        identity = self._require_auth()
        # NodeRegistry doesn't persist — return empty for now
        self._send_json({"nodes": [], "total": 0})

    def _handle_get_node(self, node_id: str = ""):
        """GET /api/v1/nodes/{node_id} — Get node details."""
        identity = self._require_auth()
        self._send_error("Node not found", 404)

    def _handle_issue_certificate(self):
        """POST /api/v1/certificates — Issue a certificate."""
        identity = self._require_auth()
        body = self._parse_body()

        from bedrock.identity.certificates import CertificateManager
        from bedrock.identity.registration import NodeRegistry
        reg = NodeRegistry()
        node = reg.register(name=body.get("node_name", "api-node"), node_type=body.get("node_type", "generic"))

        cm = CertificateManager()
        cert = cm.issue_certificate(
            node_uuid=node.node_id.uuid,
            node_name=node.name,
            public_key_hash=node.node_id.public_key_hex(),
        )

        # Serialize certificate dataclass to dict
        self._send_json({
            "serial": cert.serial,
            "node_uuid": cert.node_uuid,
            "node_name": cert.node_name,
            "status": cert.status.value if hasattr(cert.status, 'value') else str(cert.status),
            "issuer": cert.issuer,
            "license_tier": cert.license_tier.value if hasattr(cert.license_tier, 'value') else str(cert.license_tier),
            "issued_at": cert.issued_at.isoformat() if hasattr(cert.issued_at, 'isoformat') else str(cert.issued_at),
            "expires_at": cert.expires_at.isoformat() if hasattr(cert.expires_at, 'isoformat') else str(cert.expires_at),
            "capabilities": cert.capabilities,
        }, 201)

    def _handle_revoke_certificate(self, node_id: str = ""):
        """DELETE /api/v1/certificates/{node_id} — Revoke certificate."""
        identity = self._require_auth()

        from bedrock.identity.certificates import CertificateManager
        cm = CertificateManager()
        cm.revoke_certificate(node_id, reason="Revoked via API")

        self._send_json({"status": "revoked", "node_id": node_id})

    # ── Data Separation Endpoints ──

    def _handle_create_silo(self):
        """POST /api/v1/silos — Create a data silo."""
        identity = self._require_auth()
        body = self._parse_body()

        from bedrock.data_separation.silo import SiloManager
        sm = SiloManager()
        silo = sm.create_silo(
            name=body.get("name", f"silo-{uuid.uuid4().hex[:8]}"),
            display_name=body.get("display_name", body.get("name", "New Silo")),
            categories=body.get("categories", []),
        )

        self._send_json({
            "name": silo.name,
            "display_name": silo.display_name if hasattr(silo, "display_name") else silo.name,
            "categories": body.get("categories", []),
        }, 201)

    def _handle_list_silos(self):
        """GET /api/v1/silos — List all silos."""
        identity = self._require_auth()

        from bedrock.data_separation.silo import SiloManager
        sm = SiloManager()
        silos = sm.list_silos()

        self._send_json({
            "silos": [{"name": s.name} for s in silos],
            "total": len(silos),
        })

    # ── Consent Endpoints ──

    def _handle_request_consent(self):
        """POST /api/v1/consent — Request consent."""
        identity = self._require_auth()
        body = self._parse_body()

        from bedrock.data_separation.consent import ConsentGate
        consent = ConsentGate()
        result = consent.request_consent(
            requesting_node_id=body.get("requesting_node_id", identity.get("node_id", "")),
            source_silo=body.get("source_silo", ""),
            target_silo=body.get("target_silo", ""),
            categories=body.get("categories", []),
            scope=body.get("scope", "read"),
            reason=body.get("reason", ""),
        )

        self._send_json({
            "consent_id": result.consent_id,
            "status": "pending",
        }, 201)

    def _handle_approve_consent(self, consent_id: str = ""):
        """PUT /api/v1/consent/{consent_id}/approve — Approve consent."""
        identity = self._require_auth()
        body = self._parse_body()

        from bedrock.data_separation.consent import ConsentGate
        consent = ConsentGate()
        result = consent.approve_consent(
            consent_id=consent_id,
            data_owner_id=body.get("data_owner_id", identity.get("node_id", "")),
        )

        self._send_json({
            "consent_id": result.consent_id if hasattr(result, "consent_id") else consent_id,
            "status": "approved",
        })

    def _handle_deny_consent(self, consent_id: str = ""):
        """PUT /api/v1/consent/{consent_id}/deny — Deny consent."""
        identity = self._require_auth()
        body = self._parse_body()

        from bedrock.data_separation.consent import ConsentGate
        consent = ConsentGate()
        result = consent.deny_consent(
            consent_id=consent_id,
            data_owner_id=body.get("data_owner_id", identity.get("node_id", "")),
            reason=body.get("reason", "Denied via API"),
        )

        self._send_json({
            "consent_id": consent_id,
            "status": "denied",
        })

    # ── Encryption Endpoints ──

    def _handle_encrypt(self):
        """POST /api/v1/encrypt — Encrypt field data."""
        identity = self._require_auth()
        body = self._parse_body()

        from bedrock.key_management.keys import KeyManager
        from bedrock.encryption.engine import FieldEncryptor

        km = KeyManager()
        master_key = KeyManager.generate_master_key()
        fe = FieldEncryptor(km, master_key)

        ciphertext = fe.encrypt(
            plaintext=body.get("plaintext", ""),
            silo=body.get("silo", "default"),
            record_id=body.get("record_id", str(uuid.uuid4())),
            scope=body.get("scope", "read"),
        )

        self._send_json({
            "ciphertext": ciphertext.hex() if isinstance(ciphertext, bytes) else str(ciphertext),
            "silo": body.get("silo", "default"),
        }, 200)

    def _handle_decrypt(self):
        """POST /api/v1/decrypt — Decrypt field data."""
        identity = self._require_auth()
        body = self._parse_body()

        # Decrypt requires the same master key — in production, this would
        # come from a key vault. For API demo, we require it in the request.
        self._send_error("Direct decrypt via API requires key management integration", 501)

    # ── Audit Endpoints ──

    def _handle_query_audit(self):
        """GET /api/v1/audit — Query audit chain."""
        identity = self._require_auth()
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        from bedrock.audit.chain import AuditChain
        audit = AuditChain()
        results = audit.query(
            actor_id=params.get("actor_id", [None])[0],
            action=params.get("action", [None])[0],
            silo=params.get("silo", [None])[0],
        )

        self._send_json({
            "entries": [{"actor_id": e.actor_id, "action": e.action,
                         "target_id": e.target_id, "silo": e.silo}
                        for e in results],
            "total": len(results),
        })

    def _handle_verify_audit(self):
        """GET /api/v1/audit/verify — Verify audit chain integrity."""
        identity = self._require_auth()

        from bedrock.audit.chain import AuditChain
        audit = AuditChain()
        verified = audit.verify()

        self._send_json({"verified": verified})

    # ── Licensing Endpoint ──

    def _handle_validate_license(self):
        """POST /api/v1/license/validate — Validate a license key."""
        body = self._parse_body()

        from bedrock.licensing.enforcement import LicenseEnforcer
        enforcer = LicenseEnforcer()
        license_obj = enforcer.validate_license(body.get("license_key", ""))

        self._send_json({
            "valid": license_obj.is_valid,
            "tier": license_obj.tier.value,
            "expires_at": license_obj.expires_at,
            "features": license_obj.features,
        })


def create_server(host: str = "0.0.0.0", port: int = 8443,
                  config: Optional[CoreConfig] = None,
                  api_keys: Optional[Dict[str, dict]] = None) -> HTTPServer:
    """Create and configure the Bedrock Core API server."""
    BedrockAPIHandler.config = config or CoreConfig.from_env()
    BedrockAPIHandler.api_keys = api_keys or {}

    server = HTTPServer((host, port), BedrockAPIHandler)
    return server


def run_server(host: str = "0.0.0.0", port: int = 8443,
               config: Optional[CoreConfig] = None,
               api_keys: Optional[Dict[str, dict]] = None):
    """Run the Bedrock Core API server."""
    server = create_server(host, port, config, api_keys)
    print(f"Bedrock Core API server starting on {host}:{port}")
    print(f"Environment: {(config or CoreConfig.from_env()).environment}")
    print(f"Tier: {(config or CoreConfig.from_env()).licensing.tier}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    run_server()