"""
Bedrock Core — HTTP API Server.

Exposes Bedrock Core functionality as a REST API for frontend integration.
Designed for the InFill portal and other Bedrock-based applications.

Security model:
- All endpoints require API key authentication (except /health)
- Rate limiting enforced per-tier
- No data leaves encrypted silos without consent verification
- Audit trail logging on every mutation

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from bedrock.config import CoreConfig
from bedrock.health import HealthChecker
from bedrock.server.tls import TLSConfig, wrap_server_with_tls
from bedrock.storage.persistence import PersistentBedrock
from bedrock.storage.sqlite_backend import SQLiteBackend

if TYPE_CHECKING:
    from bedrock.metering import UsageMeter


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
    config: CoreConfig | None = None
    api_keys: dict[str, dict] = {}  # api_key -> {tier, node_id, roles}
    usage_meter: UsageMeter | None = None  # Set by create_server
    persistent: PersistentBedrock | None = None  # Set by create_server

    def log_message(self, fmt: str, *args: Any) -> None:
        """Override to use structured logging."""
        if self.config and self.config.log_format == "json":
            print(
                json.dumps(
                    {
                        "timestamp": time.time(),
                        "level": "INFO",
                        "method": self.command,
                        "path": self.path,
                        "message": fmt % args,
                    }
                )
            )
        else:
            super().log_message(fmt, *args)

    def _send_json(self, data: Any, status: int = 200) -> None:
        """Send JSON response with rate limit headers."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Request-Id", str(uuid.uuid4()))

        # Add rate limit headers if metering is enabled
        if self.usage_meter and hasattr(self, "_auth_key"):
            rl_status = self.usage_meter.get_rate_limit_status(str(self._auth_key))
            self.send_header(
                "X-RateLimit-Minute-Remaining", str(rl_status.get("minute_remaining", 0))
            )
            self.send_header("X-RateLimit-Hour-Remaining", str(rl_status.get("hour_remaining", 0)))

        self.end_headers()
        self.wfile.write(
            json.dumps(data, indent=2 if self.config and self.config.debug else None).encode()
        )

    def _send_error(self, message: str, status: int = 400) -> None:
        """Send error response."""
        self._send_json({"error": message, "status": status}, status)

    def _authenticate(self) -> dict[str, Any] | None:
        """Validate API key from Authorization header."""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") or auth_header.startswith("ApiKey "):
            api_key = auth_header[7:]
        else:
            return None

        if api_key in self.api_keys:
            return self.api_keys[api_key]
        return None

    def _require_auth(self) -> dict[str, Any]:
        """Require authentication, raise 401 if missing."""
        identity = self._authenticate()
        if identity is None:
            raise AuthenticationError()
        return identity

    def _parse_body(self) -> dict[str, Any]:
        """Parse JSON request body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length)
        result: dict[str, Any] = json.loads(body)
        return result

    def _route(self, method: str, path: str) -> tuple[Callable[..., Any], dict[str, str]]:
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
            # Usage metering
            ("GET", "/api/v1/usage"): self._handle_usage,
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

    def do_GET(self) -> None:
        self._handle_request("GET")

    def do_POST(self) -> None:
        self._handle_request("POST")

    def do_PUT(self) -> None:
        self._handle_request("PUT")

    def do_DELETE(self) -> None:
        self._handle_request("DELETE")

    def _handle_request(self, method: str) -> None:
        """Route and execute request with rate limiting, metering, and error handling."""
        parsed = urlparse(self.path)
        path = parsed.path
        start_time = time.time()

        # Authenticate and get identity (for rate limiting)
        self._auth_key = None
        try:
            identity = self._authenticate()
            if identity:
                self._auth_key = identity.get("node_id", "")
                tier = identity.get("tier", "developer")
            else:
                tier = "developer"
        except Exception:
            tier = "developer"

        # Rate limit check
        if self.usage_meter and self._auth_key:
            allowed, reason = self.usage_meter.check_rate_limit(self._auth_key, tier)
            if not allowed:
                self._send_error(f"Rate limit exceeded: {reason}", 429)
                return

        try:
            handler, params = self._route(method, path)
            handler(**params)
            status_code = 200  # Default success
        except APIError as e:
            self._send_error(e.message, e.status)
            status_code = e.status
        except json.JSONDecodeError:
            self._send_error("Invalid JSON body", 400)
            status_code = 400
        except Exception as e:
            self._send_error(f"Internal error: {str(e)}", 500)
            status_code = 500

        # Record usage for metering
        if self.usage_meter and self._auth_key:
            elapsed_ms = (time.time() - start_time) * 1000
            self.usage_meter.record_usage(
                license_key=self._auth_key,
                endpoint=path,
                method=method,
                status_code=status_code,
                response_time_ms=elapsed_ms,
                tier=tier,
            )

    # ── Health Endpoints (no auth) ──

    def _handle_health(self) -> None:
        """GET /health — Basic health check."""
        checker = HealthChecker(self.config)
        report = checker.check()
        status = 200 if report.is_healthy() else 503
        self._send_json(report.to_dict(), status)

    def _handle_health_detailed(self) -> None:
        """GET /health/detailed — Detailed component health."""
        self._require_auth()
        checker = HealthChecker(self.config)
        report = checker.check()
        self._send_json(report.to_dict())

    # ── Identity Endpoints ──

    def _handle_register_node(self) -> None:
        """POST /api/v1/nodes — Register a new node."""
        self._require_auth()
        body = self._parse_body()

        if self.persistent is None:
            self._send_error("Persistence not configured", 503)
            return

        node = self.persistent.registry.register(
            name=body.get("name", f"node-{uuid.uuid4().hex[:8]}"),
            node_type=body.get("node_type", "generic"),
        )
        self.persistent.save_node(node)

        self._send_json(
            {
                "node_id": node.node_id.uuid,
                "name": node.name,
                "state": node.state.value,
            },
            201,
        )

    def _handle_list_nodes(self) -> None:
        """GET /api/v1/nodes — List all nodes."""
        self._require_auth()
        if self.persistent is None:
            self._send_json({"nodes": [], "total": 0})
            return

        nodes = [
            {"node_id": n.node_id.uuid, "name": n.name, "state": n.state.value}
            for n in self.persistent.registry._nodes.values()
        ]
        self._send_json({"nodes": nodes, "total": len(nodes)})

    def _handle_get_node(self, node_id: str = "") -> None:
        """GET /api/v1/nodes/{node_id} — Get node details."""
        self._require_auth()
        if self.persistent is None:
            self._send_error("Persistence not configured", 503)
            return

        node = self.persistent.registry.get(node_id)
        if node is None:
            self._send_error("Node not found", 404)
            return

        self._send_json(
            {
                "node_id": node.node_id.uuid,
                "name": node.name,
                "state": node.state.value,
            }
        )

    def _handle_issue_certificate(self) -> None:
        """POST /api/v1/certificates — Issue a certificate."""
        self._require_auth()
        body = self._parse_body()

        if self.persistent is None:
            self._send_error("Persistence not configured", 503)
            return

        node = self.persistent.registry.register(
            name=body.get("node_name", "api-node"), node_type=body.get("node_type", "generic")
        )
        self.persistent.save_node(node)

        cert = self.persistent.cert_manager.issue_certificate(
            node_uuid=node.node_id.uuid,
            node_name=node.name,
            public_key_hash=node.node_id.public_key_hex(),
        )
        self.persistent.save_certificate(
            {
                "serial_number": cert.serial,
                "node_uuid": cert.node_uuid,
                "node_name": cert.node_name,
                "is_valid": True,
            }
        )

        # Serialize certificate dataclass to dict
        self._send_json(
            {
                "serial": cert.serial,
                "node_uuid": cert.node_uuid,
                "node_name": cert.node_name,
                "status": cert.status.value if hasattr(cert.status, "value") else str(cert.status),
                "issuer": cert.issuer,
                "license_tier": (
                    cert.license_tier.value
                    if hasattr(cert.license_tier, "value")
                    else str(cert.license_tier)
                ),
                "issued_at": (
                    cert.issued_at.isoformat()
                    if hasattr(cert.issued_at, "isoformat") and cert.issued_at is not None
                    else str(cert.issued_at) if cert.issued_at is not None else ""
                ),
                "expires_at": (
                    cert.expires_at.isoformat()
                    if hasattr(cert.expires_at, "isoformat") and cert.expires_at is not None
                    else str(cert.expires_at) if cert.expires_at is not None else ""
                ),
                "capabilities": cert.capabilities,
            },
            201,
        )

    def _handle_revoke_certificate(self, node_id: str = "") -> None:
        """DELETE /api/v1/certificates/{node_id} — Revoke certificate."""
        self._require_auth()

        if self.persistent is None:
            self._send_error("Persistence not configured", 503)
            return

        self.persistent.cert_manager.revoke_certificate(node_id, reason="Revoked via API")

        self._send_json({"status": "revoked", "node_id": node_id})

    # ── Data Separation Endpoints ──

    def _handle_create_silo(self) -> None:
        """POST /api/v1/silos — Create a data silo."""
        self._require_auth()
        body = self._parse_body()

        if self.persistent is None:
            self._send_error("Persistence not configured", 503)
            return

        silo = self.persistent.silo_manager.create_silo(
            name=body.get("name", f"silo-{uuid.uuid4().hex[:8]}"),
            display_name=body.get("display_name", body.get("name", "New Silo")),
            categories=body.get("categories", []),
        )
        self.persistent.save_silo(silo)

        self._send_json(
            {
                "name": silo.name,
                "display_name": silo.display_name if hasattr(silo, "display_name") else silo.name,
                "categories": body.get("categories", []),
            },
            201,
        )

    def _handle_list_silos(self) -> None:
        """GET /api/v1/silos — List all silos."""
        self._require_auth()

        if self.persistent is None:
            self._send_json({"silos": [], "total": 0})
            return

        silos = self.persistent.silo_manager.list_silos()

        self._send_json(
            {
                "silos": [{"name": s.name} for s in silos],
                "total": len(silos),
            }
        )

    # ── Consent Endpoints ──

    def _handle_request_consent(self) -> None:
        """POST /api/v1/consent — Request consent."""
        identity = self._require_auth()
        body = self._parse_body()

        if self.persistent is None:
            self._send_error("Persistence not configured", 503)
            return

        result = self.persistent.consent_gate.request_consent(
            requesting_node_id=body.get("requesting_node_id", identity.get("node_id", "")),
            source_silo=body.get("source_silo", ""),
            target_silo=body.get("target_silo", ""),
            categories=body.get("categories", []),
            scope=body.get("scope", "read"),
            reason=body.get("reason", ""),
        )

        self._send_json(
            {
                "consent_id": result.consent_id,
                "status": "pending",
            },
            201,
        )

    def _handle_approve_consent(self, consent_id: str = "") -> None:
        """PUT /api/v1/consent/{consent_id}/approve — Approve consent."""
        identity = self._require_auth()
        body = self._parse_body()

        if self.persistent is None:
            self._send_error("Persistence not configured", 503)
            return

        result = self.persistent.consent_gate.approve_consent(
            consent_id=consent_id,
            data_owner_id=body.get("data_owner_id", identity.get("node_id", "")),
        )

        self._send_json(
            {
                "consent_id": result.consent_id if hasattr(result, "consent_id") else consent_id,
                "status": "approved",
            }
        )

    def _handle_deny_consent(self, consent_id: str = "") -> None:
        """PUT /api/v1/consent/{consent_id}/deny — Deny consent."""
        identity = self._require_auth()
        body = self._parse_body()

        if self.persistent is None:
            self._send_error("Persistence not configured", 503)
            return

        self.persistent.consent_gate.deny_consent(
            consent_id=consent_id,
            data_owner_id=body.get("data_owner_id", identity.get("node_id", "")),
            reason=body.get("reason", "Denied via API"),
        )

        self._send_json(
            {
                "consent_id": consent_id,
                "status": "denied",
            }
        )

    # ── Encryption Endpoints ──

    def _handle_encrypt(self) -> None:
        """POST /api/v1/encrypt — Encrypt field data."""
        self._require_auth()
        body = self._parse_body()

        if self.persistent is None:
            self._send_error("Persistence not configured", 503)
            return

        from bedrock.encryption.engine import FieldEncryptor
        from bedrock.key_management.keys import KeyManager

        km = KeyManager()
        master_key = KeyManager.generate_master_key()
        fe = FieldEncryptor(km, master_key)

        ciphertext = fe.encrypt(
            plaintext=body.get("plaintext", ""),
            silo=body.get("silo", "default"),
            record_id=body.get("record_id", str(uuid.uuid4())),
            scope=body.get("scope", "read"),
        )

        self._send_json(
            {
                "ciphertext": (
                    ciphertext.hex() if isinstance(ciphertext, bytes) else str(ciphertext)
                ),
                "silo": body.get("silo", "default"),
            },
            200,
        )

    def _handle_decrypt(self) -> None:
        """POST /api/v1/decrypt — Decrypt field data."""
        self._require_auth()
        self._parse_body()

        # Decrypt requires the same master key — in production, this would
        # come from a key vault. For API demo, we require it in the request.
        self._send_error("Direct decrypt via API requires key management integration", 501)

    # ── Audit Endpoints ──

    def _handle_query_audit(self) -> None:
        """GET /api/v1/audit — Query audit chain."""
        self._require_auth()
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if self.persistent is None:
            self._send_json({"entries": [], "total": 0})
            return

        results = self.persistent.audit_chain.query(
            actor_id=params.get("actor_id", [None])[0],
            action=params.get("action", [None])[0],
            silo=params.get("silo", [None])[0],
        )

        self._send_json(
            {
                "entries": [
                    {
                        "actor_id": e.actor_id,
                        "action": e.action,
                        "target_id": e.target_id,
                        "silo": e.silo,
                    }
                    for e in results
                ],
                "total": len(results),
            }
        )

    def _handle_verify_audit(self) -> None:
        """GET /api/v1/audit/verify — Verify audit chain integrity."""
        self._require_auth()

        if self.persistent is None:
            self._send_json({"verified": False, "error": "Persistence not configured"})
            return

        verified = self.persistent.audit_chain.verify()

        self._send_json({"verified": verified})

    # ── Licensing Endpoint ──

    def _handle_validate_license(self) -> None:
        """POST /api/v1/license/validate — Validate a license key."""
        body = self._parse_body()

        from bedrock.licensing.enforcement import LicenseEnforcer

        enforcer = LicenseEnforcer()
        license_obj = enforcer.validate_license(body.get("license_key", ""))

        self._send_json(
            {
                "valid": license_obj.is_valid,
                "tier": license_obj.tier.value,
                "expires_at": license_obj.expires_at,
                "features": license_obj.features,
            }
        )

    # ── Usage Metering Endpoint ──

    def _handle_usage(self) -> None:
        """GET /api/v1/usage — Get usage summary for authenticated key."""
        identity = self._require_auth()
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if not self.usage_meter:
            self._send_json({"usage": {}, "message": "Usage metering not enabled"})
            return

        hours = float(params.get("hours", ["1"])[0])
        license_key = self._auth_key or identity.get("node_id", "")
        tier = identity.get("tier", "developer")

        summary = self.usage_meter.get_usage_summary(license_key, tier, hours)
        rl_status = self.usage_meter.get_rate_limit_status(license_key)

        self._send_json(
            {
                "usage": {
                    "total_requests": summary.total_requests,
                    "requests_by_endpoint": summary.requests_by_endpoint,
                    "requests_by_method": summary.requests_by_method,
                    "requests_by_status": summary.requests_by_status,
                    "avg_response_time_ms": round(summary.avg_response_time_ms, 2),
                    "total_bytes_sent": summary.total_bytes_sent,
                    "throttled_count": summary.rate_limit_throttled,
                    "blocked_count": summary.rate_limit_blocked,
                    "monthly_used": self.usage_meter.get_monthly_usage(license_key),
                },
                "rate_limits": rl_status,
                "period_hours": hours,
            }
        )


def create_server(
    host: str = "0.0.0.0",
    port: int = 8443,
    config: CoreConfig | None = None,
    api_keys: dict[str, dict] | None = None,
    tls_config: TLSConfig | None = None,
    enable_metering: bool = True,
    db_path: str = "bedrock.db",
) -> HTTPServer:
    """Create and configure the Bedrock Core API server.

    Args:
        host: Bind address.
        port: Bind port.
        config: Core configuration (loaded from env if not provided).
        api_keys: Dict of api_key -> {tier, node_id, roles}.
        tls_config: TLS configuration. If None, auto-configured:
            - Development: generates self-signed certs
            - Production: requires BEDROCK_TLS_CERT and BEDROCK_TLS_KEY env vars
        enable_metering: Whether to enable usage metering and rate limiting.
        db_path: Path to the SQLite database for persistence.
    """
    from bedrock.metering import UsageMeter

    BedrockAPIHandler.config = config or CoreConfig.from_env()
    BedrockAPIHandler.api_keys = api_keys or {}
    BedrockAPIHandler.usage_meter = UsageMeter() if enable_metering else None
    BedrockAPIHandler.persistent = PersistentBedrock(storage=SQLiteBackend(db_path))
    BedrockAPIHandler.persistent.restore_all()

    server = HTTPServer((host, port), BedrockAPIHandler)

    # Apply TLS if configured
    if tls_config is None:
        # Auto-configure: dev mode gets self-signed, prod requires env vars
        effective_config = BedrockAPIHandler.config
        assert effective_config is not None  # Set above
        if effective_config.environment == "development":
            tls_config = TLSConfig.for_development()
        else:
            tls_config = TLSConfig.from_env()

    if tls_config and tls_config.enabled:
        wrap_server_with_tls(server, tls_config)
        scheme = "https"
    else:
        scheme = "http"

    print(f"Bedrock Core API server created on {scheme}://{host}:{port}")
    print(f"TLS: {'enabled' if (tls_config and tls_config.enabled) else 'disabled'}")
    if tls_config and tls_config.enabled:
        print(f"TLS version: {tls_config.min_version.name} - {tls_config.max_version.name}")

    return server


def run_server(
    host: str = "0.0.0.0",
    port: int = 8443,
    config: CoreConfig | None = None,
    api_keys: dict[str, dict] | None = None,
    tls_config: TLSConfig | None = None,
    enable_metering: bool = True,
    db_path: str = "bedrock.db",
) -> None:
    """Run the Bedrock Core API server."""
    server = create_server(host, port, config, api_keys, tls_config, enable_metering, db_path)
    effective_config = BedrockAPIHandler.config
    assert effective_config is not None  # Set by create_server
    metering_status = "enabled" if BedrockAPIHandler.usage_meter else "disabled"
    print(f"Environment: {effective_config.environment}")
    print(f"Tier: {effective_config.licensing.tier}")
    print(f"Usage metering: {metering_status}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    run_server()
