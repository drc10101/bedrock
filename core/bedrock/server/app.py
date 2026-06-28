"""
Bedrock Core — FastAPI HTTP Server.

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

import time
import uuid
from typing import TYPE_CHECKING, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from bedrock.config import CoreConfig
from bedrock.health import HealthChecker
from bedrock.server.tls import TLSConfig
from bedrock.storage.persistence import PersistentBedrock
from bedrock.storage.sqlite_backend import SQLiteBackend

if TYPE_CHECKING:
    from bedrock.metering import UsageMeter


# ── Error classes (preserved for backward compat) �──


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


# ── FastAPI app factory ──


def create_app(
    config: CoreConfig | None = None,
    api_keys: dict[str, dict] | None = None,
    tls_config: Any | None = None,
    enable_metering: bool = True,
    db_path: str = "bedrock.db",
) -> FastAPI:
    """Create and configure the Bedrock Core FastAPI application.

    Args:
        config: Core configuration (loaded from env if not provided).
        api_keys: Dict of api_key -> {tier, node_id, roles}.
        tls_config: TLS configuration (used by uvicorn, not FastAPI directly).
        enable_metering: Whether to enable usage metering and rate limiting.
        db_path: Path to the SQLite database for persistence.

    Returns:
        Configured FastAPI application instance.
    """
    from bedrock.metering import UsageMeter

    effective_config = config or CoreConfig.from_env()
    effective_api_keys = api_keys or {}
    meter: UsageMeter | None = UsageMeter() if enable_metering else None
    persistent = PersistentBedrock(storage=SQLiteBackend(db_path))
    persistent.restore_all()

    app = FastAPI(
        title="Bedrock Core API",
        version="0.3.0",
        description="Identity-based security framework API",
        docs_url="/docs" if effective_config.debug else None,
        redoc_url="/redoc" if effective_config.debug else None,
    )

    # Store shared state on app.state for access in handlers
    app.state.config = effective_config
    app.state.api_keys = effective_api_keys
    app.state.usage_meter = meter
    app.state.persistent = persistent

    # ── Auth dependency ──

    async def _authenticate(authorization: str | None = Header(None)) -> dict[str, Any]:
        """Validate API key from Authorization header."""
        if not authorization:
            raise HTTPException(status_code=401, detail="Authentication required")

        api_key: str | None = None
        if authorization.startswith("Bearer ") or authorization.startswith("ApiKey "):
            api_key = authorization[7:]

        if not api_key or api_key not in effective_api_keys:
            raise HTTPException(status_code=401, detail="Invalid API key")

        return effective_api_keys[api_key]

    # ── Rate limiting middleware ──

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next: Any) -> Response:
        start_time = time.time()

        # Authenticate for rate limiting
        auth_header = request.headers.get("authorization", "")
        auth_key = ""
        tier = "developer"

        if auth_header and (auth_header.startswith("Bearer ") or auth_header.startswith("ApiKey ")):
            api_key = auth_header[7:]
            if api_key in effective_api_keys:
                identity = effective_api_keys[api_key]
                auth_key = identity.get("node_id", "")
                tier = identity.get("tier", "developer")

        # Rate limit check
        if meter and auth_key:
            allowed, reason = meter.check_rate_limit(auth_key, tier)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"error": f"Rate limit exceeded: {reason}", "status": 429},
                )

        # Process request
        response: Response = await call_next(request)

        # Record usage
        if meter and auth_key:
            elapsed_ms = (time.time() - start_time) * 1000
            meter.record_usage(
                license_key=auth_key,
                endpoint=request.url.path,
                method=request.method,
                status_code=response.status_code,
                response_time_ms=elapsed_ms,
                tier=tier,
            )

        # Add rate limit headers
        if meter and auth_key:
            rl_status = meter.get_rate_limit_status(auth_key)
            response.headers["X-RateLimit-Minute-Remaining"] = str(
                rl_status.get("minute_remaining", 0)
            )
            response.headers["X-RateLimit-Hour-Remaining"] = str(rl_status.get("hour_remaining", 0))

        response.headers["X-Request-Id"] = str(uuid.uuid4())
        return response

    # ── Health Endpoints (no auth) ──

    @app.get("/health")
    async def health_check() -> JSONResponse:
        """Basic health check."""
        checker = HealthChecker(effective_config)
        report = checker.check()
        status_code = 200 if report.is_healthy() else 503
        return JSONResponse(content=report.to_dict(), status_code=status_code)

    @app.get("/health/detailed")
    async def health_detailed(identity: dict[str, Any] = Depends(_authenticate)) -> dict[str, Any]:
        """Detailed component health (requires auth)."""
        checker = HealthChecker(effective_config)
        report = checker.check()
        return report.to_dict()

    # ── Identity Endpoints ──

    @app.post("/api/v1/nodes", status_code=201)
    async def register_node(
        request: Request, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Register a new node."""
        body = await request.json()
        node = persistent.registry.register(
            name=body.get("name", f"node-{uuid.uuid4().hex[:8]}"),
            node_type=body.get("node_type", "generic"),
        )
        persistent.save_node(node)
        return {
            "node_id": node.node_id.uuid,
            "name": node.name,
            "state": node.state.value,
        }

    @app.get("/api/v1/nodes")
    async def list_nodes(identity: dict[str, Any] = Depends(_authenticate)) -> dict[str, Any]:
        """List all nodes."""
        nodes = [
            {"node_id": n.node_id.uuid, "name": n.name, "state": n.state.value}
            for n in persistent.registry._nodes.values()
        ]
        return {"nodes": nodes, "total": len(nodes)}

    @app.get("/api/v1/nodes/{node_id}")
    async def get_node(
        node_id: str, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Get node details."""
        node = persistent.registry.get(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        return {
            "node_id": node.node_id.uuid,
            "name": node.name,
            "state": node.state.value,
        }

    @app.post("/api/v1/certificates", status_code=201)
    async def issue_certificate(
        request: Request, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Issue a certificate."""
        body = await request.json()
        # Look up existing node if node_uuid provided, otherwise register new
        node_uuid = body.get("node_uuid")
        if node_uuid:
            node = persistent.registry.get(node_uuid)
            if node is None:
                raise HTTPException(status_code=404, detail=f"Node {node_uuid} not found")
        else:
            node = persistent.registry.register(
                name=body.get("node_name", "api-node"),
                node_type=body.get("node_type", "generic"),
            )
            persistent.save_node(node)

        cert = persistent.cert_manager.issue_certificate(
            node_uuid=node.node_id.uuid,
            node_name=node.name,
            public_key_hash=node.node_id.public_key_hex(),
        )
        persistent.save_certificate(
            {
                "serial_number": cert.serial,
                "node_uuid": cert.node_uuid,
                "node_name": cert.node_name,
                "is_valid": True,
            }
        )

        return {
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
        }

    @app.delete("/api/v1/certificates/{node_id}")
    async def revoke_certificate(
        node_id: str, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Revoke a certificate."""
        try:
            persistent.cert_manager.revoke_certificate(node_id, reason="Revoked via API")
        except KeyError:
            raise HTTPException(
                status_code=404, detail=f"No certificate found for node '{node_id}'"
            ) from None
        return {"status": "revoked", "node_id": node_id}

    # ── Data Separation Endpoints ──

    @app.post("/api/v1/silos", status_code=201)
    async def create_silo(
        request: Request, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Create a data silo."""
        body = await request.json()
        silo = persistent.silo_manager.create_silo(
            name=body.get("name", f"silo-{uuid.uuid4().hex[:8]}"),
            display_name=body.get("display_name", body.get("name", "New Silo")),
            categories=body.get("categories", []),
        )
        persistent.save_silo(silo)

        return {
            "name": silo.name,
            "display_name": silo.display_name if hasattr(silo, "display_name") else silo.name,
            "categories": body.get("categories", []),
        }

    @app.get("/api/v1/silos")
    async def list_silos(identity: dict[str, Any] = Depends(_authenticate)) -> dict[str, Any]:
        """List all silos."""
        silos = persistent.silo_manager.list_silos()
        return {
            "silos": [{"name": s.name} for s in silos],
            "total": len(silos),
        }

    # ── Consent Endpoints ──

    @app.post("/api/v1/consent", status_code=201)
    async def request_consent(
        request: Request, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Request consent."""
        body = await request.json()
        result = persistent.consent_gate.request_consent(
            requesting_node_id=body.get("requesting_node_id", identity.get("node_id", "")),
            source_silo=body.get("source_silo", ""),
            target_silo=body.get("target_silo", ""),
            categories=body.get("categories", []),
            scope=body.get("scope", "read"),
            reason=body.get("reason", ""),
        )
        return {
            "consent_id": result.consent_id,
            "status": "pending",
        }

    @app.put("/api/v1/consent/{consent_id}/approve")
    async def approve_consent(
        consent_id: str, request: Request, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Approve consent."""
        body = await request.json()
        result = persistent.consent_gate.approve_consent(
            consent_id=consent_id,
            data_owner_id=body.get("data_owner_id", identity.get("node_id", "")),
        )
        return {
            "consent_id": result.consent_id if hasattr(result, "consent_id") else consent_id,
            "status": "approved",
        }

    @app.put("/api/v1/consent/{consent_id}/deny")
    async def deny_consent(
        consent_id: str, request: Request, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Deny consent."""
        body = await request.json()
        persistent.consent_gate.deny_consent(
            consent_id=consent_id,
            data_owner_id=body.get("data_owner_id", identity.get("node_id", "")),
            reason=body.get("reason", "Denied via API"),
        )
        return {
            "consent_id": consent_id,
            "status": "denied",
        }

    # ── Encryption Endpoints ──

    @app.post("/api/v1/encrypt")
    async def encrypt_field(
        request: Request, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Encrypt field data."""
        from bedrock.encryption.engine import FieldEncryptor
        from bedrock.key_management.keys import KeyManager

        body = await request.json()
        km = KeyManager()
        master_key = KeyManager.generate_master_key()
        fe = FieldEncryptor(km, master_key)

        ciphertext = fe.encrypt(
            plaintext=body.get("plaintext", ""),
            silo=body.get("silo", "default"),
            record_id=body.get("record_id", str(uuid.uuid4())),
            scope=body.get("scope", "read"),
        )

        return {
            "ciphertext": ciphertext.hex() if isinstance(ciphertext, bytes) else str(ciphertext),
            "silo": body.get("silo", "default"),
        }

    @app.post("/api/v1/decrypt")
    async def decrypt_field(
        request: Request, identity: dict[str, Any] = Depends(_authenticate)
    ) -> dict[str, Any]:
        """Decrypt field data."""
        raise HTTPException(
            status_code=501,
            detail="Direct decrypt via API requires key management integration",
        )

    # ── Audit Endpoints ──

    @app.get("/api/v1/audit")
    async def query_audit(
        actor_id: str | None = None,
        action: str | None = None,
        silo: str | None = None,
        identity: dict[str, Any] = Depends(_authenticate),
    ) -> dict[str, Any]:
        """Query audit chain."""
        results = persistent.audit_chain.query(
            actor_id=actor_id,
            action=action,
            silo=silo,
        )
        return {
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

    @app.get("/api/v1/audit/verify")
    async def verify_audit(identity: dict[str, Any] = Depends(_authenticate)) -> dict[str, Any]:
        """Verify audit chain integrity."""
        verified = persistent.audit_chain.verify()
        return {"verified": verified}

    # ── Licensing Endpoint ──

    @app.post("/api/v1/license/validate")
    async def validate_license(request: Request) -> dict[str, Any]:
        """Validate a license key."""
        from bedrock.licensing.enforcement import LicenseEnforcer, LicenseValidationError

        body = await request.json()
        enforcer = LicenseEnforcer()
        try:
            license_obj = enforcer.validate_license(body.get("license_key", ""))
        except LicenseValidationError as e:
            return {
                "valid": False,
                "tier": "unknown",
                "expires_at": None,
                "features": [],
                "error": str(e),
            }
        return {
            "valid": license_obj.is_valid,
            "tier": license_obj.tier.value,
            "expires_at": license_obj.expires_at,
            "features": license_obj.features,
        }

    # ── Usage Metering Endpoint ──

    @app.get("/api/v1/usage")
    async def get_usage(
        hours: float = Query(1.0),
        identity: dict[str, Any] = Depends(_authenticate),
    ) -> dict[str, Any]:
        """Get usage summary for authenticated key."""
        if not meter:
            return {"usage": {}, "message": "Usage metering not enabled"}

        license_key = identity.get("node_id", "")
        tier = identity.get("tier", "developer")
        summary = meter.get_usage_summary(license_key, tier, hours)
        rl_status = meter.get_rate_limit_status(license_key)

        return {
            "usage": {
                "total_requests": summary.total_requests,
                "requests_by_endpoint": summary.requests_by_endpoint,
                "requests_by_method": summary.requests_by_method,
                "requests_by_status": summary.requests_by_status,
                "avg_response_time_ms": round(summary.avg_response_time_ms, 2),
                "total_bytes_sent": summary.total_bytes_sent,
                "throttled_count": summary.rate_limit_throttled,
                "blocked_count": summary.rate_limit_blocked,
                "monthly_used": meter.get_monthly_usage(license_key),
            },
            "rate_limits": rl_status,
            "period_hours": hours,
        }

    # ── Lifespan event ──

    @app.on_event("startup")
    async def startup_event() -> None:
        scheme = "https" if (tls_config and tls_config.enabled) else "http"
        print(f"Bedrock Core API server started ({scheme})")
        print(f"Environment: {effective_config.environment}")
        print(f"Tier: {effective_config.licensing.tier}")
        print(f"Usage metering: {'enabled' if meter else 'disabled'}")

    return app


# ── Backward-compatible entry points ──


def create_server(
    host: str = "0.0.0.0",
    port: int = 8443,
    config: CoreConfig | None = None,
    api_keys: dict[str, dict] | None = None,
    tls_config: Any | None = None,
    enable_metering: bool = True,
    db_path: str = "bedrock.db",
) -> FastAPI:
    """Create and configure the Bedrock Core API application.

    Returns a FastAPI app instance. For backward compatibility, this
    function has the same signature as the old http.server version.

    Use run_server() to start serving with uvicorn.
    """
    app = create_app(
        config=config,
        api_keys=api_keys,
        tls_config=tls_config,
        enable_metering=enable_metering,
        db_path=db_path,
    )
    # Store bind info for run_server
    app.state.host = host
    app.state.port = port
    app.state.tls_config = tls_config
    return app


def run_server(
    host: str = "0.0.0.0",
    port: int = 8443,
    config: CoreConfig | None = None,
    api_keys: dict[str, dict] | None = None,
    tls_config: Any | None = None,
    enable_metering: bool = True,
    db_path: str = "bedrock.db",
) -> None:
    """Run the Bedrock Core API server with uvicorn.

    This is the production-grade server entry point. It uses uvicorn
    with proper connection handling, timeouts, and graceful shutdown.
    """
    import uvicorn

    app = create_server(host, port, config, api_keys, tls_config, enable_metering, db_path)

    effective_config = config or CoreConfig.from_env()

    # Determine TLS settings
    if tls_config is None:
        if effective_config.environment == "development":
            tls_config = TLSConfig.for_development()
        else:
            tls_config = TLSConfig.from_env()

    ssl_kwargs: dict[str, Any] = {}
    if tls_config and tls_config.enabled:
        from bedrock.server.tls import create_ssl_context

        ssl_kwargs["ssl"] = create_ssl_context(tls_config)
        scheme = "https"
    else:
        scheme = "http"

    print(f"Starting Bedrock Core API server on {scheme}://{host}:{port}")
    print(f"TLS: {'enabled' if (tls_config and tls_config.enabled) else 'disabled'}")
    if tls_config and tls_config.enabled:
        print(f"TLS version: {tls_config.min_version.name} - {tls_config.max_version.name}")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        timeout_keep_alive=30,
        **ssl_kwargs,
    )


if __name__ == "__main__":
    run_server()
