"""
Bedrock CLI — Developer onboarding and management command-line tool.

Provides:
  bedrock init      — Initialize a new Bedrock project
  bedrock serve     — Start the API server
  bedrock keygen    — Generate signing keys
  bedrock license   — Issue and validate license keys
  bedrock trial     — Generate a free 30-day trial license
  bedrock health    — Run health checks
  bedrock status    — Show system status and config summary
  bedrock version   — Show version info
"""

import argparse
import contextlib
import json
import os
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from bedrock.config import CoreConfig
from bedrock.health import HealthChecker
from bedrock.licensing.enforcement import LicenseEnforcer, LicenseTier
from bedrock.licensing.keygen import LicenseKeygen

VERSION = "0.3.0"


def cmd_init(args):
    """Initialize a new Bedrock project directory."""
    project_dir = Path(args.directory).resolve()
    project_dir.mkdir(parents=True, exist_ok=True)

    # Create directory structure
    dirs = [
        "config",
        "data",
        "data/audit",
        "data/keys",
        "logs",
    ]
    for d in dirs:
        (project_dir / d).mkdir(parents=True, exist_ok=True)

    # Generate default config
    config = CoreConfig.from_env()
    config_path = project_dir / "config" / "bedrock.json"
    config_data = {
        "environment": config.environment,
        "debug": config.debug,
        "log_level": config.log_level,
        "log_format": config.log_format,
        "encryption": {
            "master_key_source": config.encryption.master_key_source,
            "hkdf_hash": config.encryption.hkdf_hash,
            "hkdf_info_prefix": config.encryption.hkdf_info_prefix,
            "field_cipher": config.encryption.field_cipher,
            "e2ee_curve": config.encryption.e2ee_curve,
        },
        "identity": {
            "node_id_version": config.identity.node_id_version,
            "attestation_required": config.identity.attestation_required,
            "cert_default_ttl_hours": config.identity.cert_default_ttl_hours,
            "cert_key_type": config.identity.cert_key_type,
        },
        "licensing": {
            "tier": config.licensing.tier,
            "dev_mode": config.licensing.dev_mode,
            "dev_max_nodes": config.licensing.dev_max_nodes,
        },
    }

    with open(config_path, "w") as f:
        json.dump(config_data, f, indent=2)

    # Generate a master encryption key
    import secrets

    master_key_path = project_dir / "data" / "keys" / "master.key"
    if not master_key_path.exists():
        master_key = secrets.token_hex(32)  # 256-bit key
        with open(master_key_path, "w") as f:
            f.write(master_key)
        # Restrict permissions (Unix)
        with contextlib.suppress(OSError, AttributeError):
            os.chmod(master_key_path, 0o600)

    # Generate a signing key for license issuance
    keygen = LicenseKeygen()
    signing_key = keygen.generate_signing_key()
    keys_path = project_dir / "data" / "keys" / "signing_keys.json"
    keygen.export_keys_file(keys_path)

    # Create .env template
    env_path = project_dir / "config" / ".env.template"
    env_content = """# Bedrock Environment Configuration
BEDROCK_ENV=development
BEDROCK_DEBUG=false
BEDROCK_LOG_LEVEL=INFO
BEDROCK_DEV_MODE=true
BEDROCK_TIER=developer
BEDROCK_MASTER_KEY=<from data/keys/master.key>

# License signing key (required in production)
# BEDROCK_SIGNING_KEY=<your-signing-key>

# Stripe integration (required for paid license billing)
# BEDROCK_STRIPE_PRODUCT_ID=<your-stripe-product-id>
# BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL=<your-stripe-price-id>
# BEDROCK_STRIPE_PRICE_DEV_TEAM=<your-stripe-price-id>

# TLS (production only)
# BEDROCK_TLS_CERT=/path/to/cert.pem
# BEDROCK_TLS_KEY=/path/to/key.pem
"""
    with open(env_path, "w") as f:
        f.write(env_content)

    print(f"Bedrock project initialized in: {project_dir}")
    print(f"  Config:       {config_path}")
    print(f"  Master key:   {master_key_path}")
    print(f"  Signing key:  {signing_key.key_id}")
    print(f"  Keys file:    {keys_path}")
    print(f"  Env template:  {env_path}")
    print()
    print("Next steps:")
    print(f"  1. cd {project_dir}")
    print("  2. Copy .env.template to .env and configure")
    print("  3. Run: bedrock serve")
    return 0


def cmd_serve(args):
    """Start the Bedrock API server."""
    from bedrock.server.app import run_server
    from bedrock.server.tls import TLSConfig

    config = CoreConfig.from_env()

    # Load TLS config
    if config.environment == "development":
        tls_config = TLSConfig.for_development()
    else:
        tls_config = TLSConfig.from_env()

    # Load API keys from env or file
    api_keys = {}
    api_keys_json = os.environ.get("BEDROCK_API_KEYS", "")
    if api_keys_json:
        try:
            api_keys = json.loads(api_keys_json)
        except json.JSONDecodeError:
            print("Warning: BEDROCK_API_KEYS env var is not valid JSON, using empty keys")

    print("Starting Bedrock API server...")
    print(f"  Host: {args.host}")
    print(f"  Port: {args.port}")
    print(f"  Environment: {config.environment}")
    print(f"  Tier: {config.licensing.tier}")

    run_server(
        host=args.host,
        port=args.port,
        config=config,
        api_keys=api_keys,
        tls_config=tls_config,
        enable_metering=not args.no_metering,
    )
    return 0


def cmd_keygen(args):
    """Generate a new signing key."""
    keygen = _load_keygen(args)

    signing_key = keygen.generate_signing_key(key_id=args.key_id or "")

    # Save keys
    keys_path = Path(args.keys_file)
    keygen.export_keys_file(keys_path)

    print("Signing key generated:")
    print(f"  Key ID:    {signing_key.key_id}")
    print(f"  Algorithm: {signing_key.algorithm}")
    print(f"  Created:   {signing_key.created_at}")
    print(f"  Active:    {signing_key.is_active}")
    print(f"  Saved to:  {keys_path}")
    return 0


def cmd_license(args):
    """License management commands."""
    if args.license_action == "issue":
        return _license_issue(args)
    elif args.license_action == "validate":
        return _license_validate(args)
    elif args.license_action == "revoke":
        return _license_revoke(args)
    elif args.license_action == "info":
        return _license_info(args)
    else:
        print(f"Unknown license action: {args.license_action}")
        return 1


def _license_issue(args):
    """Issue a new license key."""
    keygen = _load_keygen(args)

    # Get the active signing key
    keys = keygen.list_keys(active_only=True)
    if not keys:
        print("Error: No active signing keys. Run 'bedrock keygen' first.")
        return 1

    signing_key = keys[0]  # Use first active key

    # Map tier string to LicenseTier enum
    tier_map = {
        "trial": LicenseTier.TRIAL,
        "developer": LicenseTier.DEVELOPER,
        "starter": LicenseTier.STARTER,
        "business": LicenseTier.BUSINESS,
        "enterprise": LicenseTier.ENTERPRISE,
    }
    tier = tier_map.get(args.tier, LicenseTier.DEVELOPER)

    features = args.features.split(",") if args.features else []

    license_key = keygen.issue_license(
        key=signing_key,
        tier=tier,
        issued_to=args.licensee,
        max_nodes=args.nodes,
        expires_days=args.days,
        features=features or None,
    )

    print("License key issued:")
    print(f"  Key:      {license_key}")
    print(f"  Tier:     {args.tier}")
    print(f"  Licensee: {args.licensee}")
    print(f"  Nodes:    {args.nodes}")
    if args.days:
        print(f"  Expires:  {args.days} days from now")
    if features:
        print(f"  Features: {', '.join(features)}")

    # Save updated keys (license keys are derived from signing keys)
    keys_path = Path(args.keys_file)
    keygen.export_keys_file(keys_path)
    return 0


def _license_validate(args):
    """Validate a license key."""
    from bedrock.licensing.enforcement import LicenseValidationError

    enforcer = LicenseEnforcer()
    try:
        license_obj = enforcer.validate_license(args.key)
        print("License validation result:")
        print(f"  Valid:    {license_obj.is_valid}")
        if license_obj.is_valid:
            print(f"  Tier:     {license_obj.tier.value}")
            print(f"  Licensee: {license_obj.issued_to}")
            print(f"  Expires:  {license_obj.expires_at}")
            if hasattr(license_obj, "features") and license_obj.features:
                print(
                    f"  Features: {', '.join(license_obj.features) if isinstance(license_obj.features, list) else license_obj.features}"
                )
            if license_obj.is_expired():
                print("  WARNING: License has expired")
            return 0
        else:
            print("  Reason:   Invalid license")
            return 1
    except LicenseValidationError as e:
        print("License validation result:")
        print("  Valid:    False")
        print(f"  Reason:   {str(e)}")
        return 1


def _license_revoke(args):
    """Revoke a signing key."""
    keygen = _load_keygen(args)
    success = keygen.revoke_key(args.key_id, reason=args.reason or "Manual revocation")

    if success:
        print(f"Signing key {args.key_id} revoked.")
        keys_path = Path(args.keys_file)
        keygen.export_keys_file(keys_path)
        return 0
    else:
        print(f"Signing key {args.key_id} not found.")
        return 1


def _license_info(args):
    """Show info about a license key (parse without full validation)."""
    parts = args.key.split(":")
    if len(parts) >= 2:
        print("License key info:")
        print(f"  Version: {parts[0] if parts else 'unknown'}")
        print(f"  Key:     {args.key[:20]}...")
    else:
        print(f"Key format not recognized: {args.key}")
    return 0


def cmd_health(args):
    """Run health checks."""
    config = CoreConfig.from_env()
    checker = HealthChecker(config)
    report = checker.check()

    print("Bedrock Health Check")
    print(f"{'=' * 40}")
    print(f"Overall: {'HEALTHY' if report.is_healthy() else 'UNHEALTHY'}")
    print()

    for name, status in report.components.items():
        icon = "+" if status.healthy else "X"
        print(f"  [{icon}] {name}: {status.message}")
        if not status.healthy and status.details:
            for key, value in status.details.items():
                print(f"      {key}: {value}")

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))

    return 0 if report.is_healthy() else 1


def cmd_status(args):
    """Show system status and configuration summary."""
    config = CoreConfig.from_env()

    print("Bedrock Status")
    print(f"{'=' * 40}")
    print(f"  Version:      {VERSION}")
    print(f"  Environment:  {config.environment}")
    print(f"  Tier:         {config.licensing.tier}")
    print(f"  Dev mode:     {config.licensing.dev_mode}")
    print(f"  Debug:        {config.debug}")
    print(f"  Log level:    {config.log_level}")
    print(f"  Log format:   {config.log_format}")
    print()
    print("  Encryption:")
    print(f"    Cipher:     {config.encryption.field_cipher}")
    print(f"    E2EE curve:  {config.encryption.e2ee_curve}")
    print(f"    HKDF hash:  {config.encryption.hkdf_hash}")
    print()
    print("  Identity:")
    print(f"    Node ID v:  {config.identity.node_id_version}")
    print(f"    Cert TTL:   {config.identity.cert_default_ttl_hours}h")
    print(f"    Key type:   {config.identity.cert_key_type}")
    print()
    print("  Data Separation:")
    print(f"    Strict mode: {config.data_separation.silo_strict_mode}")
    print(f"    Encryption:  {config.data_separation.silo_default_encryption}")
    print()
    print("  Audit:")
    print(f"    Hash algo:   {config.audit.hash_algo}")
    print(f"    Retention:   {config.audit.retention_years} years")
    print()
    print("  Access Control:")
    print(f"    RBAC:        {config.access_control.rbac_enforce}")
    print(f"    MFA:         {config.access_control.mfa_required}")
    print()
    print("  Licensing:")
    print(f"    Dev nodes:   {config.licensing.dev_max_nodes}")
    print(f"    CA activated: {config.licensing.runtime_ca_activated}")
    print(f"    Phone home:  {config.licensing.phone_home_enabled}")

    return 0


def cmd_trial(args):
    """Generate a free 30-day trial license key."""
    enforcer = LicenseEnforcer()
    license_key = enforcer.issue_trial_license(issued_to=args.licensee)

    # Validate it immediately to show details
    license_obj = enforcer.validate_license(license_key)

    print("Bedrock Trial License")
    print(f"{'=' * 40}")
    print(f"  License key: {license_key}")
    print(f"  Tier:        {license_obj.tier.value}")
    print(f"  Licensee:    {license_obj.issued_to}")
    print(f"  Nodes:       {license_obj.max_nodes}")
    print("  Expires:     30 days from now")
    print(f"  Features:    {', '.join(license_obj.features)}")
    print()
    print("Save this key to /etc/bedrock/license.key or set BEDROCK_LICENSE_KEY.")
    print("After 30 days, upgrade at https://bedrock.dev/pricing")
    return 0


def cmd_checkout(args):
    """Create a Stripe checkout session for a paid license."""
    from bedrock.licensing.checkout import CheckoutTier, create_checkout_session

    tier_map = {
        "developer_individual": CheckoutTier.DEVELOPER_INDIVIDUAL,
        "developer_team": CheckoutTier.DEVELOPER_TEAM,
    }
    tier = tier_map[args.tier]

    try:
        result = create_checkout_session(
            tier=tier,
            customer_email=args.email,
            success_url=args.success_url,
            cancel_url=args.cancel_url,
        )
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        print(
            "Make sure BEDROCK_STRIPE_SECRET_KEY and BEDROCK_STRIPE_PRICE_* are set.",
            file=sys.stderr,
        )
        return 1
    except Exception as e:
        print(f"Stripe error: {e}", file=sys.stderr)
        return 1

    print(f"Bedrock Checkout — {args.tier}")
    print(f"{'=' * 40}")
    print(f"  Session ID: {result.session_id}")
    print(f"  Checkout URL: {result.session_url}")
    print()
    print("  Open the checkout URL in a browser to complete payment.")
    return 0


def cmd_webhook(args):
    """Start the Stripe webhook server for license delivery."""
    from bedrock.licensing.webhook import run_webhook_server

    port = args.port or int(os.environ.get("WEBHOOK_PORT", "8444"))

    # Verify required env vars
    required = ["BEDROCK_STRIPE_SECRET_KEY", "BEDROCK_STRIPE_WEBHOOK_SECRET", "BEDROCK_SIGNING_KEY"]
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        print(f"Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
        return 1

    run_webhook_server(host=args.host, port=port)
    return 0


def _load_keygen(args):
    """Load LicenseKeygen with existing keys or create new."""
    keys_path = Path(args.keys_file) if args.keys_file else Path("data/keys/signing_keys.json")

    if keys_path.exists():
        return LicenseKeygen.from_file(keys_path)
    else:
        # Ensure parent directory exists
        keys_path.parent.mkdir(parents=True, exist_ok=True)
        return LicenseKeygen()


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="bedrock",
        description="Bedrock — Identity-based security framework CLI",
    )
    parser.add_argument("--version", action="version", version=f"Bedrock {VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize a new Bedrock project")
    init_parser.add_argument(
        "directory", nargs="?", default=".", help="Project directory (default: current)"
    )
    init_parser.set_defaults(func=cmd_init)

    # serve
    serve_parser = subparsers.add_parser("serve", help="Start the API server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    serve_parser.add_argument("--port", type=int, default=8443, help="Bind port (default: 8443)")
    serve_parser.add_argument(
        "--keys-file", default="data/keys/signing_keys.json", help="Path to signing keys file"
    )
    serve_parser.add_argument("--no-metering", action="store_true", help="Disable usage metering")
    serve_parser.set_defaults(func=cmd_serve)

    # keygen
    keygen_parser = subparsers.add_parser("keygen", help="Generate a signing key")
    keygen_parser.add_argument("--key-id", help="Custom key ID (auto-generated if omitted)")
    keygen_parser.add_argument(
        "--keys-file", default="data/keys/signing_keys.json", help="Path to signing keys file"
    )
    keygen_parser.set_defaults(func=cmd_keygen)

    # license
    license_parser = subparsers.add_parser("license", help="License management")
    license_parser.add_argument(
        "license_action", choices=["issue", "validate", "revoke", "info"], help="License action"
    )
    license_parser.add_argument(
        "--tier",
        default="developer",
        choices=["trial", "developer", "starter", "business", "enterprise"],
        help="License tier",
    )
    license_parser.add_argument("--licensee", default="unknown", help="Licensee name or ID")
    license_parser.add_argument("--nodes", type=int, default=3, help="Max nodes for license")
    license_parser.add_argument("--days", type=int, help="License validity in days")
    license_parser.add_argument("--features", help="Comma-separated feature list")
    license_parser.add_argument("--key", help="License key to validate/info")
    license_parser.add_argument("--key-id", help="Signing key ID to revoke")
    license_parser.add_argument("--reason", help="Reason for revocation")
    license_parser.add_argument(
        "--keys-file", default="data/keys/signing_keys.json", help="Path to signing keys file"
    )
    license_parser.set_defaults(func=cmd_license)

    # trial
    trial_parser = subparsers.add_parser("trial", help="Generate a free 30-day trial license")
    trial_parser.add_argument(
        "--licensee", default="trial-user", help="Name or email for the trial"
    )
    trial_parser.add_argument(
        "--keys-file", default="data/keys/signing_keys.json", help="Path to signing keys file"
    )
    trial_parser.set_defaults(func=cmd_trial)

    # checkout
    checkout_parser = subparsers.add_parser(
        "checkout", help="Create a Stripe checkout session for paid license"
    )
    checkout_parser.add_argument(
        "--tier",
        required=True,
        choices=["developer_individual", "developer_team"],
        help="License tier to purchase",
    )
    checkout_parser.add_argument("--email", help="Customer email (pre-fills checkout)")
    checkout_parser.add_argument(
        "--success-url",
        default="https://bedrock.dev/license/success?session_id={CHECKOUT_SESSION_ID}",
        help="URL to redirect on success",
    )
    checkout_parser.add_argument(
        "--cancel-url",
        default="https://bedrock.dev/license/cancel",
        help="URL to redirect on cancellation",
    )
    checkout_parser.set_defaults(func=cmd_checkout)

    # webhook
    webhook_parser = subparsers.add_parser(
        "webhook", help="Start the Stripe webhook server for license delivery"
    )
    webhook_parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    webhook_parser.add_argument("--port", type=int, default=8444, help="Bind port (default: 8444)")
    webhook_parser.set_defaults(func=cmd_webhook)

    # health
    health_parser = subparsers.add_parser("health", help="Run health checks")
    health_parser.add_argument("--json", action="store_true", help="Output as JSON")
    health_parser.set_defaults(func=cmd_health)

    # status
    status_parser = subparsers.add_parser("status", help="Show system status")
    status_parser.set_defaults(func=cmd_status)

    return parser


def main():
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if os.environ.get("BEDROCK_DEBUG"):
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
