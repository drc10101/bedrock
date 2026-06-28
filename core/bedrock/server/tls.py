"""
Bedrock TLS — HTTPS/TLS termination for the API server.

Provides TLS configuration, certificate generation, and server wrapping.
Production uses CA-signed certs. Developer mode generates self-signed certs.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import os
import ssl
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from http.server import HTTPServer


class TLSConfig:
    """TLS configuration for the Bedrock API server.

    Attributes:
        enabled: Whether TLS is enabled (True in production).
        cert_file: Path to the TLS certificate (PEM).
        key_file: Path to the TLS private key (PEM).
        ca_file: Path to the CA certificate bundle for client verification.
        min_version: Minimum TLS version (default 1.2).
        max_version: Maximum TLS version (default 1.3).
        cipher_suites: Allowed cipher suites.
        verify_client: Whether to verify client certificates (mTLS).
        client_ca_file: Path to CA bundle for verifying client certs.
    """

    # Secure cipher suites — no RC4, no 3DES, no export-grade
    SECURE_CIPHERS = (
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305"
    )

    def __init__(
        self,
        enabled: bool = True,
        cert_file: str = "",
        key_file: str = "",
        ca_file: str = "",
        min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
        max_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
        cipher_suites: str = SECURE_CIPHERS,
        verify_client: bool = False,
        client_ca_file: str = "",
    ):
        self.enabled = enabled
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.min_version = min_version
        self.max_version = max_version
        self.cipher_suites = cipher_suites
        self.verify_client = verify_client
        self.client_ca_file = client_ca_file

    @classmethod
    def from_env(cls) -> "TLSConfig":
        """Load TLS configuration from environment variables."""
        enabled = os.environ.get("BEDROCK_TLS_ENABLED", "true").lower() == "true"
        return cls(
            enabled=enabled,
            cert_file=os.environ.get("BEDROCK_TLS_CERT", ""),
            key_file=os.environ.get("BEDROCK_TLS_KEY", ""),
            ca_file=os.environ.get("BEDROCK_TLS_CA", ""),
            verify_client=os.environ.get("BEDROCK_TLS_VERIFY_CLIENT", "false").lower() == "true",
            client_ca_file=os.environ.get("BEDROCK_TLS_CLIENT_CA", ""),
        )

    @classmethod
    def for_development(cls, cert_dir: str = "") -> "TLSConfig":
        """Create a TLS config for development mode with self-signed certs.

        If cert_dir is empty, uses a temp directory.
        If certs don't exist, generates them automatically.
        """
        cert_dir = cert_dir or os.path.join(tempfile.gettempdir(), "bedrock-dev-certs")
        os.makedirs(cert_dir, exist_ok=True)

        cert_file = os.path.join(cert_dir, "bedrock-dev-cert.pem")
        key_file = os.path.join(cert_dir, "bedrock-dev-key.pem")

        # Generate self-signed cert if it doesn't exist
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            generate_self_signed_cert(cert_file, key_file)

        return cls(
            enabled=True,
            cert_file=cert_file,
            key_file=key_file,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_3,
            verify_client=False,
        )

    @classmethod
    def for_production(cls, cert_file: str, key_file: str, ca_file: str = "") -> "TLSConfig":
        """Create a TLS config for production with CA-signed certs.

        Requires explicit cert paths — no auto-generation.
        """
        if not os.path.exists(cert_file):
            raise FileNotFoundError(f"TLS certificate not found: {cert_file}")
        if not os.path.exists(key_file):
            raise FileNotFoundError(f"TLS private key not found: {key_file}")

        return cls(
            enabled=True,
            cert_file=cert_file,
            key_file=key_file,
            ca_file=ca_file,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_3,
            verify_client=bool(ca_file),
            client_ca_file=ca_file,
        )


def generate_self_signed_cert(
    cert_file: str,
    key_file: str,
    common_name: str = "bedrock-dev",
    days: int = 365,
    san_dns: list | None = None,
    san_ip: list | None = None,
) -> dict:
    """Generate a self-signed TLS certificate for development.

    Uses openssl subprocess to generate cert + key.
    Production must use CA-signed certs — this is dev-only.

    Returns:
        Dict with cert_file, key_file, and subject info.
    """
    san_dns = san_dns or ["localhost", "bedrock-dev"]
    san_ip = san_ip or ["127.0.0.1", "::1"]

    # Build SAN extension string
    san_entries = []
    for dns in san_dns:
        san_entries.append(f"DNS:{dns}")
    for ip in san_ip:
        san_entries.append(f"IP:{ip}")
    san_string = ",".join(san_entries)

    # Generate private key
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_file,
            "-out",
            cert_file,
            "-days",
            str(days),
            "-nodes",
            "-subj",
            f"/CN={common_name}/O=Bedrock-Dev/C=US",
            "-addext",
            f"subjectAltName={san_string}",
        ],
        check=True,
        capture_output=True,
    )

    return {
        "cert_file": cert_file,
        "key_file": key_file,
        "common_name": common_name,
        "days_valid": days,
        "san_dns": san_dns,
        "san_ip": san_ip,
    }


def generate_self_signed_cert_python(
    cert_file: str,
    key_file: str,
    common_name: str = "bedrock-dev",
    days: int = 365,
) -> dict:
    """Generate a self-signed TLS certificate using Python's ssl module.

    Fallback when openssl is not available on the system.
    Creates a PEM cert and key using the cryptography library.
    Production must use CA-signed certs — this is dev-only.

    Returns:
        Dict with cert_file, key_file, and subject info.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        raise ImportError(
            "cryptography package required for self-signed cert generation. "
            "Install with: pip install cryptography"
        ) from None

    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build subject
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bedrock-Dev"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )

    # Build certificate
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName(common_name),
                    x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
                    x509.IPAddress(__import__("ipaddress").IPv6Address("::1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    # Write cert
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write key
    with open(key_file, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    return {
        "cert_file": cert_file,
        "key_file": key_file,
        "common_name": common_name,
        "days_valid": days,
    }


def create_ssl_context(tls_config: TLSConfig) -> ssl.SSLContext:
    """Create an SSL context from TLS configuration.

    Returns a configured SSLContext ready for wrapping a server socket.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Set TLS version range
    ctx.minimum_version = tls_config.min_version
    ctx.maximum_version = tls_config.max_version

    # Set cipher suites
    ctx.set_ciphers(tls_config.cipher_suites)

    # Load certificate and key
    ctx.load_cert_chain(tls_config.cert_file, tls_config.key_file)

    # Client certificate verification (mTLS)
    if tls_config.verify_client and tls_config.client_ca_file:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(tls_config.client_ca_file)
    elif tls_config.verify_client:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
    else:
        ctx.verify_mode = ssl.CERT_NONE

    # Hardened settings
    ctx.check_hostname = False  # Server cert, not client
    ctx.options |= ssl.OP_NO_COMPRESSION  # Prevent CRIME attack
    ctx.options |= ssl.OP_SINGLE_DH_USE  # Fresh DH key per handshake
    ctx.options |= ssl.OP_SINGLE_ECDH_USE  # Fresh ECDH key per handshake

    return ctx


def validate_cert_pair(cert_file: str, key_file: str) -> dict:
    """Validate that a certificate and key pair match and are usable.

    Returns dict with validation results:
        valid: bool — whether the pair is valid
        cert_info: dict — certificate details if valid
        errors: list[str] — any validation errors
    """
    errors = []

    # Check files exist
    if not os.path.exists(cert_file):
        errors.append(f"Certificate file not found: {cert_file}")
    if not os.path.exists(key_file):
        errors.append(f"Key file not found: {key_file}")

    if errors:
        return {"valid": False, "cert_info": {}, "errors": errors}

    # Try to load the cert + key into an SSL context
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
    except ssl.SSLError as e:
        errors.append(f"SSL error loading cert/key pair: {e}")
        return {"valid": False, "cert_info": {}, "errors": errors}

    # Extract cert info using openssl
    cert_info = {}
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_file, "-noout", "-subject", "-dates", "-issuer"],
            capture_output=True,
            text=True,
            check=True,
        )
        for line in result.stdout.strip().split("\n"):
            if "=" in line:
                key, _, value = line.partition("=")
                cert_info[key.strip()] = value.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        # openssl not available — skip cert info extraction
        pass

    return {"valid": True, "cert_info": cert_info, "errors": []}


def wrap_server_with_tls(server: HTTPServer, tls_config: TLSConfig) -> HTTPServer:
    """Wrap an HTTPServer socket with TLS.

    Modifies the server in-place to use TLS. Call before server_forever().
    """
    if not tls_config.enabled:
        return server

    ctx = create_ssl_context(tls_config)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server
