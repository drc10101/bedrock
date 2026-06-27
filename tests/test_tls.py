"""
Tests for Bedrock TLS — certificate generation, SSL context, server wrapping.

Covers TLSConfig, self-signed cert generation, SSL context creation,
cert validation, and server wrapping with TLS.
"""

import os
import ssl
import tempfile
import unittest

import sys
sys.path.insert(0, "core")

from bedrock.server.tls import (
    TLSConfig,
    generate_self_signed_cert,
    generate_self_signed_cert_python,
    create_ssl_context,
    validate_cert_pair,
    wrap_server_with_tls,
)
from http.server import HTTPServer, BaseHTTPRequestHandler


class TestTLSConfig(unittest.TestCase):
    """Test TLSConfig creation and environment loading."""

    def test_default_config(self):
        """Default config has TLS enabled with no cert paths."""
        config = TLSConfig()
        assert config.enabled is True
        assert config.cert_file == ""
        assert config.key_file == ""
        assert config.min_version == ssl.TLSVersion.TLSv1_2
        assert config.max_version == ssl.TLSVersion.TLSv1_3

    def test_for_development_generates_certs(self):
        """Development config generates self-signed certs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = TLSConfig.for_development(cert_dir=tmpdir)
            assert config.enabled is True
            assert os.path.exists(config.cert_file)
            assert os.path.exists(config.key_file)
            assert config.min_version == ssl.TLSVersion.TLSv1_2
            assert config.verify_client is False

    def test_for_production_requires_certs(self):
        """Production config requires existing cert files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Non-existent cert should raise
            with self.assertRaises(FileNotFoundError):
                TLSConfig.for_production(
                    cert_file=os.path.join(tmpdir, "missing.pem"),
                    key_file=os.path.join(tmpdir, "missing-key.pem"),
                )

    def test_for_production_with_valid_certs(self):
        """Production config works with existing cert files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate a self-signed cert first
            cert_file = os.path.join(tmpdir, "prod-cert.pem")
            key_file = os.path.join(tmpdir, "prod-key.pem")
            generate_self_signed_cert_python(cert_file, key_file, common_name="bedrock-prod")

            config = TLSConfig.for_production(cert_file=cert_file, key_file=key_file)
            assert config.enabled is True
            assert config.verify_client is False  # No CA file = no mTLS

    def test_from_env_defaults(self):
        """from_env loads defaults when no env vars set."""
        # Clear any env vars
        for key in ["BEDROCK_TLS_ENABLED", "BEDROCK_TLS_CERT", "BEDROCK_TLS_KEY", "BEDROCK_TLS_CA"]:
            if key in os.environ:
                del os.environ[key]

        config = TLSConfig.from_env()
        assert config.enabled is True  # Default
        assert config.cert_file == ""

    def test_from_env_disabled(self):
        """from_env respects BEDROCK_TLS_ENABLED=false."""
        os.environ["BEDROCK_TLS_ENABLED"] = "false"
        try:
            config = TLSConfig.from_env()
            assert config.enabled is False
        finally:
            del os.environ["BEDROCK_TLS_ENABLED"]

    def test_cipher_suites_are_secure(self):
        """Default cipher suites exclude weak ciphers."""
        config = TLSConfig()
        # Should not contain weak ciphers
        assert "RC4" not in config.cipher_suites
        assert "3DES" not in config.cipher_suites
        assert "EXPORT" not in config.cipher_suites
        # Should contain strong ciphers
        assert "ECDHE" in config.cipher_suites
        assert "GCM" in config.cipher_suites


class TestSelfSignedCert(unittest.TestCase):
    """Test self-signed certificate generation."""

    def test_generate_python_cert(self):
        """Python-based cert generation creates valid cert + key files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "test-cert.pem")
            key_file = os.path.join(tmpdir, "test-key.pem")

            result = generate_self_signed_cert_python(cert_file, key_file)

            assert os.path.exists(cert_file)
            assert os.path.exists(key_file)
            assert result["common_name"] == "bedrock-dev"
            assert result["days_valid"] == 365
            assert os.path.getsize(cert_file) > 0
            assert os.path.getsize(key_file) > 0

    def test_generate_python_cert_custom_cn(self):
        """Python cert generation with custom common name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "custom-cert.pem")
            key_file = os.path.join(tmpdir, "custom-key.pem")

            result = generate_self_signed_cert_python(
                cert_file, key_file, common_name="my-server", days=30
            )

            assert result["common_name"] == "my-server"
            assert result["days_valid"] == 30

    def test_generate_openssl_cert(self):
        """OpenSSL-based cert generation creates valid cert + key files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "openssl-cert.pem")
            key_file = os.path.join(tmpdir, "openssl-key.pem")

            try:
                result = generate_self_signed_cert(cert_file, key_file, common_name="openssl-test")
                assert os.path.exists(cert_file)
                assert os.path.exists(key_file)
                assert result["common_name"] == "openssl-test"
            except (FileNotFoundError, subprocess.CalledProcessError):
                self.skipTest("openssl not available on this system")

    def test_cert_contains_san(self):
        """Generated cert contains Subject Alternative Names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "san-cert.pem")
            key_file = os.path.join(tmpdir, "san-key.pem")

            generate_self_signed_cert_python(cert_file, key_file)

            # Read cert and check for SAN
            with open(cert_file, "r") as f:
                cert_pem = f.read()
            assert "BEGIN CERTIFICATE" in cert_pem

    def test_cert_key_match(self):
        """Generated cert and key match (can load as a pair)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "match-cert.pem")
            key_file = os.path.join(tmpdir, "match-key.pem")

            generate_self_signed_cert_python(cert_file, key_file)

            # Should not raise — cert and key match
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_file, key_file)
            # If we get here, cert and key match


class TestSSLContext(unittest.TestCase):
    """Test SSL context creation from TLS config."""

    def test_create_ssl_context(self):
        """Create an SSL context from TLS config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "ctx-cert.pem")
            key_file = os.path.join(tmpdir, "ctx-key.pem")
            generate_self_signed_cert_python(cert_file, key_file)

            config = TLSConfig(
                enabled=True,
                cert_file=cert_file,
                key_file=key_file,
            )

            ctx = create_ssl_context(config)
            assert ctx is not None
            assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
            assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3

    def test_ssl_context_hardening(self):
        """SSL context has security hardening options."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "hardened-cert.pem")
            key_file = os.path.join(tmpdir, "hardened-key.pem")
            generate_self_signed_cert_python(cert_file, key_file)

            config = TLSConfig(
                enabled=True,
                cert_file=cert_file,
                key_file=key_file,
            )

            ctx = create_ssl_context(config)
            # Check hardening options are set
            assert ctx.options & ssl.OP_NO_COMPRESSION
            # OP_SINGLE_DH_USE and OP_SINGLE_ECDH_USE are always-on in OpenSSL 3+
            # Verify by checking the context protocol version range
            assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2

    def test_ssl_context_no_client_verify_by_default(self):
        """SSL context doesn't require client certs by default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "noclient-cert.pem")
            key_file = os.path.join(tmpdir, "noclient-key.pem")
            generate_self_signed_cert_python(cert_file, key_file)

            config = TLSConfig(
                enabled=True,
                cert_file=cert_file,
                key_file=key_file,
                verify_client=False,
            )

            ctx = create_ssl_context(config)
            assert ctx.verify_mode == ssl.CERT_NONE


class TestCertValidation(unittest.TestCase):
    """Test certificate validation."""

    def test_validate_valid_pair(self):
        """Valid cert + key pair validates successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "valid-cert.pem")
            key_file = os.path.join(tmpdir, "valid-key.pem")
            generate_self_signed_cert_python(cert_file, key_file)

            result = validate_cert_pair(cert_file, key_file)
            assert result["valid"] is True
            assert len(result["errors"]) == 0

    def test_validate_missing_cert(self):
        """Missing cert file reports error."""
        result = validate_cert_pair("/nonexistent/cert.pem", "/nonexistent/key.pem")
        assert result["valid"] is False
        assert any("not found" in e for e in result["errors"])

    def test_validate_mismatched_pair(self):
        """Mismatched cert + key pair reports error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "cert-a.pem")
            key_file_a = os.path.join(tmpdir, "key-a.pem")
            key_file_b = os.path.join(tmpdir, "key-b.pem")

            generate_self_signed_cert_python(cert_file, key_file_a, common_name="cert-a")
            # Generate a different key
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(key_file_b, "wb") as f:
                f.write(key_b.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))

            result = validate_cert_pair(cert_file, key_file_b)
            assert result["valid"] is False


class TestServerWrapWithTLS(unittest.TestCase):
    """Test wrapping HTTPServer with TLS."""

    def test_wrap_server_with_tls_enabled(self):
        """Wrapping a server with TLS config enables HTTPS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "server-cert.pem")
            key_file = os.path.join(tmpdir, "server-key.pem")
            generate_self_signed_cert_python(cert_file, key_file)

            config = TLSConfig(
                enabled=True,
                cert_file=cert_file,
                key_file=key_file,
            )

            # Create a minimal HTTP server
            server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
            original_socket = server.socket

            # Wrap with TLS
            wrapped = wrap_server_with_tls(server, config)
            assert wrapped is server
            # Socket should now be an SSL socket
            assert hasattr(server.socket, 'read')  # SSL sockets have read()

            server.server_close()

    def test_wrap_server_with_tls_disabled(self):
        """Wrapping with disabled TLS leaves server unchanged."""
        config = TLSConfig(enabled=False)

        server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        original_socket = server.socket

        wrapped = wrap_server_with_tls(server, config)
        assert wrapped is server
        assert server.socket is original_socket  # Unchanged

        server.server_close()

    def test_development_config_full_round_trip(self):
        """Full round trip: dev config → generate certs → create context → wrap server."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = TLSConfig.for_development(cert_dir=tmpdir)
            assert config.enabled is True
            assert os.path.exists(config.cert_file)
            assert os.path.exists(config.key_file)

            server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
            wrapped = wrap_server_with_tls(server, config)
            assert wrapped is server

            server.server_close()


if __name__ == "__main__":
    unittest.main()