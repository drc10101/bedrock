"""
Tests for Bedrock CLI — developer onboarding and management commands.

Tests the CLI subcommands: init, keygen, license, health, status.
Uses argparse's parse_args to exercise command handlers directly.
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "core"))

from bedrock.cli import (
    build_parser, cmd_init, cmd_keygen, cmd_license,
    cmd_health, cmd_status, VERSION,
)


class TestCLIParser(unittest.TestCase):
    """Test CLI argument parsing."""

    def setUp(self):
        self.parser = build_parser()

    def test_version_flag(self):
        """--version prints version and exits."""
        with self.assertRaises(SystemExit) as ctx:
            self.parser.parse_args(["--version"])
        assert ctx.exception.code == 0

    def test_init_command(self):
        """init subcommand parses directory argument."""
        args = self.parser.parse_args(["init", "/tmp/test-project"])
        assert args.command == "init"
        assert args.directory == "/tmp/test-project"

    def test_init_default_directory(self):
        """init defaults to current directory."""
        args = self.parser.parse_args(["init"])
        assert args.directory == "."

    def test_serve_command(self):
        """serve subcommand parses host/port."""
        args = self.parser.parse_args(["serve", "--host", "localhost", "--port", "9000"])
        assert args.command == "serve"
        assert args.host == "localhost"
        assert args.port == 9000

    def test_serve_defaults(self):
        """serve has sensible defaults."""
        args = self.parser.parse_args(["serve"])
        assert args.host == "0.0.0.0"
        assert args.port == 8443

    def test_serve_no_metering(self):
        """serve --no-metering flag works."""
        args = self.parser.parse_args(["serve", "--no-metering"])
        assert args.no_metering is True

    def test_keygen_command(self):
        """keygen subcommand parses key-id."""
        args = self.parser.parse_args(["keygen", "--key-id", "my-key-001"])
        assert args.command == "keygen"
        assert args.key_id == "my-key-001"

    def test_keygen_defaults(self):
        """keygen defaults."""
        args = self.parser.parse_args(["keygen"])
        assert args.key_id is None
        assert args.keys_file == "data/keys/signing_keys.json"

    def test_license_issue(self):
        """license issue subcommand parses tier and licensee."""
        args = self.parser.parse_args([
            "license", "issue",
            "--tier", "business",
            "--licensee", "Acme Corp",
            "--nodes", "10",
            "--days", "365",
        ])
        assert args.command == "license"
        assert args.license_action == "issue"
        assert args.tier == "business"
        assert args.licensee == "Acme Corp"
        assert args.nodes == 10
        assert args.days == 365

    def test_license_validate(self):
        """license validate parses key argument."""
        args = self.parser.parse_args([
            "license", "validate",
            "--key", "1:payload:signature",
        ])
        assert args.license_action == "validate"
        assert args.key == "1:payload:signature"

    def test_license_revoke(self):
        """license revoke parses key-id and reason."""
        args = self.parser.parse_args([
            "license", "revoke",
            "--key-id", "key-123",
            "--reason", "compromised",
        ])
        assert args.license_action == "revoke"
        assert args.key_id == "key-123"
        assert args.reason == "compromised"

    def test_health_command(self):
        """health subcommand parses json flag."""
        args = self.parser.parse_args(["health", "--json"])
        assert args.command == "health"
        assert args.json is True

    def test_status_command(self):
        """status subcommand parses."""
        args = self.parser.parse_args(["status"])
        assert args.command == "status"


class TestCmdInit(unittest.TestCase):
    """Test bedrock init command."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init_creates_directories(self):
        """init creates the expected directory structure."""
        class Args:
            directory = self.temp_dir
        result = cmd_init(Args())
        assert result == 0

        # Check directories
        assert (Path(self.temp_dir) / "config").is_dir()
        assert (Path(self.temp_dir) / "data").is_dir()
        assert (Path(self.temp_dir) / "data" / "audit").is_dir()
        assert (Path(self.temp_dir) / "data" / "keys").is_dir()
        assert (Path(self.temp_dir) / "logs").is_dir()

    def test_init_creates_config(self):
        """init creates bedrock.json config file."""
        class Args:
            directory = self.temp_dir
        cmd_init(Args())

        config_path = Path(self.temp_dir) / "config" / "bedrock.json"
        assert config_path.exists()
        with open(config_path) as f:
            config = json.load(f)
        assert "environment" in config
        assert "encryption" in config
        assert "licensing" in config

    def test_init_creates_master_key(self):
        """init generates a master encryption key."""
        class Args:
            directory = self.temp_dir
        cmd_init(Args())

        key_path = Path(self.temp_dir) / "data" / "keys" / "master.key"
        assert key_path.exists()
        with open(key_path) as f:
            key = f.read().strip()
        assert len(key) == 64  # 256-bit hex key

    def test_init_creates_signing_key(self):
        """init generates a signing key."""
        class Args:
            directory = self.temp_dir
        cmd_init(Args())

        keys_path = Path(self.temp_dir) / "data" / "keys" / "signing_keys.json"
        assert keys_path.exists()
        with open(keys_path) as f:
            keys_data = json.load(f)
        assert "keys" in keys_data
        assert len(keys_data["keys"]) >= 1

    def test_init_creates_env_template(self):
        """init creates .env.template."""
        class Args:
            directory = self.temp_dir
        cmd_init(Args())

        env_path = Path(self.temp_dir) / "config" / ".env.template"
        assert env_path.exists()
        content = env_path.read_text()
        assert "BEDROCK_ENV" in content
        assert "BEDROCK_MASTER_KEY" in content

    def test_init_idempotent(self):
        """init can run multiple times without error."""
        class Args:
            directory = self.temp_dir
        result1 = cmd_init(Args())
        result2 = cmd_init(Args())
        assert result1 == 0
        assert result2 == 0


class TestCmdKeygen(unittest.TestCase):
    """Test bedrock keygen command."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_keygen_creates_key(self):
        """keygen generates a new signing key."""
        class Args:
            key_id = None
            keys_file = str(Path(self.temp_dir) / "keys.json")

        result = cmd_keygen(Args())
        assert result == 0

        keys_path = Path(self.temp_dir) / "keys.json"
        assert keys_path.exists()
        with open(keys_path) as f:
            data = json.load(f)
        assert "keys" in data

    def test_keygen_with_custom_id(self):
        """keygen accepts a custom key ID."""
        class Args:
            key_id = "my-custom-key-id"
            keys_file = str(Path(self.temp_dir) / "keys.json")

        result = cmd_keygen(Args())
        assert result == 0


class TestCmdLicense(unittest.TestCase):
    """Test bedrock license command."""

    def test_validate_invalid_key(self):
        """validate rejects an invalid license key."""
        class Args:
            license_action = "validate"
            key = "invalid-key"
            keys_file = "data/keys/signing_keys.json"

        result = cmd_license(Args())
        assert result == 1  # Invalid key returns 1


class TestCmdHealth(unittest.TestCase):
    """Test bedrock health command."""

    def test_health_runs(self):
        """health check executes and returns a result."""
        class Args:
            json = False
        result = cmd_health(Args())
        # Returns 0 (healthy) or 1 (unhealthy) — either is valid
        assert result in (0, 1)

    def test_health_json_output(self):
        """health --json produces output with JSON section."""
        import io
        from contextlib import redirect_stdout
        class Args:
            json = True
        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_health(Args())
        output = f.getvalue()
        assert "Bedrock Health Check" in output


class TestCmdStatus(unittest.TestCase):
    """Test bedrock status command."""

    def test_status_runs(self):
        """status command executes and returns 0."""
        class Args:
            pass
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_status(Args())
        assert result == 0

    def test_status_shows_version(self):
        """status output includes version."""
        class Args:
            pass
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            cmd_status(Args())
        output = f.getvalue()
        assert VERSION in output

    def test_status_shows_environment(self):
        """status output includes environment config."""
        class Args:
            pass
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            cmd_status(Args())
        output = f.getvalue()
        assert "Environment" in output
        assert "Tier" in output


class TestCLIMain(unittest.TestCase):
    """Test CLI main() entry point."""

    def test_no_command_returns_1(self):
        """No subcommand prints help and returns 1."""
        from bedrock.cli import main
        with patch("sys.argv", ["bedrock"]):
            result = main()
        assert result == 1

    def test_help_flag(self):
        """--help prints help and exits."""
        from bedrock.cli import main
        with patch("sys.argv", ["bedrock", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            assert ctx.exception.code == 0


if __name__ == "__main__":
    unittest.main()