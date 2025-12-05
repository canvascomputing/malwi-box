"""Tests for BoxEngine permission enforcement."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from malwi_box.engine import BoxEngine


class TestConfigLoading:
    """Tests for configuration loading."""

    def test_default_config_when_no_file(self, tmp_path):
        """Test that default config is used when no file exists."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        assert engine.config["allow_pypi_requests"] is True
        assert str(tmp_path) in engine.config["allow_dir_reads"]
        assert str(tmp_path) in engine.config["allow_dir_writes"]

    def test_load_config_from_file(self, tmp_path):
        """Test loading config from JSON file."""
        config = {
            "allow_file_reads": ["/etc/hosts"],
            "allow_pypi_requests": False,
            "allow_system_commands": ["ls *"],
        }
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert "/etc/hosts" in engine.config["allow_file_reads"]
        assert engine.config["allow_pypi_requests"] is False
        assert "ls *" in engine.config["allow_system_commands"]

    def test_merge_missing_keys_with_defaults(self, tmp_path):
        """Test that missing config keys are filled with defaults."""
        config = {"allow_pypi_requests": False}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Should have default for missing keys
        assert "allow_file_reads" in engine.config
        assert "allow_system_commands" in engine.config


class TestFilePermissions:
    """Tests for file access permission checks."""

    def test_allow_read_in_workdir(self, tmp_path):
        """Test that reads in workdir are allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        # Simulate 'open' event for reading
        assert engine.check_permission("open", (str(test_file), "r", 0))

    def test_allow_write_in_workdir(self, tmp_path):
        """Test that writes in workdir are allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)
        test_file = tmp_path / "new_file.txt"

        # Simulate 'open' event for writing (new file)
        assert engine.check_permission("open", (str(test_file), "w", 0))

    def test_block_read_outside_allowed(self, tmp_path):
        """Test that reads outside allowed paths are blocked."""
        config = {
            "allow_file_reads": [],
            "allow_dir_reads": [str(tmp_path / "allowed")],
        }
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Outside allowed directory
        assert not engine.check_permission("open", ("/etc/passwd", "r", 0))

    def test_allow_specific_file(self, tmp_path):
        """Test allowing a specific file path."""
        config = {"allow_file_reads": ["/etc/hosts"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("open", ("/etc/hosts", "r", 0))


class TestHashVerification:
    """Tests for file hash verification."""

    def test_verify_correct_hash(self, tmp_path):
        """Test that correct hash passes verification."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        # SHA256 of "hello world"
        expected_hash = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)
        assert engine._verify_file_hash(test_file, expected_hash)

    def test_reject_wrong_hash(self, tmp_path):
        """Test that wrong hash fails verification."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        wrong_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)
        assert not engine._verify_file_hash(test_file, wrong_hash)


class TestSystemCommands:
    """Tests for system command permission checks."""

    def test_allow_matching_glob(self, tmp_path):
        """Test that commands matching glob pattern are allowed."""
        config = {"allow_system_commands": ["/bin/ls *", "/usr/bin/git *", "ls *"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # subprocess.Popen event with full path
        assert engine.check_permission(
            "subprocess.Popen", ("/bin/ls", ["-la", "/tmp"], None, None)
        )
        assert engine.check_permission(
            "subprocess.Popen", ("/usr/bin/git", ["status"], None, None)
        )
        # Also test without full path
        assert engine.check_permission(
            "subprocess.Popen", ("ls", ["-la"], None, None)
        )

    def test_block_non_matching_command(self, tmp_path):
        """Test that commands not matching patterns are blocked."""
        config = {"allow_system_commands": ["ls *"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # rm is not in allowed patterns
        assert not engine.check_permission(
            "subprocess.Popen", ("/bin/rm", ["-rf", "/tmp/test"], None, None)
        )

    def test_os_system_command(self, tmp_path):
        """Test os.system event handling."""
        config = {"allow_system_commands": ["echo *"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("os.system", ("echo hello",))
        assert not engine.check_permission("os.system", ("rm -rf /",))


class TestNetworkPermissions:
    """Tests for network permission checks."""

    def test_allow_pypi_when_enabled(self, tmp_path):
        """Test that PyPI hosts are allowed when allow_pypi_requests is True."""
        config = {"allow_pypi_requests": True}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # socket.connect event with PyPI address
        assert engine.check_permission("socket.connect", (None, ("pypi.org", 443)))
        assert engine.check_permission(
            "socket.connect", (None, ("files.pythonhosted.org", 443))
        )

    def test_block_pypi_when_disabled(self, tmp_path):
        """Test that PyPI hosts are blocked when allow_pypi_requests is False."""
        config = {"allow_pypi_requests": False}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert not engine.check_permission("socket.connect", (None, ("pypi.org", 443)))

    def test_block_unknown_hosts(self, tmp_path):
        """Test that unknown hosts are blocked."""
        config = {"allow_pypi_requests": True}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Random host should be blocked
        assert not engine.check_permission(
            "socket.connect", (None, ("example.com", 80))
        )


class TestEnvVarPermissions:
    """Tests for environment variable permission checks."""

    def test_allow_env_write(self, tmp_path):
        """Test that allowed env var writes pass."""
        config = {"allow_env_var_writes": ["PATH", "HOME"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("os.putenv", ("PATH", "/usr/bin"))
        assert engine.check_permission("os.putenv", ("HOME", "/home/user"))

    def test_block_env_write(self, tmp_path):
        """Test that non-allowed env var writes are blocked."""
        config = {"allow_env_var_writes": ["PATH"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert not engine.check_permission("os.putenv", ("SECRET_KEY", "value"))


class TestDecisionRecording:
    """Tests for review mode decision recording."""

    def test_record_and_save_decisions(self, tmp_path):
        """Test that decisions are recorded and saved correctly."""
        config_path = tmp_path / ".malwi-box"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Record some decisions
        engine.record_decision(
            "open",
            ("/tmp/test.txt", "r"),
            allowed=True,
            details={"path": "/tmp/test.txt", "mode": "r"},
        )
        engine.record_decision(
            "subprocess.Popen",
            ("git", ["status"]),
            allowed=True,
            details={"command": "git status"},
        )

        # Save decisions
        engine.save_decisions()

        # Verify config was written
        assert config_path.exists()
        saved_config = json.loads(config_path.read_text())
        assert "/tmp/test.txt" in saved_config.get("allow_file_reads", [])
        assert "git status" in saved_config.get("allow_system_commands", [])


class TestUnhandledEvents:
    """Tests for events not explicitly handled."""

    def test_unhandled_events_allowed(self, tmp_path):
        """Test that events without handlers are allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        # Random event that's not handled
        assert engine.check_permission("compile", ("source", "filename"))
        assert engine.check_permission("exec", ("code",))
        assert engine.check_permission("import", ("module",))
