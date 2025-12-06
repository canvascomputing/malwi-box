"""Tests for BoxEngine permission enforcement."""

import json

from malwi_box.engine import BoxEngine


class TestConfigLoading:
    """Tests for configuration loading."""

    def test_default_config_when_no_file(self, tmp_path):
        """Test that default config is used when no file exists."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        assert engine.config["allow_pypi_requests"] is True
        # Default config uses variables like $PWD which get expanded at runtime
        assert "$PWD" in engine.config["allow_read"]
        assert "$PWD" in engine.config["allow_create"]
        assert "$PWD" in engine.config["allow_modify"]
        assert engine.config["allow_delete"] == []  # Conservative default

    def test_load_config_from_file(self, tmp_path):
        """Test loading config from JSON file."""
        config = {
            "allow_read": ["/etc/hosts"],
            "allow_pypi_requests": False,
            "allow_system_commands": ["ls *"],
        }
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert "/etc/hosts" in engine.config["allow_read"]
        assert engine.config["allow_pypi_requests"] is False
        assert "ls *" in engine.config["allow_system_commands"]

    def test_merge_missing_keys_with_defaults(self, tmp_path):
        """Test that missing config keys are filled with defaults."""
        config = {"allow_pypi_requests": False}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Should have default for missing keys
        assert "allow_read" in engine.config
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

    def test_allow_create_in_workdir(self, tmp_path):
        """Test that creating files in workdir is allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)
        test_file = tmp_path / "new_file.txt"

        # Simulate 'open' event for creating new file
        assert engine.check_permission("open", (str(test_file), "w", 0))

    def test_allow_modify_in_workdir(self, tmp_path):
        """Test that modifying files in workdir is allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)
        test_file = tmp_path / "existing.txt"
        test_file.write_text("existing content")

        # Simulate 'open' event for modifying existing file
        assert engine.check_permission("open", (str(test_file), "w", 0))

    def test_block_read_outside_allowed(self, tmp_path):
        """Test that reads outside allowed paths are blocked."""
        config = {
            "allow_read": [str(tmp_path / "allowed")],
        }
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Outside allowed directory
        assert not engine.check_permission("open", ("/etc/passwd", "r", 0))

    def test_allow_specific_file(self, tmp_path):
        """Test allowing a specific file path."""
        config = {"allow_read": ["/etc/hosts"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("open", ("/etc/hosts", "r", 0))

    def test_block_create_outside_allowed(self, tmp_path):
        """Test that creating files outside allowed paths is blocked."""
        config = {
            "allow_create": [str(tmp_path / "allowed")],
        }
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # New file outside allowed directory
        assert not engine.check_permission("open", ("/tmp/newfile.txt", "w", 0))

    def test_block_modify_outside_allowed(self, tmp_path):
        """Test that modifying files outside allowed paths is blocked."""
        config = {
            "allow_modify": [str(tmp_path / "allowed")],
        }
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Create a file to test modify permission
        test_file = tmp_path / "outside.txt"
        test_file.write_text("content")

        # Existing file outside allowed directory
        assert not engine.check_permission("open", (str(test_file), "w", 0))


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


class TestDomainPermissions:
    """Tests for domain permission checks via DNS resolution events."""

    def test_allow_pypi_when_enabled(self, tmp_path):
        """Test that PyPI domains are allowed when allow_pypi_requests is True."""
        config = {"allow_pypi_requests": True}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # socket.getaddrinfo event with PyPI domain
        assert engine.check_permission("socket.getaddrinfo", ("pypi.org", 443, 0, 1, 0))
        assert engine.check_permission(
            "socket.getaddrinfo", ("files.pythonhosted.org", 443, 0, 1, 0)
        )
        # socket.gethostbyname event
        assert engine.check_permission("socket.gethostbyname", ("pypi.org",))

    def test_block_pypi_when_disabled(self, tmp_path):
        """Test that PyPI domains are blocked when allow_pypi_requests is False."""
        config = {"allow_pypi_requests": False}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert not engine.check_permission("socket.getaddrinfo", ("pypi.org", 443, 0, 1, 0))
        assert not engine.check_permission("socket.gethostbyname", ("pypi.org",))

    def test_block_unknown_domains(self, tmp_path):
        """Test that unknown domains are blocked."""
        config = {"allow_pypi_requests": True}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Random domain should be blocked
        assert not engine.check_permission(
            "socket.getaddrinfo", ("example.com", 80, 0, 1, 0)
        )
        assert not engine.check_permission("socket.gethostbyname", ("example.com",))

    def test_allow_domain_any_port(self, tmp_path):
        """Test that domain without port allows any port."""
        config = {"allow_domains": ["httpbin.org"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("socket.getaddrinfo", ("httpbin.org", 80, 0, 1, 0))
        assert engine.check_permission("socket.getaddrinfo", ("httpbin.org", 443, 0, 1, 0))
        assert engine.check_permission("socket.getaddrinfo", ("httpbin.org", 8080, 0, 1, 0))
        assert engine.check_permission("socket.gethostbyname", ("httpbin.org",))

    def test_allow_domain_specific_port(self, tmp_path):
        """Test that domain:port only allows that specific port."""
        config = {"allow_domains": ["api.example.com:443"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Correct port - allowed
        assert engine.check_permission("socket.getaddrinfo", ("api.example.com", 443, 0, 1, 0))
        # Wrong port - blocked
        assert not engine.check_permission("socket.getaddrinfo", ("api.example.com", 80, 0, 1, 0))
        # gethostbyname has no port, so domain:port entry allows it (port is None)
        assert engine.check_permission("socket.gethostbyname", ("api.example.com",))

    def test_allow_subdomain(self, tmp_path):
        """Test that subdomains are allowed when parent domain is in list."""
        config = {"allow_domains": ["example.com"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("socket.getaddrinfo", ("example.com", 443, 0, 1, 0))
        assert engine.check_permission("socket.getaddrinfo", ("api.example.com", 443, 0, 1, 0))
        assert engine.check_permission("socket.getaddrinfo", ("www.example.com", 80, 0, 1, 0))


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

    def test_allow_env_unset(self, tmp_path):
        """Test that os.unsetenv uses same permissions as putenv."""
        config = {"allow_env_var_writes": ["TEMP_VAR"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("os.unsetenv", ("TEMP_VAR",))
        assert not engine.check_permission("os.unsetenv", ("SECRET_KEY",))


class TestDecisionRecording:
    """Tests for review mode decision recording."""

    def test_record_and_save_read_decision(self, tmp_path):
        """Test that read decisions are saved correctly."""
        config_path = tmp_path / ".malwi-box"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        engine.record_decision(
            "open",
            ("/tmp/test.txt", "r"),
            allowed=True,
            details={"path": "/tmp/test.txt", "mode": "r", "is_new_file": False},
        )

        engine.save_decisions()

        saved_config = json.loads(config_path.read_text())
        assert "/tmp/test.txt" in saved_config.get("allow_read", [])

    def test_record_and_save_create_decision(self, tmp_path):
        """Test that create decisions are saved correctly."""
        config_path = tmp_path / ".malwi-box"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        engine.record_decision(
            "open",
            ("/tmp/newfile.txt", "w"),
            allowed=True,
            details={"path": "/tmp/newfile.txt", "mode": "w", "is_new_file": True},
        )

        engine.save_decisions()

        saved_config = json.loads(config_path.read_text())
        assert "/tmp/newfile.txt" in saved_config.get("allow_create", [])

    def test_record_and_save_modify_decision(self, tmp_path):
        """Test that modify decisions are saved correctly."""
        config_path = tmp_path / ".malwi-box"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        engine.record_decision(
            "open",
            ("/tmp/existing.txt", "w"),
            allowed=True,
            details={"path": "/tmp/existing.txt", "mode": "w", "is_new_file": False},
        )

        engine.save_decisions()

        saved_config = json.loads(config_path.read_text())
        assert "/tmp/existing.txt" in saved_config.get("allow_modify", [])

    def test_record_and_save_command_decision(self, tmp_path):
        """Test that command decisions are saved correctly."""
        config_path = tmp_path / ".malwi-box"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        engine.record_decision(
            "subprocess.Popen",
            ("git", ["status"]),
            allowed=True,
            details={"command": "git status"},
        )

        engine.save_decisions()

        saved_config = json.loads(config_path.read_text())
        assert "git status" in saved_config.get("allow_system_commands", [])

    def test_record_and_save_domain_with_port(self, tmp_path):
        """Test that domain decisions with port are saved correctly."""
        config_path = tmp_path / ".malwi-box"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Record domain decision with port
        engine.record_decision(
            "socket.getaddrinfo",
            ("httpbin.org", 443, 0, 1, 0),
            allowed=True,
            details={"domain": "httpbin.org", "port": 443},
        )

        engine.save_decisions()

        saved_config = json.loads(config_path.read_text())
        assert "httpbin.org:443" in saved_config.get("allow_domains", [])

    def test_record_and_save_domain_without_port(self, tmp_path):
        """Test that domain decisions without port are saved correctly."""
        config_path = tmp_path / ".malwi-box"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Record domain decision without port (gethostbyname)
        engine.record_decision(
            "socket.gethostbyname",
            ("example.com",),
            allowed=True,
            details={"domain": "example.com"},
        )

        engine.save_decisions()

        saved_config = json.loads(config_path.read_text())
        assert "example.com" in saved_config.get("allow_domains", [])

    def test_record_and_save_env_var_decision(self, tmp_path):
        """Test that env var write decisions are saved correctly."""
        config_path = tmp_path / ".malwi-box"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        engine.record_decision(
            "os.putenv",
            ("MY_VAR", "value"),
            allowed=True,
            details={"key": "MY_VAR"},
        )

        engine.save_decisions()

        saved_config = json.loads(config_path.read_text())
        assert "MY_VAR" in saved_config.get("allow_env_var_writes", [])


class TestUnhandledEvents:
    """Tests for events not explicitly handled."""

    def test_unhandled_events_allowed(self, tmp_path):
        """Test that events without handlers are allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        # Random event that's not handled
        assert engine.check_permission("compile", ("source", "filename"))
        assert engine.check_permission("exec", ("code",))
        assert engine.check_permission("import", ("module",))


class TestPathVariableExpansion:
    """Tests for path variable expansion."""

    def test_expand_pwd(self, tmp_path):
        """Test that $PWD is expanded to workdir."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._expand_path_variables("$PWD/subdir")
        assert result == f"{tmp_path}/subdir"

    def test_expand_home(self, tmp_path):
        """Test that $HOME is expanded correctly."""
        import os
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._expand_path_variables("$HOME/.config")
        expected = os.path.expanduser("~") + "/.config"
        assert result == expected

    def test_expand_tmpdir(self, tmp_path):
        """Test that $TMPDIR is expanded correctly."""
        import tempfile
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._expand_path_variables("$TMPDIR/test")
        expected = tempfile.gettempdir() + "/test"
        assert result == expected

    def test_expand_python_stdlib(self, tmp_path):
        """Test that $PYTHON_STDLIB is expanded correctly."""
        import sysconfig
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._expand_path_variables("$PYTHON_STDLIB")
        expected = sysconfig.get_path("stdlib") or ""
        assert result == expected

    def test_expand_python_site_packages(self, tmp_path):
        """Test that $PYTHON_SITE_PACKAGES is expanded correctly."""
        import sysconfig
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._expand_path_variables("$PYTHON_SITE_PACKAGES")
        expected = sysconfig.get_path("purelib") or ""
        assert result == expected

    def test_expand_env_var(self, tmp_path, monkeypatch):
        """Test that $ENV{VAR} expands to environment variable."""
        monkeypatch.setenv("MY_TEST_VAR", "/custom/path")
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._expand_path_variables("$ENV{MY_TEST_VAR}/subdir")
        assert result == "/custom/path/subdir"

    def test_expand_env_var_missing(self, tmp_path):
        """Test that missing $ENV{VAR} expands to empty string."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._expand_path_variables("$ENV{NONEXISTENT_VAR_12345}/subdir")
        assert result == "/subdir"

    def test_no_expansion_without_dollar(self, tmp_path):
        """Test that paths without $ are returned unchanged."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._expand_path_variables("/some/absolute/path")
        assert result == "/some/absolute/path"

    def test_variables_work_in_config(self, tmp_path):
        """Test that variables in config are expanded for permission checks."""
        config = {"allow_read": ["$PWD/allowed"]}
        config_path = tmp_path / ".malwi-box"
        config_path.write_text(json.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        test_file = allowed_dir / "test.txt"
        test_file.write_text("test")

        # File in $PWD/allowed should be allowed
        assert engine.check_permission("open", (str(test_file), "r", 0))


class TestPathToVariable:
    """Tests for converting paths back to variables."""

    def test_convert_pwd(self, tmp_path):
        """Test converting workdir path to $PWD."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._path_to_variable(f"{tmp_path}/subdir")
        assert result == "$PWD/subdir"

    def test_convert_home(self, tmp_path):
        """Test converting home path to $HOME."""
        import os
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)
        home = os.path.expanduser("~")

        result = engine._path_to_variable(f"{home}/.config")
        assert result == "$HOME/.config"

    def test_convert_tmpdir(self, tmp_path):
        """Test converting temp path to $TMPDIR."""
        import tempfile
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)
        tmpdir = tempfile.gettempdir()

        result = engine._path_to_variable(f"{tmpdir}/test")
        assert result == "$TMPDIR/test"

    def test_convert_site_packages(self, tmp_path):
        """Test converting site-packages path to $PYTHON_SITE_PACKAGES."""
        import sysconfig
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)
        site_packages = sysconfig.get_path("purelib")

        if site_packages:
            result = engine._path_to_variable(f"{site_packages}/mypackage")
            assert result == "$PYTHON_SITE_PACKAGES/mypackage"

    def test_no_conversion_for_unknown_path(self, tmp_path):
        """Test that unknown paths are returned unchanged."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box", workdir=tmp_path)

        result = engine._path_to_variable("/some/random/path")
        assert result == "/some/random/path"

    def test_save_decisions_converts_to_variables(self, tmp_path):
        """Test that save_decisions converts paths to variables."""
        config_path = tmp_path / ".malwi-box"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Record a decision with an absolute path in workdir
        test_path = f"{tmp_path}/test.txt"
        engine.record_decision(
            "open",
            (test_path, "r"),
            allowed=True,
            details={"path": test_path, "mode": "r", "is_new_file": False},
        )

        engine.save_decisions()

        saved_config = json.loads(config_path.read_text())
        # Should be saved as $PWD/test.txt, not the absolute path
        assert "$PWD/test.txt" in saved_config.get("allow_read", [])
