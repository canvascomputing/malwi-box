"""Tests for CLI functionality."""

import subprocess
import sys


class TestCLICommands:
    """Tests for CLI command structure."""

    def test_help_shows_subcommands(self):
        """Test that main help shows all subcommands."""
        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "run" in result.stdout
        assert "eval" in result.stdout
        assert "install" in result.stdout

    def test_run_help(self):
        """Test run subcommand help."""
        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "--review" in result.stdout

    def test_install_help(self):
        """Test install subcommand help."""
        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "install", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "--review" in result.stdout
        assert "--version" in result.stdout
        assert "-r" in result.stdout
        assert "--requirements" in result.stdout

    def test_install_without_args_errors(self):
        """Test that install without package or requirements errors."""
        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "install"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "Must specify package or -r/--requirements" in result.stderr


class TestEvalCommand:
    """Tests for eval subcommand."""

    def test_eval_help(self):
        """Test eval subcommand help."""
        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "eval", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "--review" in result.stdout
        assert "--force" in result.stdout
        assert "code" in result.stdout

    def test_eval_simple_code(self, tmp_path):
        """Test executing simple code string."""
        # Use default config with proper read permissions
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "eval", "print('hello')"],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_eval_with_force_flag(self, tmp_path):
        """Test eval with --force flag logs violations but continues."""
        # Config with stdlib permissions but blocking /etc/passwd
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "malwi_box.cli",
                "eval",
                "--force",
                "open('/etc/passwd'); print('done')",
            ],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )
        # With --force, code continues despite violations
        assert "done" in result.stdout

    def test_eval_blocks_violations(self, tmp_path):
        """Test that eval blocks security violations without --force."""
        # Allow stdlib but block /etc/passwd
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "malwi_box.cli",
                "eval",
                "open('/etc/passwd'); print('should not reach')",
            ],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )
        # Should be blocked before reaching print
        assert result.returncode != 0
        assert "should not reach" not in result.stdout


class TestConfigCreate:
    """Tests for config create subcommand."""

    def test_config_create_help(self):
        """Test that config create --help shows options."""
        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "config", "create", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "--path" in result.stdout

    def test_config_create_default_path(self, tmp_path):
        """Test creating config at default path."""
        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "config", "create"],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )
        assert result.returncode == 0
        assert (tmp_path / ".malwi-box.toml").exists()
        assert "Created" in result.stdout

    def test_config_create_custom_path(self, tmp_path):
        """Test creating config at custom path."""
        custom = tmp_path / "custom.yaml"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "malwi_box.cli",
                "config",
                "create",
                "--path",
                str(custom),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert custom.exists()

    def test_config_create_refuses_overwrite(self, tmp_path):
        """Test that config create refuses to overwrite existing file."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text("allow_read = []")
        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "config", "create"],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )
        assert result.returncode == 1
        assert "already exists" in result.stderr


class TestFormatEvent:
    """Tests for _format_event function."""

    def test_format_open_read(self):
        """Test formatting of file read events."""
        from malwi_box.formatting import format_event as _format_event

        result = _format_event("open", ("/etc/passwd", "r", 0))
        assert result == "Read file: /etc/passwd"

    def test_format_open_write_new_file(self, tmp_path):
        """Test formatting of file create events."""
        from malwi_box.formatting import format_event as _format_event

        new_file = str(tmp_path / "newfile.txt")
        result = _format_event("open", (new_file, "w", 0))
        assert result == f"Create file: {new_file}"

    def test_format_open_write_existing_file(self, tmp_path):
        """Test formatting of file modify events."""
        from malwi_box.formatting import format_event as _format_event

        existing = tmp_path / "existing.txt"
        existing.write_text("content")
        result = _format_event("open", (str(existing), "w", 0))
        assert result == f"Modify file: {existing}"

    def test_format_putenv(self):
        """Test formatting of env var set events."""
        from malwi_box.formatting import format_event as _format_event

        result = _format_event("os.putenv", (b"MY_VAR", b"my_value"))
        assert result == "Set env var: MY_VAR=my_value"

    def test_format_putenv_truncates_long_values(self):
        """Test that long env var values are truncated."""
        from malwi_box.formatting import format_event as _format_event

        long_value = "x" * 100
        result = _format_event("os.putenv", (b"KEY", long_value.encode()))
        assert "..." in result
        assert len(result) < 80

    def test_format_unsetenv(self):
        """Test formatting of env var unset events."""
        from malwi_box.formatting import format_event as _format_event

        result = _format_event("os.unsetenv", (b"MY_VAR",))
        assert result == "Unset env var: MY_VAR"

    def test_format_dns_lookup_with_port(self):
        """Test formatting of DNS lookup with port."""
        from malwi_box.formatting import format_event as _format_event

        result = _format_event("socket.getaddrinfo", ("example.com", 443, 0, 1, 0))
        assert result == "DNS lookup: example.com:443"

    def test_format_dns_lookup_without_port(self):
        """Test formatting of DNS lookup without port."""
        from malwi_box.formatting import format_event as _format_event

        result = _format_event("socket.gethostbyname", ("example.com",))
        assert result == "DNS lookup: example.com"

    def test_format_subprocess(self):
        """Test formatting of subprocess events."""
        from malwi_box.formatting import format_event as _format_event

        # args[1] is argv which includes program name
        args = ("/bin/ls", ["/bin/ls", "-la", "/tmp"], None, None)
        result = _format_event("subprocess.Popen", args)
        assert result == "Execute: /bin/ls -la /tmp"

    def test_format_subprocess_truncates_long_commands(self):
        """Test that long commands are truncated."""
        from malwi_box.formatting import format_event as _format_event

        long_args = ["arg"] * 50
        result = _format_event("subprocess.Popen", ("/bin/cmd", long_args, None, None))
        assert "..." in result
        assert len(result) <= 95  # "Execute: " prefix + truncated command

    def test_format_os_system(self):
        """Test formatting of os.system events."""
        from malwi_box.formatting import format_event as _format_event

        result = _format_event("os.system", ("ls -la",))
        assert result == "Shell: ls -la"

    def test_format_unknown_event_fallback(self):
        """Test fallback for unknown events."""
        from malwi_box.formatting import format_event as _format_event

        result = _format_event("unknown.event", ("arg1", "arg2"))
        assert "unknown.event" in result
        assert "arg1" in result


class TestMakeHashable:
    """Tests for session tracking with unhashable args."""

    def test_run_with_review_blocks_disallowed_file(self, tmp_path):
        """Test that review mode prompts for files not in config."""
        # Create a simple script that tries to read a file outside workdir
        script = tmp_path / "test_script.py"
        script.write_text("""
import sys
try:
    # Try to read a file that should be blocked
    open('/etc/passwd', 'r')
except SystemExit:
    pass
print("done")
""")
        # Create empty config to ensure /etc/passwd is not allowed
        config = tmp_path / ".malwi-box.toml"
        config.write_text("allow_read = []\nallow_domains = []")

        # Run with review mode, deny the request
        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--review", str(script)],
            input="n\n",
            capture_output=True,
            text=True,
            timeout=10,
            cwd=tmp_path,
        )
        # Should see the approval prompt
        assert "[malwi-box]" in result.stderr
