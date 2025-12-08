"""Tests for BoxEngine permission enforcement."""

from malwi_box import toml
from malwi_box.engine import BoxEngine
from malwi_box.formatting import _build_command


class TestConfigLoading:
    """Tests for configuration loading."""

    def test_default_config_when_no_file(self, tmp_path):
        """Test that default config is used when no file exists."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        # Default config uses variable $PYPI_DOMAINS (expands to pypi domains)
        assert "$PYPI_DOMAINS" in engine.config["allow_domains"]
        # Default config uses variables like $PWD which get expanded at runtime
        assert "$PWD" in engine.config["allow_read"]
        assert "$PWD" in engine.config["allow_create"]
        # Pip-friendly defaults allow modify in temp dirs
        assert "$TMPDIR" in engine.config["allow_modify"]
        assert "$PIP_CACHE" in engine.config["allow_modify"]
        # Delete is allowed in temp dirs by default
        assert "$TMPDIR" in engine.config["allow_delete"]
        assert "$PIP_CACHE" in engine.config["allow_delete"]

    def test_load_config_from_file(self, tmp_path):
        """Test loading config from YAML file."""
        config = {
            "allow_read": ["/etc/hosts"],
            "allow_domains": [],
            "allow_shell_commands": ["ls *"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert "/etc/hosts" in engine.config["allow_read"]
        assert engine.config["allow_domains"] == []
        assert "ls *" in engine.config["allow_shell_commands"]

    def test_merge_missing_keys_with_defaults(self, tmp_path):
        """Test that missing config keys are filled with defaults."""
        config = {"allow_domains": ["example.com"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Should have default for missing keys
        assert "allow_read" in engine.config
        assert "allow_shell_commands" in engine.config
        assert "allow_executables" in engine.config


class TestFilePermissions:
    """Tests for file access permission checks."""

    def test_allow_read_in_workdir(self, tmp_path):
        """Test that reads in workdir are allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        # Simulate 'open' event for reading
        assert engine.check_permission("open", (str(test_file), "r", 0))

    def test_allow_create_in_workdir(self, tmp_path):
        """Test that creating files in workdir is allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)
        test_file = tmp_path / "new_file.txt"

        # Simulate 'open' event for creating new file
        assert engine.check_permission("open", (str(test_file), "w", 0))

    def test_allow_modify_in_workdir(self, tmp_path):
        """Test that modifying files in workdir is allowed when configured."""
        config = {"allow_modify": ["$PWD"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)
        test_file = tmp_path / "existing.txt"
        test_file.write_text("existing content")

        # Simulate 'open' event for modifying existing file
        assert engine.check_permission("open", (str(test_file), "w", 0))

    def test_block_read_outside_allowed(self, tmp_path):
        """Test that reads outside allowed paths are blocked."""
        config = {
            "allow_read": [str(tmp_path / "allowed")],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Outside allowed directory
        assert not engine.check_permission("open", ("/etc/passwd", "r", 0))

    def test_allow_specific_file(self, tmp_path):
        """Test allowing a specific file path."""
        config = {"allow_read": ["/etc/hosts"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("open", ("/etc/hosts", "r", 0))

    def test_block_create_outside_allowed(self, tmp_path):
        """Test that creating files outside allowed paths is blocked."""
        config = {
            "allow_create": [str(tmp_path / "allowed")],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # New file outside allowed directory
        assert not engine.check_permission("open", ("/tmp/newfile.txt", "w", 0))

    def test_block_modify_outside_allowed(self, tmp_path):
        """Test that modifying files outside allowed paths is blocked."""
        config = {
            "allow_modify": [str(tmp_path / "allowed")],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

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
        expected_hash = (
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        )

        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)
        assert engine._verify_file_hash(test_file, expected_hash)

    def test_reject_wrong_hash(self, tmp_path):
        """Test that wrong hash fails verification."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        wrong_hash = (
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        )

        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)
        assert not engine._verify_file_hash(test_file, wrong_hash)


class TestShellCommands:
    """Tests for shell command permission checks."""

    def test_allow_matching_glob(self, tmp_path):
        """Test that commands matching glob pattern are allowed."""
        config = {
            "allow_executables": ["*"],  # Allow all executables
            "allow_shell_commands": ["/bin/ls *", "/usr/bin/git *", "ls *"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # subprocess.Popen event with full path
        assert engine.check_permission(
            "subprocess.Popen", ("/bin/ls", ["-la", "/tmp"], None, None)
        )
        assert engine.check_permission(
            "subprocess.Popen", ("/usr/bin/git", ["status"], None, None)
        )
        # Also test without full path
        assert engine.check_permission("subprocess.Popen", ("ls", ["-la"], None, None))

    def test_block_non_matching_command(self, tmp_path):
        """Test that commands not matching patterns are blocked."""
        config = {
            "allow_executables": ["*"],  # Allow all executables
            "allow_shell_commands": ["ls *"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # rm is not in allowed shell command patterns
        assert not engine.check_permission(
            "subprocess.Popen", ("/bin/rm", ["-rf", "/tmp/test"], None, None)
        )

    def test_os_system_command(self, tmp_path):
        """Test os.system event handling (shell commands only, no executable check)."""
        config = {"allow_shell_commands": ["echo *"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # os.system only checks shell commands, not executables
        assert engine.check_permission("os.system", ("echo hello",))
        assert not engine.check_permission("os.system", ("rm -rf /",))


class TestCommandPatternMatching:
    """Tests for shell command glob pattern matching."""

    def test_manual_glob_pattern_matches_similar_command(self, tmp_path):
        """Test that manually added glob patterns match similar commands."""
        # User manually edits config to add glob pattern
        config = {"allow_executables": ["*"], "allow_shell_commands": ["git clone *"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Different git clone commands should all match the pattern
        assert engine.check_permission(
            "subprocess.Popen",
            ("git", ["clone", "https://github.com/user/repo1"], None, None),
        )
        assert engine.check_permission(
            "subprocess.Popen",
            ("git", ["clone", "https://github.com/user/repo2"], None, None),
        )
        assert engine.check_permission(
            "subprocess.Popen",
            ("git", ["clone", "--depth=1", "https://example.com/repo"], None, None),
        )

    def test_saved_command_skipped_if_pattern_covers(self, tmp_path):
        """Test that saving a command is skipped if pattern already covers it."""
        config = {"allow_shell_commands": ["git clone *"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Try to save a specific command that's already covered by pattern
        engine._save_shell_command(config, "git clone https://github.com/user/repo2")

        # Should not add the specific command since pattern covers it
        assert config["allow_shell_commands"] == ["git clone *"]

    def test_exact_command_in_config_matches(self, tmp_path):
        """Test that exact command in allow_shell_commands matches the same command.

        Regression test: commands were saved without exe but checked with exe.
        e.g., "version" was saved but "git version" was checked.
        """
        # Simulate what happens when user approves "git version"
        config = {"allow_executables": ["*"], "allow_shell_commands": ["git version"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # subprocess.Popen("git", ["version"]) should match "git version"
        assert engine.check_permission(
            "subprocess.Popen", ("git", ["version"], None, None)
        )

    def test_command_with_full_path_matches(self, tmp_path):
        """Test that command with full path in config matches."""
        config = {
            "allow_executables": ["*"],
            "allow_shell_commands": ["/usr/bin/git version"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Full path command should match
        assert engine.check_permission(
            "subprocess.Popen", ("/usr/bin/git", ["version"], None, None)
        )

    def test_command_with_argv0_convention_matches(self, tmp_path):
        """Test command matches when args include program name (argv[0] convention).

        When subprocess.Popen is called with a list like ['git', 'rev-parse', 'HEAD'],
        the args tuple includes the program name as the first element.
        """
        config = {
            "allow_executables": ["*"],
            "allow_shell_commands": ["git rev-parse HEAD"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Args include program name (argv[0] convention)
        assert engine.check_permission(
            "subprocess.Popen",
            ("git", ["git", "rev-parse", "HEAD"], None, None),
        )

    def test_full_path_exe_with_short_argv0_matches(self, tmp_path):
        """Test full path exe matches when argv[0] is short name.

        Common case: exe is resolved to full path but argv[0] is short name.
        """
        config = {
            "allow_executables": ["*"],
            "allow_shell_commands": ["git status"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Full path exe with short name in argv[0]
        assert engine.check_permission(
            "subprocess.Popen",
            ("/usr/bin/git", ["git", "status"], None, None),
        )

    def test_command_without_args_matches(self, tmp_path):
        """Test command with no arguments matches."""
        config = {
            "allow_executables": ["*"],
            "allow_shell_commands": ["python"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Command with empty args
        assert engine.check_permission(
            "subprocess.Popen", ("python", [], None, None)
        )

    def test_wildcard_pattern_with_complex_args(self, tmp_path):
        """Test wildcard patterns match commands with complex arguments."""
        config = {
            "allow_executables": ["*"],
            "allow_shell_commands": ["git clone *"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Complex git clone command with multiple flags
        assert engine.check_permission(
            "subprocess.Popen",
            (
                "git",
                ["git", "clone", "--filter=blob:none", "--quiet", "https://x.com/r"],
                None,
                None,
            ),
        )

    def test_raw_toml_config_file(self, tmp_path):
        """Test loading commands from a raw TOML file (as user would edit).

        This tests the actual file format, not just programmatic config.
        """
        config_path = tmp_path / ".malwi-box.toml"
        # Raw TOML as a user would write it
        config_path.write_text('''
allow_executables = ["*"]
allow_shell_commands = [
    "git rev-parse HEAD",
    "git status",
    "git clone *",
]
''')

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Exact match
        assert engine.check_permission(
            "subprocess.Popen",
            ("git", ["git", "rev-parse", "HEAD"], None, None),
        )
        # Another exact match
        assert engine.check_permission(
            "subprocess.Popen",
            ("git", ["git", "status"], None, None),
        )
        # Glob pattern match
        assert engine.check_permission(
            "subprocess.Popen",
            ("git", ["git", "clone", "https://github.com/user/repo"], None, None),
        )
        # Should NOT match
        assert not engine.check_permission(
            "subprocess.Popen",
            ("git", ["git", "push"], None, None),
        )


class TestBuildCommand:
    """Tests for _build_command function."""

    def test_short_exe_with_argv0(self):
        """Test short exe when args include program name."""
        assert _build_command("git", ["git", "status"]) == "git status"

    def test_short_exe_without_argv0(self):
        """Test short exe when args don't include program name."""
        assert _build_command("git", ["status"]) == "git status"

    def test_full_path_exe_with_short_argv0(self):
        """Test full path exe with short program name in args."""
        assert _build_command("/usr/bin/git", ["git", "status"]) == "git status"

    def test_full_path_exe_with_full_path_argv0(self):
        """Test full path exe with full path in args."""
        result = _build_command("/usr/bin/git", ["/usr/bin/git", "status"])
        assert result == "/usr/bin/git status"

    def test_exe_only_no_args(self):
        """Test command with no arguments."""
        assert _build_command("python", []) == "python"

    def test_multi_word_args(self):
        """Test command with multiple arguments."""
        result = _build_command("git", ["git", "clone", "--depth=1", "https://x.com"])
        assert result == "git clone --depth=1 https://x.com"

    def test_args_with_different_basename(self):
        """Test when first arg is not the executable."""
        result = _build_command("python", ["-m", "pip", "install"])
        assert result == "python -m pip install"


class TestExecutableControl:
    """Tests for executable control (allow_executables)."""

    def test_empty_list_blocks_all(self, tmp_path):
        """Test that empty allow_executables blocks all executables."""
        config = {"allow_executables": [], "allow_shell_commands": ["*"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Empty list should block all executables
        assert not engine.check_permission(
            "subprocess.Popen", ("/bin/ls", ["-la"], None, None)
        )
        assert not engine.check_permission("os.exec", ("/bin/bash", [], None))
        assert not engine.check_permission("ctypes.dlopen", ("/usr/lib/libc.dylib",))

    def test_glob_allows_all(self, tmp_path):
        """Test that '*' glob pattern allows all executables."""
        config = {"allow_executables": ["*"], "allow_shell_commands": ["*"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # "*" pattern should allow all executables
        assert engine.check_permission(
            "subprocess.Popen", ("/bin/ls", ["-la"], None, None)
        )
        assert engine.check_permission("os.exec", ("/bin/bash", [], None))
        assert engine.check_permission("ctypes.dlopen", ("/usr/lib/libc.dylib",))

    def test_allow_specific_executable(self, tmp_path):
        """Test allowing a specific executable path."""
        config = {"allow_executables": ["/bin/ls"], "allow_shell_commands": ["*"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # /bin/ls should be allowed
        assert engine.check_permission(
            "subprocess.Popen", ("/bin/ls", ["-la"], None, None)
        )
        # /bin/rm should be blocked (not in allow_executables)
        assert not engine.check_permission(
            "subprocess.Popen", ("/bin/rm", ["-rf"], None, None)
        )

    def test_short_executable_name_resolved_via_path(self, tmp_path):
        """Test that short executable names in config are resolved via PATH.

        Regression test: Executables saved as short names (e.g., "git") were not
        matching when checked because _resolve_path treated them as relative paths
        instead of using PATH lookup via _resolve_executable.
        """
        import shutil

        # Find an actual executable on the system
        git_path = shutil.which("git")
        if git_path is None:
            import pytest

            pytest.skip("git not found on system")

        # Compute the hash of the actual git binary
        import hashlib

        with open(git_path, "rb") as f:
            git_hash = f"sha256:{hashlib.sha256(f.read()).hexdigest()}"

        # Config with short name "git" and its hash
        config = {
            "allow_executables": [{"path": "git", "hash": git_hash}],
            "allow_shell_commands": ["git version"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Should match: short name "git" resolves to full path via PATH lookup
        assert engine.check_permission(
            "subprocess.Popen", ("git", ["git", "version"], None, None)
        )

    def test_allow_executable_with_variable(self, tmp_path):
        """Test allowing executables with path variables."""
        # Create a fake executable in workdir
        exe = tmp_path / "my_script"
        exe.write_text("#!/bin/bash\necho hello")
        exe.chmod(0o755)

        config = {
            "allow_executables": ["$PWD/my_script"],
            "allow_shell_commands": ["*"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("subprocess.Popen", (str(exe), [], None, None))

    def test_block_unresolvable_executable(self, tmp_path):
        """Test that unresolvable executables are blocked when restrictions exist."""
        config = {"allow_executables": ["/bin/ls"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Nonexistent executable should be blocked
        assert not engine.check_permission(
            "subprocess.Popen", ("nonexistent_command_xyz", [], None, None)
        )

    def test_os_exec_event(self, tmp_path):
        """Test executable control for os.exec event."""
        config = {"allow_executables": ["/bin/bash"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # os.exec: (path, args, env)
        assert engine.check_permission("os.exec", ("/bin/bash", ["-c", "echo"], None))
        assert not engine.check_permission("os.exec", ("/bin/sh", ["-c", "echo"], None))

    def test_os_spawn_event(self, tmp_path):
        """Test executable control for os.spawn event."""
        config = {"allow_executables": ["/bin/echo"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # os.spawn: (mode, path, args, env)
        assert engine.check_permission("os.spawn", (0, "/bin/echo", ["hello"], None))
        assert not engine.check_permission("os.spawn", (0, "/bin/cat", ["file"], None))

    def test_ctypes_dlopen_event(self, tmp_path):
        """Test executable control for ctypes.dlopen event."""
        config = {"allow_executables": ["/usr/lib/libc.dylib"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # ctypes.dlopen: (name,)
        assert engine.check_permission("ctypes.dlopen", ("/usr/lib/libc.dylib",))
        assert not engine.check_permission("ctypes.dlopen", ("/usr/lib/other.dylib",))

    def test_executable_with_hash_verification(self, tmp_path):
        """Test executable with hash verification."""
        # Create a test executable
        exe = tmp_path / "test_exe"
        exe.write_text("#!/bin/bash\necho test")
        exe.chmod(0o755)

        # Get the actual hash
        import hashlib

        actual_hash = hashlib.sha256(exe.read_bytes()).hexdigest()

        config = {
            "allow_executables": [{"path": str(exe), "hash": f"sha256:{actual_hash}"}],
            "allow_shell_commands": ["*"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Correct hash should pass
        assert engine.check_permission("subprocess.Popen", (str(exe), [], None, None))

    def test_executable_with_wrong_hash_blocked(self, tmp_path):
        """Test that wrong hash blocks the executable."""
        exe = tmp_path / "test_exe"
        exe.write_text("#!/bin/bash\necho test")
        exe.chmod(0o755)

        wrong_hash = (
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        )
        config = {
            "allow_executables": [{"path": str(exe), "hash": wrong_hash}],
            "allow_shell_commands": ["*"],
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Wrong hash should fail
        assert not engine.check_permission(
            "subprocess.Popen", (str(exe), [], None, None)
        )

    def test_save_and_reload_os_exec_permission(self, tmp_path):
        """Test that saved os.exec permission works after reload.

        This reproduces a bug where executable permissions saved in review mode
        did not work on subsequent runs because the path resolution differed.
        """
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Simulate what happens in review mode: record a decision for os.exec
        engine.record_decision(
            "os.exec",
            ("/bin/echo", ["/bin/echo", "hello"]),
            allowed=True,
            details={"executable": "/bin/echo"},
        )
        engine.save_decisions()

        # Reload config and verify permission works
        engine2 = BoxEngine(config_path=str(config_path), workdir=tmp_path)
        args = ("/bin/echo", ["/bin/echo", "hello"])
        assert engine2.check_permission("os.exec", args)

    def test_save_and_reload_subprocess_permission(self, tmp_path):
        """Test that saved subprocess.Popen permission works after reload."""
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Simulate review mode decision
        engine.record_decision(
            "subprocess.Popen",
            ("/bin/ls", ["-la"]),
            allowed=True,
            details={"executable": "/bin/ls", "command": "/bin/ls -la"},
        )
        engine.save_decisions()

        # Reload and verify
        engine2 = BoxEngine(config_path=str(config_path), workdir=tmp_path)
        assert engine2.check_permission("subprocess.Popen", ("/bin/ls", ["-la"]))

    def test_save_executable_hash_fallback(self, tmp_path):
        """Test that unresolvable executable falls back to path-only."""
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Record decision for non-existent executable
        exe = "nonexistent_binary_xyz"
        engine.record_decision(
            "subprocess.Popen",
            (exe, []),
            allowed=True,
            details={"executable": exe, "command": exe},
        )
        engine.save_decisions()

        saved_config = toml.loads(config_path.read_text())
        executables = saved_config.get("allow_executables", [])
        assert len(executables) == 1
        # Should be plain string since we can't compute hash
        assert executables[0] == "nonexistent_binary_xyz"


class TestDomainPermissions:
    """Tests for domain permission checks via DNS resolution events."""

    def test_allow_pypi_by_default(self, tmp_path):
        """Test that PyPI domains are allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        # socket.getaddrinfo event with PyPI domain
        assert engine.check_permission("socket.getaddrinfo", ("pypi.org", 443, 0, 1, 0))
        assert engine.check_permission(
            "socket.getaddrinfo", ("files.pythonhosted.org", 443, 0, 1, 0)
        )
        # socket.gethostbyname event
        assert engine.check_permission("socket.gethostbyname", ("pypi.org",))

    def test_block_pypi_when_removed_from_allow_domains(self, tmp_path):
        """Test that PyPI domains are blocked when removed from allow_domains."""
        config = {"allow_domains": []}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert not engine.check_permission(
            "socket.getaddrinfo", ("pypi.org", 443, 0, 1, 0)
        )
        assert not engine.check_permission("socket.gethostbyname", ("pypi.org",))

    def test_block_unknown_domains(self, tmp_path):
        """Test that unknown domains are blocked."""
        config = {"allow_domains": ["pypi.org"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Random domain should be blocked
        assert not engine.check_permission(
            "socket.getaddrinfo", ("example.com", 80, 0, 1, 0)
        )
        assert not engine.check_permission("socket.gethostbyname", ("example.com",))

    def test_allow_domain_any_port(self, tmp_path):
        """Test that domain without port allows any port."""
        config = {"allow_domains": ["httpbin.org"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission(
            "socket.getaddrinfo", ("httpbin.org", 80, 0, 1, 0)
        )
        assert engine.check_permission(
            "socket.getaddrinfo", ("httpbin.org", 443, 0, 1, 0)
        )
        assert engine.check_permission(
            "socket.getaddrinfo", ("httpbin.org", 8080, 0, 1, 0)
        )
        assert engine.check_permission("socket.gethostbyname", ("httpbin.org",))

    def test_allow_domain_specific_port(self, tmp_path):
        """Test that domain:port only allows that specific port."""
        config = {"allow_domains": ["api.example.com:443"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Correct port - allowed
        assert engine.check_permission(
            "socket.getaddrinfo", ("api.example.com", 443, 0, 1, 0)
        )
        # Wrong port - blocked
        assert not engine.check_permission(
            "socket.getaddrinfo", ("api.example.com", 80, 0, 1, 0)
        )
        # gethostbyname has no port, so domain:port entry allows it (port is None)
        assert engine.check_permission("socket.gethostbyname", ("api.example.com",))

    def test_allow_subdomain(self, tmp_path):
        """Test that subdomains are allowed when parent domain is in list."""
        config = {"allow_domains": ["example.com"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission(
            "socket.getaddrinfo", ("example.com", 443, 0, 1, 0)
        )
        assert engine.check_permission(
            "socket.getaddrinfo", ("api.example.com", 443, 0, 1, 0)
        )
        assert engine.check_permission(
            "socket.getaddrinfo", ("www.example.com", 80, 0, 1, 0)
        )


class TestEnvVarPermissions:
    """Tests for environment variable permission checks."""

    def test_allow_env_read(self, tmp_path):
        """Test that allowed env var reads pass."""
        config = {"allow_env_var_reads": ["PATH", "HOME"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("os.getenv", ("PATH",))
        assert engine.check_permission("os.environ.get", ("HOME",))

    def test_block_env_read_when_empty(self, tmp_path):
        """Test that empty allow_env_var_reads blocks all reads."""
        config = {"allow_env_var_reads": []}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert not engine.check_permission("os.getenv", ("PATH",))
        assert not engine.check_permission("os.environ.get", ("HOME",))

    def test_block_sensitive_env_read(self, tmp_path):
        """Test that sensitive env vars are always blocked."""
        config = {"allow_env_var_reads": ["AWS_SECRET_ACCESS_KEY"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Even if explicitly allowed, sensitive vars are blocked
        assert not engine.check_permission("os.getenv", ("AWS_SECRET_ACCESS_KEY",))
        assert not engine.check_permission("os.environ.get", ("GITHUB_TOKEN",))

    def test_allow_env_read_with_variable(self, tmp_path):
        """Test that $SAFE_ENV_VARS variable expands correctly."""
        config = {"allow_env_var_reads": ["$SAFE_ENV_VARS"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Safe env vars should be allowed
        assert engine.check_permission("os.getenv", ("PATH",))
        assert engine.check_permission("os.getenv", ("HOME",))
        assert engine.check_permission("os.getenv", ("PYTHONPATH",))
        # Non-safe vars should be blocked
        assert not engine.check_permission("os.getenv", ("MY_CUSTOM_VAR",))


class TestDecisionRecording:
    """Tests for review mode decision recording."""

    def test_record_and_save_read_decision(self, tmp_path):
        """Test that read decisions are saved correctly."""
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        test_file = str(tmp_path / "test.txt")
        engine.record_decision(
            "open",
            (test_file, "r"),
            allowed=True,
            details={"path": test_file, "mode": "r", "is_new_file": False},
        )

        engine.save_decisions()

        saved_config = toml.loads(config_path.read_text())
        # Path is converted to $PWD variable (workdir)
        allow_read = saved_config.get("allow_read", [])
        assert any("$PWD/test.txt" in str(e) for e in allow_read)

    def test_record_and_save_create_decision(self, tmp_path):
        """Test that create decisions are saved correctly."""
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        new_file = str(tmp_path / "newfile.txt")
        engine.record_decision(
            "open",
            (new_file, "w"),
            allowed=True,
            details={"path": new_file, "mode": "w", "is_new_file": True},
        )

        engine.save_decisions()

        saved_config = toml.loads(config_path.read_text())
        # Path is converted to $PWD variable (workdir)
        assert "$PWD/newfile.txt" in saved_config.get("allow_create", [])

    def test_record_and_save_modify_decision(self, tmp_path):
        """Test that modify decisions are saved correctly."""
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        existing_file = str(tmp_path / "existing.txt")
        engine.record_decision(
            "open",
            (existing_file, "w"),
            allowed=True,
            details={"path": existing_file, "mode": "w", "is_new_file": False},
        )

        engine.save_decisions()

        saved_config = toml.loads(config_path.read_text())
        # Path is converted to $PWD variable (workdir)
        allow_modify = saved_config.get("allow_modify", [])
        assert any("$PWD/existing.txt" in str(e) for e in allow_modify)

    def test_record_and_save_command_decision(self, tmp_path):
        """Test that command decisions are saved exactly with hash."""
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        engine.record_decision(
            "subprocess.Popen",
            ("git", ["status"]),
            allowed=True,
            details={"command": "git status", "executable": "git"},
        )

        engine.save_decisions()

        saved_config = toml.loads(config_path.read_text())
        # Command is saved exactly (user can manually edit to use glob patterns)
        assert "git status" in saved_config.get("allow_shell_commands", [])
        # Executable should be saved with hash
        executables = saved_config.get("allow_executables", [])
        assert len(executables) == 1
        entry = executables[0]
        assert isinstance(entry, dict)
        assert entry["path"] == "git"
        assert entry["hash"].startswith("sha256:")

    def test_record_and_save_domain_with_port(self, tmp_path):
        """Test that domain decisions with port are saved correctly."""
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Record domain decision with port
        engine.record_decision(
            "socket.getaddrinfo",
            ("httpbin.org", 443, 0, 1, 0),
            allowed=True,
            details={"domain": "httpbin.org", "port": 443},
        )

        engine.save_decisions()

        saved_config = toml.loads(config_path.read_text())
        assert "httpbin.org:443" in saved_config.get("allow_domains", [])

    def test_record_and_save_domain_without_port(self, tmp_path):
        """Test that domain decisions without port are saved correctly."""
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Record domain decision without port (gethostbyname)
        engine.record_decision(
            "socket.gethostbyname",
            ("example.com",),
            allowed=True,
            details={"domain": "example.com"},
        )

        engine.save_decisions()

        saved_config = toml.loads(config_path.read_text())
        assert "example.com" in saved_config.get("allow_domains", [])


class TestUnhandledEvents:
    """Tests for events not explicitly handled."""

    def test_unhandled_events_allowed(self, tmp_path):
        """Test that events without handlers are allowed by default."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        # Random event that's not handled
        assert engine.check_permission("compile", ("source", "filename"))
        assert engine.check_permission("exec", ("code",))
        assert engine.check_permission("import", ("module",))


class TestPathVariableExpansion:
    """Tests for path variable expansion."""

    def test_expand_pwd(self, tmp_path):
        """Test that $PWD is expanded to workdir."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._expand_path_variables("$PWD/subdir")
        assert result == f"{tmp_path}/subdir"

    def test_expand_home(self, tmp_path):
        """Test that $HOME is expanded correctly."""
        import os

        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._expand_path_variables("$HOME/.config")
        expected = os.path.expanduser("~") + "/.config"
        assert result == expected

    def test_expand_tmpdir(self, tmp_path):
        """Test that $TMPDIR is expanded correctly."""
        import tempfile

        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._expand_path_variables("$TMPDIR/test")
        expected = tempfile.gettempdir() + "/test"
        assert result == expected

    def test_expand_python_stdlib(self, tmp_path):
        """Test that $PYTHON_STDLIB is expanded correctly."""
        import sysconfig

        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._expand_path_variables("$PYTHON_STDLIB")
        expected = sysconfig.get_path("stdlib") or ""
        assert result == expected

    def test_expand_python_site_packages(self, tmp_path):
        """Test that $PYTHON_SITE_PACKAGES is expanded correctly."""
        import sysconfig

        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._expand_path_variables("$PYTHON_SITE_PACKAGES")
        expected = sysconfig.get_path("purelib") or ""
        assert result == expected

    def test_expand_env_var(self, tmp_path, monkeypatch):
        """Test that $ENV{VAR} expands to environment variable."""
        monkeypatch.setenv("MY_TEST_VAR", "/custom/path")
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._expand_path_variables("$ENV{MY_TEST_VAR}/subdir")
        assert result == "/custom/path/subdir"

    def test_expand_env_var_missing(self, tmp_path):
        """Test that missing $ENV{VAR} expands to empty string."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._expand_path_variables("$ENV{NONEXISTENT_VAR_12345}/subdir")
        assert result == "/subdir"

    def test_no_expansion_without_dollar(self, tmp_path):
        """Test that paths without $ are returned unchanged."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._expand_path_variables("/some/absolute/path")
        assert result == "/some/absolute/path"

    def test_variables_work_in_config(self, tmp_path):
        """Test that variables in config are expanded for permission checks."""
        config = {"allow_read": ["$PWD/allowed"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

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
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._path_to_variable(f"{tmp_path}/subdir")
        assert result == "$PWD/subdir"

    def test_convert_home(self, tmp_path):
        """Test converting home path to $HOME."""
        import os

        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)
        home = os.path.expanduser("~")

        result = engine._path_to_variable(f"{home}/.config")
        assert result == "$HOME/.config"

    def test_convert_tmpdir(self, tmp_path):
        """Test converting temp path to $TMPDIR."""
        import tempfile

        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)
        tmpdir = tempfile.gettempdir()

        result = engine._path_to_variable(f"{tmpdir}/test")
        assert result == "$TMPDIR/test"

    def test_convert_site_packages(self, tmp_path):
        """Test converting site-packages path to $PYTHON_SITE_PACKAGES."""
        import sysconfig

        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)
        site_packages = sysconfig.get_path("purelib")

        if site_packages:
            result = engine._path_to_variable(f"{site_packages}/mypackage")
            # If in a venv, it converts to $VENV, otherwise $PYTHON_SITE_PACKAGES
            assert "$PYTHON_SITE_PACKAGES" in result or "$VENV" in result

    def test_no_conversion_for_unknown_path(self, tmp_path):
        """Test that unknown paths are returned unchanged."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        result = engine._path_to_variable("/some/random/path")
        assert result == "/some/random/path"

    def test_save_decisions_converts_to_variables(self, tmp_path):
        """Test that save_decisions converts paths to variables."""
        config_path = tmp_path / ".malwi-box.toml"
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

        saved_config = toml.loads(config_path.read_text())
        # Should be saved as $PWD/test.txt, not the absolute path
        assert "$PWD/test.txt" in saved_config.get("allow_read", [])


class TestSocketConnect:
    """Tests for socket.connect event handling."""

    def test_allow_localhost(self, tmp_path):
        """Test that localhost connections are always allowed."""
        config = {"allow_ips": [], "allow_domains": []}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # socket.connect event: (socket, address) where address is (host, port)
        assert engine.check_permission("socket.connect", (None, ("localhost", 8080)))
        assert engine.check_permission("socket.connect", (None, ("127.0.0.1", 8080)))
        assert engine.check_permission("socket.connect", (None, ("::1", 8080)))

    def test_block_direct_ip_without_allow_ips(self, tmp_path):
        """Test that direct IP connections are blocked without allow_ips."""
        config = {"allow_ips": [], "allow_domains": []}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Direct IP should be blocked
        assert not engine.check_permission("socket.connect", (None, ("8.8.8.8", 53)))
        assert not engine.check_permission(
            "socket.connect", (None, ("192.168.1.1", 80))
        )

    def test_allow_ip_in_allow_ips(self, tmp_path):
        """Test that IPs in allow_ips are permitted."""
        config = {"allow_ips": ["8.8.8.8", "192.168.1.0/24"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Exact IP match
        assert engine.check_permission("socket.connect", (None, ("8.8.8.8", 53)))
        # CIDR match
        assert engine.check_permission("socket.connect", (None, ("192.168.1.100", 80)))
        assert engine.check_permission("socket.connect", (None, ("192.168.1.1", 443)))
        # Not in CIDR range
        assert not engine.check_permission(
            "socket.connect", (None, ("192.168.2.1", 80))
        )

    def test_allow_ip_with_port(self, tmp_path):
        """Test that IP:port in allow_ips only allows that port."""
        config = {"allow_ips": ["10.0.0.1:443"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Correct port
        assert engine.check_permission("socket.connect", (None, ("10.0.0.1", 443)))
        # Wrong port
        assert not engine.check_permission("socket.connect", (None, ("10.0.0.1", 80)))

    def test_hostname_falls_back_to_allow_domains(self, tmp_path):
        """Test that hostnames are checked against allow_domains."""
        config = {"allow_domains": ["example.com"], "allow_ips": []}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Hostname should check allow_domains
        assert engine.check_permission("socket.connect", (None, ("example.com", 443)))
        assert engine.check_permission(
            "socket.connect", (None, ("api.example.com", 80))
        )
        assert not engine.check_permission("socket.connect", (None, ("evil.com", 80)))

    def test_ipv6_address(self, tmp_path):
        """Test IPv6 address handling."""
        config = {"allow_ips": ["2001:db8::/32"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("socket.connect", (None, ("2001:db8::1", 80)))
        assert not engine.check_permission(
            "socket.connect", (None, ("2001:db9::1", 80))
        )

    def test_ipv6_with_port(self, tmp_path):
        """Test IPv6 with port using bracket notation."""
        config = {"allow_ips": ["[2001:db8::1]:443"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("socket.connect", (None, ("2001:db8::1", 443)))
        assert not engine.check_permission(
            "socket.connect", (None, ("2001:db8::1", 80))
        )


class TestAdditionalDNSEvents:
    """Tests for additional DNS resolution events."""

    def test_gethostbyname_ex(self, tmp_path):
        """Test socket.gethostbyname_ex event."""
        config = {"allow_domains": ["example.com"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("socket.gethostbyname_ex", ("example.com",))
        assert not engine.check_permission("socket.gethostbyname_ex", ("evil.com",))

    def test_gethostbyaddr(self, tmp_path):
        """Test socket.gethostbyaddr event."""
        config = {"allow_domains": ["example.com"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        assert engine.check_permission("socket.gethostbyaddr", ("example.com",))
        assert not engine.check_permission("socket.gethostbyaddr", ("evil.com",))


class TestIPParsing:
    """Tests for IP address parsing helpers."""

    def test_is_ip_address(self, tmp_path):
        """Test _is_ip_address helper."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        assert engine._is_ip_address("192.168.1.1")
        assert engine._is_ip_address("8.8.8.8")
        assert engine._is_ip_address("::1")
        assert engine._is_ip_address("2001:db8::1")
        assert not engine._is_ip_address("example.com")
        assert not engine._is_ip_address("localhost")

    def test_parse_ip_entry_ipv4(self, tmp_path):
        """Test parsing IPv4 entries."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        assert engine._parse_ip_entry("192.168.1.1") == ("192.168.1.1", None)
        assert engine._parse_ip_entry("192.168.1.1:443") == ("192.168.1.1", 443)
        assert engine._parse_ip_entry("10.0.0.0/8") == ("10.0.0.0/8", None)

    def test_parse_ip_entry_ipv6(self, tmp_path):
        """Test parsing IPv6 entries."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        assert engine._parse_ip_entry("::1") == ("::1", None)
        assert engine._parse_ip_entry("2001:db8::1") == ("2001:db8::1", None)
        assert engine._parse_ip_entry("[::1]:443") == ("::1", 443)
        assert engine._parse_ip_entry("[2001:db8::1]:80") == ("2001:db8::1", 80)


class TestDomainIPResolution:
    """Tests for domain → IP resolution caching."""

    def test_allowed_domain_dns_caches_ips(self, tmp_path):
        """Test that DNS lookup for allowed domain caches resolved IPs."""
        config = {"allow_domains": ["example.com"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Simulate DNS lookup - this should cache the IPs
        assert engine.check_permission(
            "socket.getaddrinfo", ("example.com", 443, 0, 1, 0)
        )

        # Verify IPs were cached
        assert len(engine._resolved_ips) > 0

    def test_cached_ip_allowed_on_connect(self, tmp_path):
        """Test that cached IPs are allowed for socket.connect."""
        config = {"allow_domains": ["example.com"], "allow_ips": []}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # First do DNS lookup to cache IPs
        engine.check_permission("socket.getaddrinfo", ("example.com", 443, 0, 1, 0))

        # Get one of the cached IPs
        cached_ip = next(iter(engine._resolved_ips))

        # Now socket.connect to that IP should be allowed
        assert engine.check_permission("socket.connect", (None, (cached_ip, 443)))

    def test_uncached_ip_blocked_on_connect(self, tmp_path):
        """Test that IPs not in cache are blocked."""
        config = {"allow_domains": ["example.com"], "allow_ips": []}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Don't do DNS lookup - IP won't be cached
        # Connect to arbitrary IP should be blocked
        assert not engine.check_permission(
            "socket.connect", (None, ("203.0.113.1", 443))
        )

    def test_pypi_domains_cache_ips(self, tmp_path):
        """Test that PyPI domains (in default allow_domains) cache their IPs."""
        # Use default config which includes PyPI domains
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        # DNS lookup for PyPI should cache IPs
        assert engine.check_permission("socket.getaddrinfo", ("pypi.org", 443, 0, 1, 0))

        # Verify IPs were cached
        assert len(engine._resolved_ips) > 0


class TestURLPermissions:
    """Tests for URL path allowlisting via urllib.Request event."""

    def test_url_allow_empty_blocks_all(self, tmp_path):
        """Test that empty allow_http_urls blocks all URLs (consistent behavior)."""
        config = {"allow_http_urls": []}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Empty allow_http_urls = block all URLs (consistent with all allow_* attrs)
        assert not engine.check_permission(
            "urllib.Request", ("https://example.com/any/path", None, {}, None)
        )

    def test_url_block_unmatched_path(self, tmp_path):
        """Test that URLs not matching allow_urls are blocked."""
        config = {"allow_http_urls": ["api.example.com/v1/*"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Unmatched path should be blocked
        assert not engine.check_permission(
            "urllib.Request", ("https://api.example.com/v2/users", None, {}, None)
        )

    def test_url_allow_matching_glob_pattern(self, tmp_path):
        """Test that URLs matching glob pattern in allow_urls are allowed."""
        config = {"allow_http_urls": ["api.example.com/v1/*"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Matching paths should be allowed
        assert engine.check_permission(
            "urllib.Request", ("https://api.example.com/v1/users", None, {}, None)
        )
        assert engine.check_permission(
            "urllib.Request", ("https://api.example.com/v1/orders/123", None, {}, None)
        )

    def test_url_scheme_optional_in_pattern(self, tmp_path):
        """Test that patterns without scheme match both http and https."""
        config = {"allow_http_urls": ["example.com/api/*"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Both http and https should match
        assert engine.check_permission(
            "urllib.Request", ("https://example.com/api/test", None, {}, None)
        )
        assert engine.check_permission(
            "urllib.Request", ("http://example.com/api/test", None, {}, None)
        )

    def test_url_scheme_explicit_in_pattern(self, tmp_path):
        """Test that pattern with explicit scheme only matches that scheme."""
        config = {"allow_http_urls": ["https://secure.example.com/*"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # https should match
        assert engine.check_permission(
            "urllib.Request", ("https://secure.example.com/data", None, {}, None)
        )
        # http should NOT match when pattern specifies https
        assert not engine.check_permission(
            "urllib.Request", ("http://secure.example.com/data", None, {}, None)
        )

    def test_url_subdomain_matching(self, tmp_path):
        """Test that subdomain matching works in URL patterns."""
        config = {"allow_http_urls": ["example.com/api/*"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Subdomain should match parent domain pattern
        assert engine.check_permission(
            "urllib.Request", ("https://api.example.com/api/v1", None, {}, None)
        )
        assert engine.check_permission(
            "urllib.Request", ("https://www.example.com/api/v1", None, {}, None)
        )

    def test_url_port_in_pattern(self, tmp_path):
        """Test that port in pattern is enforced."""
        config = {"allow_http_urls": ["api.example.com:8080/api/*"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Correct port should match
        assert engine.check_permission(
            "urllib.Request",
            ("https://api.example.com:8080/api/test", None, {}, None),
        )
        # Wrong port should NOT match
        assert not engine.check_permission(
            "urllib.Request",
            ("https://api.example.com:443/api/test", None, {}, None),
        )

    def test_url_exact_path_match(self, tmp_path):
        """Test exact path matching (no glob)."""
        config = {"allow_http_urls": ["example.com/health"]}
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Exact match
        assert engine.check_permission(
            "urllib.Request", ("https://example.com/health", None, {}, None)
        )
        # Not an exact match (extra path segment)
        assert not engine.check_permission(
            "urllib.Request", ("https://example.com/health/check", None, {}, None)
        )

    def test_url_multiple_patterns(self, tmp_path):
        """Test matching against multiple URL patterns."""
        config = {
            "allow_http_urls": [
                "api.example.com/v1/*",
                "cdn.example.com/assets/*",
                "example.com/health",
            ]
        }
        config_path = tmp_path / ".malwi-box.toml"
        config_path.write_text(toml.dumps(config))

        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Each pattern should match
        assert engine.check_permission(
            "urllib.Request", ("https://api.example.com/v1/users", None, {}, None)
        )
        assert engine.check_permission(
            "urllib.Request", ("https://cdn.example.com/assets/img.png", None, {}, None)
        )
        assert engine.check_permission(
            "urllib.Request", ("https://example.com/health", None, {}, None)
        )
        # None should match
        assert not engine.check_permission(
            "urllib.Request", ("https://other.example.com/data", None, {}, None)
        )

    def test_save_url_decision(self, tmp_path):
        """Test that URL decisions are saved to config."""
        config_path = tmp_path / ".malwi-box.toml"
        engine = BoxEngine(config_path=str(config_path), workdir=tmp_path)

        # Record a URL decision
        engine.record_decision(
            "urllib.Request",
            ("https://api.example.com/v1/users", None, {}, "GET"),
            allowed=True,
            details={"url": "https://api.example.com/v1/users", "method": "GET"},
        )
        engine.save_decisions()

        # Reload and verify
        saved_config = toml.loads(config_path.read_text())
        assert "allow_http_urls" in saved_config
        assert "api.example.com/v1/users" in saved_config["allow_http_urls"]


class TestURLPatternMatching:
    """Tests for the _url_matches_pattern helper method."""

    def test_pattern_matching_basic(self, tmp_path):
        """Test basic URL pattern matching."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        # Exact match
        assert engine._url_matches_pattern("https://example.com/api", "example.com/api")
        # Glob match
        assert engine._url_matches_pattern(
            "https://example.com/api/v1/users", "example.com/api/*"
        )

    def test_pattern_matching_root_path(self, tmp_path):
        """Test matching root path."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        assert engine._url_matches_pattern("https://example.com/", "example.com/")
        assert engine._url_matches_pattern("https://example.com", "example.com/")

    def test_pattern_matching_wildcard_domain(self, tmp_path):
        """Test that wildcard in domain part doesn't accidentally match."""
        engine = BoxEngine(config_path=tmp_path / ".malwi-box.toml", workdir=tmp_path)

        # Pattern *.example.com should NOT be treated as glob in domain
        # (subdomain matching is done differently)
        assert not engine._url_matches_pattern(
            "https://evil.com/example.com/path", "example.com/*"
        )
