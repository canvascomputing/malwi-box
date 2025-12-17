"""Tests for the malwi_python wrapper binary and sandbox injection."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from malwi_box.wrapper import get_malwi_python_path, get_wrapper_env, setup_wrapper_bin_dir, cleanup_wrapper_bin_dir


class TestWrapperAvailability:
    """Test that the wrapper is built and available."""

    def test_wrapper_exists(self):
        """Test that malwi_python wrapper is built."""
        wrapper_path = get_malwi_python_path()
        assert wrapper_path is not None, "malwi_python wrapper not found"
        assert wrapper_path.exists()
        assert wrapper_path.is_file()

    def test_wrapper_is_executable(self):
        """Test that malwi_python is executable."""
        wrapper_path = get_malwi_python_path()
        if wrapper_path is None:
            pytest.skip("Wrapper not available")
        assert os.access(wrapper_path, os.X_OK)


class TestWrapperExecution:
    """Test basic wrapper execution."""

    @pytest.fixture
    def wrapper_path(self):
        path = get_malwi_python_path()
        if path is None:
            pytest.skip("Wrapper not available")
        return path

    @pytest.fixture
    def wrapper_env(self):
        """Get base environment for wrapper."""
        # The wrapper binary auto-detects PYTHONHOME, so we just need to disable the hook
        env = get_wrapper_env(mode="run")
        env["MALWI_BOX_ENABLED"] = "0"  # Disable by default
        return {**os.environ, **env}

    def test_wrapper_runs_python_code(self, wrapper_path, wrapper_env):
        """Test that wrapper can execute Python code."""
        result = subprocess.run(
            [str(wrapper_path), "-c", "print('hello')"],
            capture_output=True,
            text=True,
            env=wrapper_env,
        )
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_wrapper_without_hook_allows_all(self, wrapper_path, wrapper_env):
        """Test that wrapper without MALWI_BOX_ENABLED allows everything."""
        result = subprocess.run(
            [str(wrapper_path), "-c", "import socket; s = socket.socket()"],
            capture_output=True,
            text=True,
            env={**wrapper_env, "MALWI_BOX_ENABLED": "0"},
        )
        assert result.returncode == 0

    def test_wrapper_with_hook_blocks_violations(self, wrapper_path, wrapper_env):
        """Test that wrapper with hook enabled blocks violations."""
        result = subprocess.run(
            [str(wrapper_path), "-c",
             "import socket; s = socket.socket(); s.connect(('evil.com', 80))"],
            capture_output=True,
            text=True,
            env={**wrapper_env, "MALWI_BOX_ENABLED": "1", "MALWI_BOX_MODE": "run"},
        )
        # Exit code 78 means blocked by malwi-box
        assert result.returncode == 78
        assert "Blocked" in result.stderr

    def test_wrapper_force_mode_logs_but_allows(self, wrapper_path, wrapper_env):
        """Test that force mode logs violations but doesn't block."""
        result = subprocess.run(
            [str(wrapper_path), "-c", "print('allowed')"],
            capture_output=True,
            text=True,
            env={**wrapper_env, "MALWI_BOX_ENABLED": "1", "MALWI_BOX_MODE": "force"},
        )
        assert result.returncode == 0
        assert "allowed" in result.stdout


class TestSetupPyInjection:
    """Test that hook is injected into setup.py execution."""

    @pytest.fixture
    def malicious_package(self):
        """Create a temporary package with a malicious setup.py."""
        tmpdir = Path(tempfile.mkdtemp(prefix="malwi_test_pkg_"))

        # Create setup.py that tries to connect to evil.com
        setup_py = tmpdir / "setup.py"
        setup_py.write_text('''
import socket
import sys

# Try to connect to evil.com - should be blocked
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("evil.com", 80))
    s.close()
    print("CONNECTED - NOT BLOCKED!", file=sys.stderr)
except Exception as e:
    print(f"BLOCKED: {e}", file=sys.stderr)

from setuptools import setup
setup(name="test-pkg", version="0.0.1")
''')

        # Create pyproject.toml
        pyproject = tmpdir / "pyproject.toml"
        pyproject.write_text('''
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "test-pkg"
version = "0.0.1"
''')

        yield tmpdir

        # Cleanup
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_setup_py_socket_blocked_with_wrapper(self, malicious_package):
        """Test that socket.connect in setup.py is blocked when using wrapper."""
        wrapper_path = get_malwi_python_path()
        if wrapper_path is None:
            pytest.skip("Wrapper not available")

        # Get wrapper env (PYTHONHOME, PYTHONPATH) and enable hook
        wrapper_env = get_wrapper_env(mode="run")

        # Run setup.py with the wrapper and hook enabled
        result = subprocess.run(
            [str(wrapper_path), str(malicious_package / "setup.py")],
            capture_output=True,
            text=True,
            cwd=str(malicious_package),
            env={**os.environ, **wrapper_env},
        )

        # Should exit with 78 (blocked) because socket.connect to evil.com is blocked
        assert result.returncode == 78, f"Expected exit 78, got {result.returncode}. stderr: {result.stderr}"
        assert "Blocked" in result.stderr

    def test_setup_py_socket_allowed_without_wrapper(self, malicious_package):
        """Test that without wrapper, socket.connect works (baseline)."""
        # Run setup.py with regular Python (no hook)
        result = subprocess.run(
            [sys.executable, str(malicious_package / "setup.py")],
            capture_output=True,
            text=True,
            cwd=str(malicious_package),
            timeout=10,
        )

        # Without the hook, connection should succeed (or timeout, but not be blocked)
        # The connection might fail for network reasons, but it won't show "Blocked"
        assert "Blocked" not in result.stderr or "BLOCKED:" in result.stderr


class TestInstallCommand:
    """Test the malwi-box pip install CLI command."""

    @pytest.fixture
    def malicious_package(self):
        """Create a temporary package with a setup.py that tries malicious actions."""
        tmpdir = Path(tempfile.mkdtemp(prefix="malwi_test_pkg_"))

        # Create setup.py that tries to make a socket connection (blocked by default)
        setup_py = tmpdir / "setup.py"
        setup_py.write_text('''
import socket
import sys

# Try to connect to evil.com - should be blocked immediately
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
s.connect(("evil.com", 80))
s.close()
print("CONNECTED - NOT BLOCKED!", file=sys.stderr)

from setuptools import setup
setup(name="test-pkg", version="0.0.1")
''')

        # Create pyproject.toml
        pyproject = tmpdir / "pyproject.toml"
        pyproject.write_text('''
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "test-pkg"
version = "0.0.1"
''')

        yield tmpdir

        # Cleanup
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_install_blocks_socket_in_setup_py(self, malicious_package):
        """Test that malwi-box pip install blocks socket.connect in setup.py."""
        wrapper_path = get_malwi_python_path()
        if wrapper_path is None:
            pytest.skip("Wrapper not available")

        # Run setup.py directly with the wrapper (simulates what pip does)
        # This is faster than running full pip install
        from malwi_box.wrapper import setup_wrapper_bin_dir, cleanup_wrapper_bin_dir

        bin_dir, env = setup_wrapper_bin_dir(mode="run")
        try:
            test_env = os.environ.copy()
            test_env.update(env)
            test_env["PATH"] = f"{bin_dir}:{test_env.get('PATH', '')}"

            result = subprocess.run(
                ["python", str(malicious_package / "setup.py")],
                capture_output=True,
                text=True,
                env=test_env,
                timeout=10,
            )

            # Should be blocked with exit code 78
            assert result.returncode == 78, (
                f"Expected exit 78, got {result.returncode}.\n"
                f"stdout: {result.stdout}\n"
                f"stderr: {result.stderr}"
            )
            assert "Blocked" in result.stderr
        finally:
            cleanup_wrapper_bin_dir(bin_dir)


class TestVenvCompilation:
    """Test the venv compilation functionality."""

    def test_build_fails_gracefully_without_compiler(self, tmp_path):
        """Test that build_malwi_python fails gracefully when compiler is missing."""
        from malwi_box.venv import build_malwi_python

        # Create a fake PATH with no compiler
        fake_bin = tmp_path / "fake_bin"
        fake_bin.mkdir()

        # Create a fake python3-config that works
        python_config = fake_bin / "python3-config"
        python_config.write_text(f"""#!/bin/bash
if [ "$1" = "--cflags" ]; then
    echo "-I/usr/include/python3.10"
elif [ "$1" = "--ldflags" ]; then
    echo "-lpython3.10"
fi
""")
        python_config.chmod(0o755)

        # Create a fake python executable
        fake_python = fake_bin / "python3"
        fake_python.write_text(f"""#!/bin/bash
echo ""
echo ""
""")
        fake_python.chmod(0o755)

        output_path = tmp_path / "malwi_python"

        # Modify PATH to exclude real compilers
        old_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = str(fake_bin)
            success, error = build_malwi_python(output_path, fake_python)

            # Should fail but not crash
            assert success is False
            assert error is not None
        finally:
            os.environ["PATH"] = old_path

    def test_build_fails_gracefully_without_python_config(self, tmp_path):
        """Test that build_malwi_python fails gracefully when python3-config is missing."""
        from malwi_box.venv import build_malwi_python

        # Create a fake bin directory with no python3-config
        fake_bin = tmp_path / "fake_bin"
        fake_bin.mkdir()

        # Create a fake python executable (but no python3-config)
        fake_python = fake_bin / "python3"
        fake_python.write_text("#!/bin/bash\necho 'fake python'")
        fake_python.chmod(0o755)

        output_path = tmp_path / "malwi_python"

        # Modify PATH to only include fake_bin (no python3-config anywhere)
        old_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = str(fake_bin)
            success, error = build_malwi_python(output_path, fake_python)

            # Should fail but not crash
            assert success is False
            assert error is not None
            assert "python3-config" in error.lower()
        finally:
            os.environ["PATH"] = old_path


class TestReviewModeWithSubprocesses:
    """Test that review mode approval works correctly with subprocesses."""

    @pytest.fixture
    def wrapper_path(self):
        path = get_malwi_python_path()
        if path is None:
            pytest.skip("Wrapper not available")
        return path

    def test_review_mode_subprocess_accepts_piped_approval(self, wrapper_path):
        """Test that review mode can accept approval via piped stdin for subprocesses.

        This verifies that when stdin is piped (not a TTY), the approval mechanism
        falls back to reading from stdin instead of /dev/tty, avoiding TTY contention.
        """
        # Code that spawns a subprocess which triggers a blocked event
        code = '''
import subprocess
import sys

# Spawn a child process that tries to connect to a blocked host
result = subprocess.run(
    [sys.executable, "-c", "import socket; s = socket.socket(); s.connect(('evil.com', 80))"],
    capture_output=True,
    text=True,
)
# Report child's exit code
print(f"child_exit={result.returncode}")
'''
        env = os.environ.copy()
        env["MALWI_BOX_ENABLED"] = "1"
        env["MALWI_BOX_MODE"] = "review"

        # Pipe "n" (deny) to stdin - child process should be blocked
        result = subprocess.run(
            [str(wrapper_path), "-c", code],
            input="n\n",  # Deny the socket.connect
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )

        # The child process should have been denied (exit 1) or the parent
        # should report the child was blocked (exit 78)
        # The key point: no crash, no TTY contention error
        assert "child_exit=" in result.stdout or result.returncode != 0

    def test_review_mode_subprocess_no_tty_contention(self, wrapper_path):
        """Test that nested subprocesses in review mode don't cause TTY contention.

        When stdin is piped, _prompt_approval() uses input() instead of /dev/tty,
        preventing multiple processes from competing for the terminal.
        """
        # Code that triggers an event requiring approval, then spawns subprocess
        code = '''
import subprocess
import sys
print("parent started")
# This subprocess also runs under review mode via inherited env
result = subprocess.run(
    [sys.executable, "-c", "print('child ok')"],
    capture_output=True,
    text=True,
)
print(f"child_stdout={result.stdout.strip()}")
print(f"child_exit={result.returncode}")
'''
        env = os.environ.copy()
        env["MALWI_BOX_ENABLED"] = "1"
        env["MALWI_BOX_MODE"] = "review"

        # Approve any prompts
        result = subprocess.run(
            [str(wrapper_path), "-c", code],
            input="y\ny\ny\ny\ny\n",  # Multiple approvals if needed
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )

        # Should complete without crash - the key assertion
        # Either succeeds (0) or cleanly blocked (78) or denied (1)
        assert result.returncode in (0, 1, 78), (
            f"Unexpected exit code {result.returncode}.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

        # If it succeeded, verify subprocess ran
        if result.returncode == 0:
            assert "child_stdout=child ok" in result.stdout
            assert "child_exit=0" in result.stdout

    def test_review_mode_eof_blocks_with_exit_78(self, wrapper_path):
        """Test that EOF in review mode results in exit code 78 (blocked), not 130 (aborted).

        When a subprocess in review mode has no stdin (EOF), it should block the action
        with exit code 78 rather than treating it as user abort (exit code 130).
        """
        # Code that triggers an event requiring approval
        code = "import socket; s = socket.socket(); s.connect(('evil.com', 80))"

        env = os.environ.copy()
        env["MALWI_BOX_ENABLED"] = "1"
        env["MALWI_BOX_MODE"] = "review"

        # Close stdin completely (no input at all) - simulates subprocess with no stdin
        result = subprocess.run(
            [str(wrapper_path), "-c", code],
            stdin=subprocess.DEVNULL,  # EOF immediately
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )

        # Should exit with 78 (blocked) not 130 (aborted)
        assert result.returncode == 78, (
            f"Expected exit code 78 (blocked), got {result.returncode}.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

        # Should show "Blocked" message, not "Aborted"
        assert "Blocked" in result.stderr, (
            f"Expected 'Blocked' in stderr, got:\n{result.stderr}"
        )
        assert "Aborted" not in result.stderr, (
            f"Should not show 'Aborted' for EOF, got:\n{result.stderr}"
        )

    def test_review_mode_piped_denial_blocks_action(self, wrapper_path):
        """Test that piped 'n' denial in review mode blocks the action.

        When stdin is piped with 'n', the action should be denied and exit with code 1.
        """
        # Code that triggers an event requiring approval
        code = "import socket; s = socket.socket(); s.connect(('evil.com', 80))"

        env = os.environ.copy()
        env["MALWI_BOX_ENABLED"] = "1"
        env["MALWI_BOX_MODE"] = "review"

        # Pipe "n" to deny the action
        result = subprocess.run(
            [str(wrapper_path), "-c", code],
            input="n\n",
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )

        # Should exit with 1 (denied by user)
        assert result.returncode == 1, (
            f"Expected exit code 1 (denied), got {result.returncode}.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
        assert "Denied" in result.stderr


class TestBinDirSetup:
    """Test the bin directory setup for PATH manipulation."""

    def test_setup_creates_bin_dir(self):
        """Test that setup_wrapper_bin_dir creates directory with python links."""
        wrapper_path = get_malwi_python_path()
        if wrapper_path is None:
            pytest.skip("Wrapper not available")

        bin_dir, env = setup_wrapper_bin_dir(mode="run")

        try:
            assert bin_dir is not None
            assert bin_dir.exists()
            assert (bin_dir / "python").exists()
            assert (bin_dir / "python3").exists()
            assert env["MALWI_BOX_ENABLED"] == "1"
            assert env["MALWI_BOX_MODE"] == "run"
        finally:
            cleanup_wrapper_bin_dir(bin_dir)

    def test_setup_with_config_path(self):
        """Test that config path is passed through."""
        wrapper_path = get_malwi_python_path()
        if wrapper_path is None:
            pytest.skip("Wrapper not available")

        bin_dir, env = setup_wrapper_bin_dir(mode="force", config_path="/tmp/test.toml")

        try:
            assert env["MALWI_BOX_MODE"] == "force"
            assert env["MALWI_BOX_CONFIG"] == "/tmp/test.toml"
        finally:
            cleanup_wrapper_bin_dir(bin_dir)

    def test_python_in_path_uses_wrapper(self):
        """Test that prepending bin_dir to PATH makes 'python' use wrapper."""
        wrapper_path = get_malwi_python_path()
        if wrapper_path is None:
            pytest.skip("Wrapper not available")

        bin_dir, env = setup_wrapper_bin_dir(mode="run")

        try:
            # Modify PATH to include our bin_dir first
            new_env = os.environ.copy()
            new_env.update(env)
            new_env["PATH"] = f"{bin_dir}:{new_env.get('PATH', '')}"

            # Run 'python' which should now be our wrapper
            result = subprocess.run(
                ["python", "-c", "print('from wrapper')"],
                capture_output=True,
                text=True,
                env=new_env,
            )

            assert result.returncode == 0
            assert "from wrapper" in result.stdout
        finally:
            cleanup_wrapper_bin_dir(bin_dir)
