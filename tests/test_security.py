"""Security tests for malwi-box sandbox protections.

These tests verify that sandboxed code cannot bypass the audit hook
by using dangerous operations like adding new hooks or setting tracers.
"""

import subprocess
import sys


def run_sandboxed_code(code: str) -> tuple[int, str, str]:
    """Run code in a subprocess with malwi-box hook installed.

    Returns (exit_code, stdout, stderr).
    """
    wrapper = f"""
from malwi_box import install_hook

def hook(event, args):
    pass

install_hook(hook)

{code}
"""
    result = subprocess.run(
        [sys.executable, "-c", wrapper],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


class TestBlockedOperations:
    """Test that dangerous operations are blocked in sandbox mode."""

    def test_block_sys_addaudithook(self):
        """Verify sys.addaudithook is blocked."""
        code = """
import sys
sys.addaudithook(lambda e, a: None)
print("FAIL: should not reach here")
"""
        exit_code, stdout, stderr = run_sandboxed_code(code)

        assert exit_code == 77, f"Expected exit code 77, got {exit_code}"
        assert "BLOCKED: sys.addaudithook" in stderr
        assert "FAIL" not in stdout

    def test_block_sys_setprofile(self):
        """Verify sys.setprofile is blocked."""
        code = """
import sys
sys.setprofile(lambda *a: None)
print("FAIL: should not reach here")
"""
        exit_code, stdout, stderr = run_sandboxed_code(code)

        assert exit_code == 77, f"Expected exit code 77, got {exit_code}"
        assert "BLOCKED: sys.setprofile" in stderr
        assert "FAIL" not in stdout

    def test_block_sys_settrace(self):
        """Verify sys.settrace is blocked."""
        code = """
import sys
sys.settrace(lambda *a: None)
print("FAIL: should not reach here")
"""
        exit_code, stdout, stderr = run_sandboxed_code(code)

        assert exit_code == 77, f"Expected exit code 77, got {exit_code}"
        assert "BLOCKED: sys.settrace" in stderr
        assert "FAIL" not in stdout

    def test_normal_code_runs_fine(self):
        """Verify that normal code without blocked operations runs successfully."""
        code = """
print("Hello from sandbox")
x = 1 + 2
print(f"Result: {x}")
"""
        exit_code, stdout, stderr = run_sandboxed_code(code)

        assert exit_code == 0, (
            f"Expected exit code 0, got {exit_code}. stderr: {stderr}"
        )
        assert "Hello from sandbox" in stdout
        assert "Result: 3" in stdout


class TestSecurityMessage:
    """Test that security violation messages are informative."""

    def test_blocked_message_includes_event_name(self):
        """Verify the blocked message includes which event was blocked."""
        code = """
import sys
sys.setprofile(lambda *a: None)
"""
        _, _, stderr = run_sandboxed_code(code)

        assert "[malwi-box]" in stderr
        assert "BLOCKED" in stderr
        assert "sys.setprofile" in stderr
        assert "Terminating" in stderr
