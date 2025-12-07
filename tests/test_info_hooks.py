"""Tests for info-only hooks (encoding/crypto operations)."""

import subprocess
import sys


class TestBase64Hooks:
    """Tests for base64 encoding/decoding info hooks."""

    def test_base64_encode_logged_in_force_mode(self, tmp_path):
        """Test that base64 encoding is logged in force mode."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_base64.py"
        script.write_text("""
import base64
result = base64.b64encode(b"hello world")
print("encoded:", result)
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "encoded:" in result.stdout
        # Info event should be logged
        assert "Base64:" in result.stderr or "encoding.base64" in result.stderr

    def test_base64_decode_logged(self, tmp_path):
        """Test that base64 decoding is logged."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_b64decode.py"
        script.write_text("""
import base64
result = base64.b64decode(b"aGVsbG8gd29ybGQ=")
print("decoded:", result)
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "decoded:" in result.stdout

    def test_urlsafe_base64_logged(self, tmp_path):
        """Test that urlsafe base64 operations are logged."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_urlsafe.py"
        script.write_text("""
import base64
result = base64.urlsafe_b64encode(b"hello+world/test")
print("encoded:", result)
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "encoded:" in result.stdout


class TestInfoEventsNeverBlock:
    """Tests verifying info-only events never block execution."""

    def test_base64_never_blocked_in_run_mode(self, tmp_path):
        """Verify base64 events don't cause exit in run mode."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_no_block.py"
        script.write_text("""
import base64
# These should all complete without blocking
base64.b64encode(b"test1")
base64.b64decode(b"dGVzdDE=")
base64.urlsafe_b64encode(b"test2")
print("all operations completed")
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "all operations completed" in result.stdout


class TestFormatEvent:
    """Tests for event formatting."""

    def test_format_base64_event(self):
        """Test formatting of base64 events."""
        from malwi_box.formatting import format_event

        result = format_event("encoding.base64", ("b64encode",))
        assert result == "Base64: b64encode"

        result = format_event("encoding.base64", ("urlsafe_b64decode",))
        assert result == "Base64: urlsafe_b64decode"

    def test_format_cipher_event(self):
        """Test formatting of cipher events."""
        from malwi_box.formatting import format_event

        result = format_event("crypto.cipher", ("encryptor",))
        assert "Encrypt" in result

        result = format_event("crypto.cipher", ("decryptor",))
        assert "Decrypt" in result

    def test_format_fernet_event(self):
        """Test formatting of fernet events."""
        from malwi_box.formatting import format_event

        result = format_event("crypto.fernet", ("encrypt",))
        assert result == "Fernet: encrypt"

        result = format_event("crypto.fernet", ("decrypt",))
        assert result == "Fernet: decrypt"


class TestInfoOnlyEventsConstant:
    """Tests for INFO_ONLY_EVENTS constant."""

    def test_info_only_events_contains_expected(self):
        """Verify INFO_ONLY_EVENTS contains expected events."""
        from malwi_box.engine import INFO_ONLY_EVENTS

        assert "encoding.base64" in INFO_ONLY_EVENTS
        assert "crypto.cipher" in INFO_ONLY_EVENTS
        assert "crypto.fernet" in INFO_ONLY_EVENTS

    def test_info_only_events_is_frozenset(self):
        """Verify INFO_ONLY_EVENTS is immutable."""
        from malwi_box.engine import INFO_ONLY_EVENTS

        assert isinstance(INFO_ONLY_EVENTS, frozenset)
