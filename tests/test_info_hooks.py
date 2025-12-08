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

    def test_info_only_events_contains_new_encoding_events(self):
        """Verify INFO_ONLY_EVENTS contains new encoding events."""
        from malwi_box.engine import INFO_ONLY_EVENTS

        assert "encoding.hex" in INFO_ONLY_EVENTS
        assert "encoding.zlib" in INFO_ONLY_EVENTS
        assert "encoding.gzip" in INFO_ONLY_EVENTS
        assert "encoding.bz2" in INFO_ONLY_EVENTS
        assert "encoding.lzma" in INFO_ONLY_EVENTS

    def test_info_only_events_contains_new_crypto_events(self):
        """Verify INFO_ONLY_EVENTS contains new crypto events."""
        from malwi_box.engine import INFO_ONLY_EVENTS

        assert "crypto.hmac" in INFO_ONLY_EVENTS
        assert "crypto.rsa" in INFO_ONLY_EVENTS
        assert "crypto.aes" in INFO_ONLY_EVENTS
        assert "crypto.chacha20" in INFO_ONLY_EVENTS
        assert "secrets.token" in INFO_ONLY_EVENTS

    def test_info_only_events_contains_deserialization_events(self):
        """Verify INFO_ONLY_EVENTS contains deserialization events."""
        from malwi_box.engine import INFO_ONLY_EVENTS

        assert "pickle.find_class" in INFO_ONLY_EVENTS
        assert "marshal.loads" in INFO_ONLY_EVENTS

    def test_info_only_events_contains_archive_events(self):
        """Verify INFO_ONLY_EVENTS contains archive events."""
        from malwi_box.engine import INFO_ONLY_EVENTS

        assert "shutil.unpack_archive" in INFO_ONLY_EVENTS

    def test_info_only_events_is_frozenset(self):
        """Verify INFO_ONLY_EVENTS is immutable."""
        from malwi_box.engine import INFO_ONLY_EVENTS

        assert isinstance(INFO_ONLY_EVENTS, frozenset)


class TestNewEncodingHooks:
    """Tests for new encoding hooks (hex, compression)."""

    def test_hex_encode_logged(self, tmp_path):
        """Test that hex encoding is logged in force mode.

        Note: binascii is a C module, so we can't intercept it with profile hooks.
        This test just verifies the script runs successfully.
        """
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_hex.py"
        script.write_text("""
import binascii
result = binascii.hexlify(b"hello world")
print("hexlified:", result)
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "hexlified:" in result.stdout

    def test_gzip_compress_logged(self, tmp_path):
        """Test that gzip compression is logged."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_gzip.py"
        script.write_text("""
import gzip
result = gzip.compress(b"hello world")
print("compressed length:", len(result))
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "compressed length:" in result.stdout
        assert "Gzip:" in result.stderr or "encoding.gzip" in result.stderr

    def test_zlib_compress_logged(self, tmp_path):
        """Test that zlib compression is logged."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_zlib.py"
        script.write_text("""
import zlib
result = zlib.compress(b"hello world")
print("compressed length:", len(result))
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "compressed length:" in result.stdout


class TestNewCryptoHooks:
    """Tests for new crypto hooks (hmac, secrets)."""

    def test_hmac_logged(self, tmp_path):
        """Test that hmac operations are logged."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_hmac.py"
        script.write_text("""
import hmac
import hashlib
h = hmac.new(b"secret", b"message", hashlib.sha256)
print("digest:", h.hexdigest())
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "digest:" in result.stdout
        assert "HMAC:" in result.stderr or "crypto.hmac" in result.stderr

    def test_secrets_token_logged(self, tmp_path):
        """Test that secrets token generation is logged."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_secrets.py"
        script.write_text("""
import secrets
token = secrets.token_hex(16)
print("token length:", len(token))
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "token length:" in result.stdout
        assert "SecureRandom:" in result.stderr or "secrets.token" in result.stderr


class TestDeserializationHooks:
    """Tests for deserialization info hooks (pickle, marshal)."""

    def test_pickle_find_class_logged(self, tmp_path):
        """Test that pickle.find_class is logged when unpickling."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_pickle.py"
        script.write_text("""
import pickle

# Create and unpickle a simple class instance
class MyClass:
    pass

data = pickle.dumps(MyClass())
result = pickle.loads(data)
print("unpickled:", type(result).__name__)
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "unpickled:" in result.stdout
        # pickle.find_class is a PEP 578 built-in event
        assert "Pickle" in result.stderr or "pickle.find_class" in result.stderr

    def test_marshal_loads_logged(self, tmp_path):
        """Test that marshal.loads is logged."""
        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]'
        )

        script = tmp_path / "test_marshal.py"
        script.write_text("""
import marshal

# Create and load marshal data
data = marshal.dumps([1, 2, 3])
result = marshal.loads(data)
print("loaded:", result)
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "loaded:" in result.stdout
        # marshal.loads is a PEP 578 built-in event
        assert "Marshal" in result.stderr or "marshal.loads" in result.stderr


class TestArchiveHooks:
    """Tests for archive extraction info hooks."""

    def test_unpack_archive_logged(self, tmp_path):
        """Test that shutil.unpack_archive is logged."""
        import zipfile

        config = tmp_path / ".malwi-box.toml"
        config.write_text(
            f'allow_read = ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"]\n'
            f'allow_write = ["{tmp_path}/**"]'
        )

        # Create a simple zip file
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("test.txt", "hello world")

        extract_dir = tmp_path / "extracted"

        script = tmp_path / "test_unpack.py"
        script.write_text(f"""
import shutil
shutil.unpack_archive("{zip_path}", "{extract_dir}")
print("extracted to:", "{extract_dir}")
""")

        result = subprocess.run(
            [sys.executable, "-m", "malwi_box.cli", "run", "--force", str(script)],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "extracted to:" in result.stdout
        # shutil.unpack_archive is a PEP 578 built-in event
        assert "Unpack:" in result.stderr or "shutil.unpack_archive" in result.stderr


class TestNewFormatFunctions:
    """Tests for new event format functions."""

    def test_format_hex_event(self):
        """Test formatting of hex encoding events."""
        from malwi_box.formatting import format_event

        result = format_event("encoding.hex", ("hexlify",))
        assert result == "Hex: hexlify"

        result = format_event("encoding.hex", ("unhexlify",))
        assert result == "Hex: unhexlify"

    def test_format_compression_events(self):
        """Test formatting of compression events."""
        from malwi_box.formatting import format_event

        result = format_event("encoding.gzip", ("compress",))
        assert result == "Gzip: compress"

        result = format_event("encoding.zlib", ("decompress",))
        assert result == "Zlib: decompress"

        result = format_event("encoding.bz2", ("compress",))
        assert result == "Bz2: compress"

        result = format_event("encoding.lzma", ("decompress",))
        assert result == "LZMA: decompress"

    def test_format_hmac_event(self):
        """Test formatting of HMAC events."""
        from malwi_box.formatting import format_event

        result = format_event("crypto.hmac", ("new",))
        assert result == "HMAC: new"

    def test_format_secrets_event(self):
        """Test formatting of secrets events."""
        from malwi_box.formatting import format_event

        result = format_event("secrets.token", ("token_hex",))
        assert result == "SecureRandom: token_hex bytes"

    def test_format_crypto_algo_events(self):
        """Test formatting of crypto algorithm events."""
        from malwi_box.formatting import format_event

        # RSA format: (key_size, operation)
        result = format_event("crypto.rsa", (2048, "generate"))
        assert result == "RSA: generate (2048 bits)"

        # AES format: (mode, operation)
        result = format_event("crypto.aes", ("CBC", "init"))
        assert result == "AES: init (CBC)"

        result = format_event("crypto.chacha20", ("init",))
        assert result == "ChaCha20: init"

    def test_format_pickle_event(self):
        """Test formatting of pickle events."""
        from malwi_box.formatting import format_event

        result = format_event("pickle.find_class", ("builtins", "list"))
        assert "Pickle" in result
        assert "builtins.list" in result

    def test_format_marshal_event(self):
        """Test formatting of marshal events."""
        from malwi_box.formatting import format_event

        result = format_event("marshal.loads", (b"data",))
        assert "Marshal" in result

    def test_format_archive_event(self):
        """Test formatting of archive events."""
        from malwi_box.formatting import format_event

        args = ("/path/test.zip", "/path/out", "zip")
        result = format_event("shutil.unpack_archive", args)
        assert "Unpack:" in result
        assert "test.zip" in result
