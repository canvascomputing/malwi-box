"""BoxEngine - Permission engine for Python audit event enforcement."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# PyPI-related hosts that are allowed when allow_pypi_requests is True
PYPI_HOSTS = frozenset({
    "pypi.org",
    "www.pypi.org",
    "files.pythonhosted.org",
    "upload.pypi.org",
    "test.pypi.org",
})


class BoxEngine:
    """Permission engine for audit event enforcement.

    Reads configuration from a JSON file and enforces fine-grained
    permissions for file access, environment variables, subprocess
    execution, and network requests.
    """

    def __init__(self, config_path: str = ".malwi-box", workdir: str | None = None):
        """Initialize the BoxEngine.

        Args:
            config_path: Path to the JSON configuration file.
            workdir: Working directory for relative paths. Defaults to cwd.
        """
        self.config_path = Path(config_path)
        self.workdir = Path(workdir) if workdir else Path.cwd()
        self.config = self._load_config()
        self._decisions: list[dict[str, Any]] = []

    def _default_config(self) -> dict[str, Any]:
        """Return default configuration with workdir permissions."""
        workdir_str = str(self.workdir)

        # Get Python's standard library paths
        stdlib_paths = []
        try:
            import sysconfig
            stdlib = sysconfig.get_path("stdlib")
            if stdlib:
                stdlib_paths.append(stdlib)
            purelib = sysconfig.get_path("purelib")
            if purelib:
                stdlib_paths.append(purelib)
            platlib = sysconfig.get_path("platlib")
            if platlib:
                stdlib_paths.append(platlib)
        except Exception:
            pass

        # Also include common system paths for reading
        read_paths = [workdir_str] + stdlib_paths

        return {
            "allow_file_reads": [],
            "allow_file_writes": [],
            "allow_file_changes": [],
            "allow_dir_reads": read_paths,
            "allow_dir_writes": [workdir_str],
            "allow_dir_changes": [workdir_str],
            "allow_env_var_reads": [],
            "allow_env_var_writes": [],
            "allow_pypi_requests": True,
            "allow_hosts": [],
            "allow_system_commands": [],
        }

    def _load_config(self) -> dict[str, Any]:
        """Load config from JSON file or return defaults."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    config = json.load(f)
                # Merge with defaults for any missing keys
                defaults = self._default_config()
                for key, value in defaults.items():
                    if key not in config:
                        config[key] = value
                return config
            except (json.JSONDecodeError, OSError) as e:
                sys.stderr.write(f"[malwi-box] Warning: Could not load config: {e}\n")
                return self._default_config()
        return self._default_config()

    def _resolve_path(self, path: str | Path) -> Path:
        """Resolve a path to an absolute path."""
        p = Path(path)
        if not p.is_absolute():
            p = self.workdir / p
        return p.resolve()

    def _normalize_entry(self, entry: str | dict) -> tuple[str, str | None]:
        """Normalize a config entry to (path, hash) tuple."""
        if isinstance(entry, dict):
            return entry.get("path", ""), entry.get("hash")
        return entry, None

    def _verify_file_hash(self, path: Path, expected_hash: str) -> bool:
        """Verify file matches expected SHA256 hash.

        Args:
            path: Path to the file to verify.
            expected_hash: Expected hash in format "sha256:hexdigest".

        Returns:
            True if hash matches, False otherwise.
        """
        if not expected_hash.startswith("sha256:"):
            return False
        if not path.exists():
            return False
        try:
            expected = expected_hash[7:]
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            return actual == expected
        except OSError:
            return False

    def _check_path_in_list(
        self, path: Path, entries: list, check_hash: bool = False
    ) -> bool:
        """Check if a path matches any entry in the list.

        Args:
            path: Resolved absolute path to check.
            entries: List of path strings or dicts with path/hash.
            check_hash: If True, verify hash for entries that have one.

        Returns:
            True if path is allowed.
        """
        for entry in entries:
            entry_path, entry_hash = self._normalize_entry(entry)
            resolved_entry = self._resolve_path(entry_path)

            if path == resolved_entry:
                if check_hash and entry_hash:
                    return self._verify_file_hash(path, entry_hash)
                return True
        return False

    def _check_path_in_dir_list(self, path: Path, dirs: list) -> bool:
        """Check if a path is within any directory in the list.

        Args:
            path: Resolved absolute path to check.
            dirs: List of directory paths.

        Returns:
            True if path is within any allowed directory.
        """
        for dir_entry in dirs:
            dir_path = self._resolve_path(dir_entry)
            try:
                path.relative_to(dir_path)
                return True
            except ValueError:
                continue
        return False

    def _check_read_permission(self, path: Path) -> bool:
        """Check if reading a file is permitted."""
        # Check specific file permissions
        if self._check_path_in_list(path, self.config.get("allow_file_reads", [])):
            return True
        # Check directory permissions
        if self._check_path_in_dir_list(path, self.config.get("allow_dir_reads", [])):
            return True
        return False

    def _check_write_permission(self, path: Path, is_new_file: bool) -> bool:
        """Check if writing to a file is permitted.

        Args:
            path: Resolved absolute path.
            is_new_file: True if file doesn't exist (creation).
        """
        if is_new_file:
            # Creating new file - check writes
            if self._check_path_in_list(path, self.config.get("allow_file_writes", [])):
                return True
            if self._check_path_in_dir_list(
                path, self.config.get("allow_dir_writes", [])
            ):
                return True
        else:
            # Modifying existing file - check changes (with hash verification)
            if self._check_path_in_list(
                path, self.config.get("allow_file_changes", []), check_hash=True
            ):
                return True
            if self._check_path_in_dir_list(
                path, self.config.get("allow_dir_changes", [])
            ):
                return True
        return False

    def _check_file_access(self, args: tuple) -> bool:
        """Check file access permission for 'open' event."""
        if not args:
            return True

        path_arg = args[0]
        mode = args[1] if len(args) > 1 else "r"

        # Handle non-string paths (file descriptors, etc.)
        if not isinstance(path_arg, (str, Path, bytes)):
            return True

        if isinstance(path_arg, bytes):
            path_arg = path_arg.decode("utf-8", errors="replace")

        resolved = self._resolve_path(path_arg)

        # Determine if this is a write operation
        # w=write, a=append, x=exclusive create, +=read/write
        # Note: 'b' is binary mode (not write), 'r' is read
        is_write = any(c in str(mode) for c in "wax+")

        if is_write:
            is_new_file = not resolved.exists()
            return self._check_write_permission(resolved, is_new_file)
        else:
            return self._check_read_permission(resolved)

    def _check_env_write(self, args: tuple) -> bool:
        """Check environment variable write permission."""
        if not args:
            return True

        key = args[0]
        allowed = self.config.get("allow_env_var_writes", [])
        return key in allowed

    def _check_system_command(self, event: str, args: tuple) -> bool:
        """Check system command execution permission."""
        if not args:
            return True

        # Build command string based on event type
        if event == "subprocess.Popen":
            executable = args[0] if args else ""
            cmd_args = args[1] if len(args) > 1 else []
            if executable and cmd_args:
                command = " ".join([str(executable)] + [str(a) for a in cmd_args])
            elif executable:
                command = str(executable)
            else:
                return True
        elif event == "os.system":
            command = str(args[0]) if args else ""
        else:
            return True

        # Check against allowed patterns using glob matching
        for pattern in self.config.get("allow_system_commands", []):
            if fnmatch.fnmatch(command, pattern):
                return True
        return False

    def _check_network(self, args: tuple) -> bool:
        """Check network connection permission."""
        if len(args) < 2:
            return True

        address = args[1]
        if not isinstance(address, tuple) or len(address) < 1:
            return True

        host = str(address[0])

        # Check PyPI requests
        if self.config.get("allow_pypi_requests", False):
            if host in PYPI_HOSTS:
                return True

        # Check allowed hosts list
        allowed_hosts = self.config.get("allow_hosts", [])
        if host in allowed_hosts:
            return True

        return False

    def check_permission(self, event: str, args: tuple) -> bool:
        """Check if an audit event is permitted.

        Args:
            event: The audit event name.
            args: The event arguments.

        Returns:
            True if the event is allowed, False otherwise.
        """
        # Map events to handlers
        if event == "open":
            return self._check_file_access(args)
        elif event in ("os.putenv", "os.unsetenv"):
            return self._check_env_write(args)
        elif event in ("os.getenv", "os.environ.get"):
            return self._check_env_read(args)
        elif event in ("subprocess.Popen", "os.system"):
            return self._check_system_command(event, args)
        elif event == "socket.connect":
            return self._check_network(args)

        # Events not explicitly handled are allowed
        return True

    def _violation(self, reason: str) -> None:
        """Handle a permission violation by terminating immediately."""
        sys.stderr.write(f"[malwi-box] VIOLATION: {reason} - Terminating\n")
        sys.stderr.flush()
        os._exit(78)  # Exit code 78 for permission violation

    def record_decision(
        self, event: str, args: tuple, allowed: bool, details: dict | None = None
    ) -> None:
        """Record a user decision during review mode.

        Args:
            event: The audit event name.
            args: The event arguments.
            allowed: Whether the user allowed this event.
            details: Optional additional details about the decision.
        """
        decision = {
            "event": event,
            "args": repr(args),
            "allowed": allowed,
            "details": details or {},
        }
        self._decisions.append(decision)

    def save_decisions(self) -> None:
        """Merge recorded decisions into config file."""
        if not self._decisions:
            return

        # Load existing config or start fresh
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    config = json.load(f)
            except (json.JSONDecodeError, OSError):
                config = self._default_config()
        else:
            config = self._default_config()

        # Process decisions and update config
        for decision in self._decisions:
            if not decision.get("allowed"):
                continue

            event = decision["event"]
            details = decision.get("details", {})

            if event == "open":
                path = details.get("path")
                mode = details.get("mode", "r")
                if path:
                    if any(c in mode for c in "wax"):
                        if path not in config.get("allow_file_writes", []):
                            config.setdefault("allow_file_writes", []).append(path)
                    else:
                        if path not in config.get("allow_file_reads", []):
                            config.setdefault("allow_file_reads", []).append(path)

            elif event in ("subprocess.Popen", "os.system"):
                cmd = details.get("command")
                if cmd and cmd not in config.get("allow_system_commands", []):
                    config.setdefault("allow_system_commands", []).append(cmd)

            elif event in ("os.putenv", "os.unsetenv"):
                key = details.get("key")
                if key and key not in config.get("allow_env_var_writes", []):
                    config.setdefault("allow_env_var_writes", []).append(key)

            elif event == "socket.connect":
                host = details.get("host")
                if host and host not in config.get("allow_hosts", []):
                    config.setdefault("allow_hosts", []).append(host)

        # Write updated config
        try:
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2)
        except OSError as e:
            sys.stderr.write(f"[malwi-box] Warning: Could not save config: {e}\n")

    def _check_env_read(self, args: tuple) -> bool:
        """Check if reading an env var is allowed.

        The args tuple contains the function object being called.
        We can't easily get the key being accessed, so we allow by default
        unless the user has restricted env var reads.
        """
        allowed = self.config.get("allow_env_var_reads", [])
        # If no restrictions configured, allow all
        if not allowed:
            return True
        # If restrictions are configured, block by default
        # (The actual key is not easily accessible from the profile hook)
        return False

    def create_hook(self, enforce: bool = True) -> callable:
        """Return a hook function that uses this engine.

        Args:
            enforce: If True, terminate on violation. If False, just log.

        Returns:
            A callable suitable for use with install_hook().
        """

        def hook(event: str, args: tuple) -> None:
            if not self.check_permission(event, args):
                if enforce:
                    self._violation(f"{event}:{args}")
                else:
                    sys.stderr.write(
                        f"[malwi-box] WOULD BLOCK: {event}: {args}\n"
                    )

        return hook
