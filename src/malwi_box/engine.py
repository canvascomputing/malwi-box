"""BoxEngine - Permission engine for Python audit event enforcement."""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# PyPI-related domains for default allow_domains
PYPI_DOMAINS = [
    "pypi.org",
    "files.pythonhosted.org",
]

# Events that can execute native binaries or load shared libraries
EXEC_EVENTS = frozenset({
    "subprocess.Popen",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "ctypes.dlopen",
})

# Events that run shell commands (checked against allow_shell_commands)
SHELL_EVENTS = frozenset({"subprocess.Popen", "os.system"})


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
        self._resolved_ips: set[str] = set()  # IPs resolved from allowed domains
        self._in_resolution = False  # Guard against recursive DNS resolution

    def _default_config(self) -> dict[str, Any]:
        """Return default configuration with workdir permissions."""
        return {
            "allow_read": [
                "$PWD",
                "$PYTHON_STDLIB",
                "$PYTHON_SITE_PACKAGES",
                "$PYTHON_PLATLIB",
            ],
            "allow_create": ["$PWD"],
            "allow_modify": ["$PWD"],
            "allow_delete": [],  # Conservative default - no delete allowed
            "allow_env_var_reads": [],
            "allow_env_var_writes": [],
            "allow_domains": PYPI_DOMAINS.copy(),
            "allow_executables": [],  # Block all by default, use ["*"] to allow all
            "allow_shell_commands": [],  # Block all by default, use ["*"] to allow all
            "allow_ips": [],  # CIDR notation supported, e.g. ["10.0.0.0/8", "192.168.1.100"]
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

    def _expand_path_variables(self, path: str) -> str:
        """Expand variables in a path string.

        Supports:
          $PWD, $HOME, $TMPDIR
          $PYTHON_STDLIB, $PYTHON_SITE_PACKAGES, $PYTHON_PLATLIB, $PYTHON_PREFIX
          $ENV{VAR_NAME}
        """
        if "$" not in path:
            return path

        import re
        import sysconfig
        import tempfile

        variables = {
            "$PWD": str(self.workdir),
            "$HOME": os.path.expanduser("~"),
            "$TMPDIR": tempfile.gettempdir(),
            "$PYTHON_STDLIB": sysconfig.get_path("stdlib") or "",
            "$PYTHON_SITE_PACKAGES": sysconfig.get_path("purelib") or "",
            "$PYTHON_PLATLIB": sysconfig.get_path("platlib") or "",
            "$PYTHON_PREFIX": sys.prefix,
        }

        result = path
        for var, value in variables.items():
            if var in result:
                result = result.replace(var, value)

        # Handle $ENV{VAR_NAME} pattern
        def env_replace(match: re.Match) -> str:
            var_name = match.group(1)
            return os.environ.get(var_name, "")

        result = re.sub(r"\$ENV\{([^}]+)\}", env_replace, result)

        return result

    def _path_to_variable(self, path: str) -> str:
        """Convert an absolute path to a variable if possible."""
        import sysconfig
        import tempfile

        # Order matters - more specific first
        mappings = [
            (sysconfig.get_path("purelib"), "$PYTHON_SITE_PACKAGES"),
            (sysconfig.get_path("platlib"), "$PYTHON_PLATLIB"),
            (sysconfig.get_path("stdlib"), "$PYTHON_STDLIB"),
            (sys.prefix, "$PYTHON_PREFIX"),
            (tempfile.gettempdir(), "$TMPDIR"),
            (str(self.workdir), "$PWD"),
            (os.path.expanduser("~"), "$HOME"),
        ]

        for prefix, var in mappings:
            if prefix and path.startswith(prefix):
                return path.replace(prefix, var, 1)

        return path

    def _resolve_path(self, path: str | Path) -> Path:
        """Resolve a path to an absolute path, expanding variables."""
        if isinstance(path, str):
            path = self._expand_path_variables(path)
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

    def _compute_file_hash(self, path: Path) -> str | None:
        """Compute SHA256 hash of a file.

        Returns hash in format "sha256:<hexdigest>" or None if file can't be read.
        """
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            return f"sha256:{digest}"
        except OSError:
            return None

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
        path_str = str(path)
        for entry in entries:
            entry_path, entry_hash = self._normalize_entry(entry)

            # Handle glob patterns (e.g., "*", "/usr/bin/*", "$PWD/.venv/bin/*")
            if "*" in entry_path or "?" in entry_path:
                expanded = self._expand_path_variables(entry_path)
                if fnmatch.fnmatch(path_str, expanded):
                    # Glob matches don't support hash verification
                    return True
                continue

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
            dirs: List of directory paths (strings or dicts with 'path' key).

        Returns:
            True if path is within any allowed directory (not equal to).
        """
        for dir_entry in dirs:
            entry_path, _ = self._normalize_entry(dir_entry)
            dir_path = self._resolve_path(entry_path)
            try:
                rel = path.relative_to(dir_path)
                # Only allow if path is INSIDE the directory, not equal to it
                if rel != Path("."):
                    return True
            except ValueError:
                continue
        return False

    def _check_path_permission(
        self, path: Path, allow_list: list, check_hash: bool = False
    ) -> bool:
        """Check if a path is permitted by an allow list.

        Args:
            path: Resolved absolute path to check.
            allow_list: List of allowed paths (files or directories).
            check_hash: If True, verify hash for entries that have one.

        Returns:
            True if path is allowed.
        """
        # Check exact file match
        if self._check_path_in_list(path, allow_list, check_hash=check_hash):
            return True
        # Check if path is within an allowed directory
        return self._check_path_in_dir_list(path, allow_list)

    def _check_read_permission(self, path: Path) -> bool:
        """Check if reading a file is permitted."""
        return self._check_path_permission(path, self.config.get("allow_read", []))

    def _check_create_permission(self, path: Path) -> bool:
        """Check if creating a new file is permitted."""
        return self._check_path_permission(path, self.config.get("allow_create", []))

    def _check_modify_permission(self, path: Path) -> bool:
        """Check if modifying an existing file is permitted."""
        return self._check_path_permission(
            path, self.config.get("allow_modify", []), check_hash=True
        )

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

        # Determine operation type from mode
        # w=write, a=append, x=exclusive create, +=read/write
        # Note: 'b' is binary mode (not write), 'r' is read
        is_write = any(c in str(mode) for c in "wax+")

        if is_write:
            is_new_file = not resolved.exists()
            if is_new_file:
                return self._check_create_permission(resolved)
            else:
                return self._check_modify_permission(resolved)
        else:
            return self._check_read_permission(resolved)

    def _check_env_write(self, args: tuple) -> bool:
        """Check environment variable write permission."""
        if not args:
            return True

        key = args[0]
        allowed = self.config.get("allow_env_var_writes", [])
        return key in allowed

    def _extract_executable(self, event: str, args: tuple) -> str | None:
        """Extract executable path from various execution events.

        Returns None if no executable can be determined (e.g., os.system).
        """
        if not args:
            return None

        if event == "subprocess.Popen":
            return str(args[0]) if args[0] else None
        elif event == "os.exec":
            # os.exec: (path, args, env)
            return str(args[0]) if args[0] else None
        elif event == "os.spawn":
            # os.spawn: (mode, path, args, env)
            return str(args[1]) if len(args) > 1 and args[1] else None
        elif event == "os.posix_spawn":
            # os.posix_spawn: (path, argv, env)
            return str(args[0]) if args[0] else None
        elif event == "ctypes.dlopen":
            # ctypes.dlopen: (name,)
            return str(args[0]) if args[0] else None

        return None

    def _resolve_executable(self, executable: str) -> Path | None:
        """Resolve executable to absolute path, searching PATH if needed."""
        import shutil

        # If already absolute, just resolve
        if os.path.isabs(executable):
            return Path(executable).resolve()

        # Search PATH
        found = shutil.which(executable)
        if found:
            return Path(found).resolve()

        # Try relative to workdir
        rel_path = self.workdir / executable
        if rel_path.exists():
            return rel_path.resolve()

        return None

    def _check_executable(self, event: str, args: tuple) -> bool:
        """Check if executing a binary is permitted."""
        executable = self._extract_executable(event, args)
        if executable is None:
            return True  # Can't determine executable, allow

        allow_list = self.config.get("allow_executables", [])
        if not allow_list:
            return False  # Empty list = block all executables

        exe_path = self._resolve_executable(executable)
        if exe_path is None:
            return False  # Can't resolve = block

        return self._check_path_permission(exe_path, allow_list, check_hash=True)

    def _check_shell_command(self, event: str, args: tuple) -> bool:
        """Check shell command execution permission."""
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
        for pattern in self.config.get("allow_shell_commands", []):
            if fnmatch.fnmatch(command, pattern):
                return True
        return False

    def _parse_domain_entry(self, entry: str) -> tuple[str, int | None]:
        """Parse a domain entry which may include a port.

        Supports formats:
            - "example.com" -> ("example.com", None)
            - "example.com:443" -> ("example.com", 443)

        Args:
            entry: Domain string, optionally with port.

        Returns:
            Tuple of (domain, port) where port is None if not specified.
        """
        # Prepend scheme so urlparse treats it as a netloc
        parsed = urlparse(f"//{entry}")
        domain = parsed.hostname or entry
        port = parsed.port
        return domain, port

    def _check_domain(self, args: tuple, event: str) -> bool:
        """Check if DNS resolution for a domain is permitted.

        Args:
            args: Event arguments (host, port, ...) for getaddrinfo
                  or (hostname,) for gethostbyname
            event: The audit event name

        Returns:
            True if allowed, False otherwise.
        """
        if not args:
            return True

        host = args[0]
        # socket.getaddrinfo has port as second arg
        port = args[1] if event == "socket.getaddrinfo" and len(args) > 1 else None

        if not host or not isinstance(host, str):
            return True

        # Check allowed domains
        for entry in self.config.get("allow_domains", []):
            allowed_domain, allowed_port = self._parse_domain_entry(entry)

            if host == allowed_domain or host.endswith("." + allowed_domain):
                # If entry specifies a port, check it matches
                if allowed_port is not None:
                    if port is None or port == allowed_port:
                        self._cache_resolved_ips(host, port)
                        return True
                else:
                    # No port specified - any port allowed
                    self._cache_resolved_ips(host, port)
                    return True

        return False

    def _cache_resolved_ips(self, domain: str, port: int | None) -> None:
        """Resolve and cache IPs for an allowed domain.

        Uses a recursion guard since DNS resolution triggers audit events.
        """
        if self._in_resolution:
            return

        self._in_resolution = True
        try:
            import socket

            results = socket.getaddrinfo(
                domain, port or 443, proto=socket.IPPROTO_TCP
            )
            for family, type_, proto, canonname, sockaddr in results:
                self._resolved_ips.add(sockaddr[0])
        except socket.gaierror:
            pass  # DNS resolution failed, nothing to cache
        finally:
            self._in_resolution = False

    def _is_ip_address(self, host: str) -> bool:
        """Check if host is an IP address (v4 or v6)."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _parse_ip_entry(self, entry: str) -> tuple[str, int | None]:
        """Parse IP entry which may include port (e.g., '10.0.0.1:80').

        For IPv6 with port, use bracket notation: [::1]:80
        """
        # Handle bracketed IPv6 with port: [::1]:80
        if entry.startswith("["):
            bracket_end = entry.find("]")
            if bracket_end != -1:
                ip_part = entry[1:bracket_end]
                if len(entry) > bracket_end + 1 and entry[bracket_end + 1] == ":":
                    port_str = entry[bracket_end + 2 :]
                    if port_str.isdigit():
                        return ip_part, int(port_str)
                return ip_part, None

        # For non-bracketed, check if it's IPv4:port or just IPv6
        if ":" in entry:
            parts = entry.rsplit(":", 1)
            # If last part is all digits, it's a port
            if parts[1].isdigit():
                # Verify first part is valid IPv4 (not IPv6)
                try:
                    ipaddress.IPv4Address(parts[0])
                    return parts[0], int(parts[1])
                except ValueError:
                    pass
            # Otherwise it's an IPv6 address without port
        return entry, None

    def _check_ip_permission(self, ip: str, port: int | None) -> bool:
        """Check if connecting to an IP is permitted."""
        # Check if IP was resolved from an allowed domain
        if ip in self._resolved_ips:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        # Check static allow_ips config
        for entry in self.config.get("allow_ips", []):
            allowed_ip, allowed_port = self._parse_ip_entry(entry)
            if allowed_port is not None and port != allowed_port:
                continue
            try:
                network = ipaddress.ip_network(allowed_ip, strict=False)
                if ip_obj in network:
                    return True
            except ValueError:
                continue
        return False

    def _check_socket_connect(self, args: tuple) -> bool:
        """Check if socket connection is permitted."""
        if len(args) < 2:
            return True

        address = args[1]
        if not isinstance(address, tuple) or len(address) < 1:
            return True

        host = address[0]
        port = address[1] if len(address) > 1 else None

        # Allow localhost/loopback
        if host in ("localhost", "127.0.0.1", "::1"):
            return True

        # Check if it's an IP address
        if self._is_ip_address(host):
            return self._check_ip_permission(host, port)

        # It's a hostname - check against allow_domains
        return self._check_domain((host, port), "socket.connect")

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
        elif event in EXEC_EVENTS:
            # Check binary execution permission first
            if not self._check_executable(event, args):
                return False
            # Also check shell command patterns for subprocess.Popen
            if event in SHELL_EVENTS:
                return self._check_shell_command(event, args)
            return True
        elif event == "os.system":
            # os.system only checks shell commands (no binary path to verify)
            return self._check_shell_command(event, args)
        elif event == "socket.connect":
            return self._check_socket_connect(args)
        elif event in (
            "socket.getaddrinfo",
            "socket.gethostbyname",
            "socket.gethostbyname_ex",
            "socket.gethostbyaddr",
        ):
            return self._check_domain(args, event)

        # Events not explicitly handled are allowed
        return True

    def _violation(self, reason: str) -> None:
        """Handle a permission violation by terminating immediately."""
        red = "\033[91m"
        reset = "\033[0m"
        sys.stderr.write(f"{red}[malwi-box] Blocked: {reason}{reset}\n")
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

    def _entry_exists(self, entries: list, path: str) -> bool:
        """Check if path already exists in allow list."""
        for e in entries:
            if isinstance(e, str) and e == path:
                return True
            if isinstance(e, dict) and e.get("path") == path:
                return True
        return False

    def _build_executable_entry(
        self, path_var: str, resolved: Path | None
    ) -> str | dict:
        """Build config entry for executable, with hash if available."""
        if not resolved or not resolved.exists():
            return path_var
        file_hash = self._compute_file_hash(resolved)
        if not file_hash:
            return path_var
        return {"path": path_var, "hash": file_hash}

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
                if not path:
                    continue
                mode = details.get("mode") or "r"
                is_new = details.get("is_new_file", False)
                is_write = any(c in mode for c in "wax+")

                if is_write and is_new:
                    key = "allow_create"
                elif is_write:
                    key = "allow_modify"
                else:
                    key = "allow_read"

                # Convert path to variable if possible for portability
                path = self._path_to_variable(path)
                if path not in config.get(key, []):
                    config.setdefault(key, []).append(path)

            elif event in EXEC_EVENTS:
                exe = details.get("executable") or details.get("library")
                if exe:
                    exe_path = self._resolve_executable(exe)
                    exe_var = self._path_to_variable(exe)
                    existing = config.get("allow_executables", [])
                    if not self._entry_exists(existing, exe_var):
                        entry = self._build_executable_entry(exe_var, exe_path)
                        config.setdefault("allow_executables", []).append(entry)
                # Also save shell command for subprocess.Popen
                if event == "subprocess.Popen":
                    cmd = details.get("command")
                    if cmd and cmd not in config.get("allow_shell_commands", []):
                        config.setdefault("allow_shell_commands", []).append(cmd)

            elif event == "os.system":
                cmd = details.get("command")
                if cmd and cmd not in config.get("allow_shell_commands", []):
                    config.setdefault("allow_shell_commands", []).append(cmd)

            elif event in ("os.putenv", "os.unsetenv"):
                key = details.get("key")
                if key and key not in config.get("allow_env_var_writes", []):
                    config.setdefault("allow_env_var_writes", []).append(key)

            elif event in ("socket.getaddrinfo", "socket.gethostbyname"):
                domain = details.get("domain")
                port = details.get("port")
                if domain:
                    # Save as "domain:port" if port specified, otherwise just domain
                    entry = f"{domain}:{port}" if port else domain
                    if entry not in config.get("allow_domains", []):
                        config.setdefault("allow_domains", []).append(entry)

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
        # If restrictions are configured, block by default
        # (The actual key is not easily accessible from the profile hook)
        return not allowed

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
