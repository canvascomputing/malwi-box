"""BoxEngine - Permission engine for Python audit event enforcement."""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import os
import re
import shutil
import socket
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from malwi_box import toml

# List variable expansion for config values
# Similar to path variables but expand to multiple values
LIST_VARIABLES: dict[str, list[str]] = {
    # PyPI infrastructure - for pip install
    "$PYPI_DOMAINS": [
        "pypi.org",
        "files.pythonhosted.org",
    ],
    # Localhost addresses - IPv4, IPv6, and hostname
    "$LOCALHOST": [
        "127.0.0.1",  # IPv4 loopback
        "::1",  # IPv6 loopback
        "localhost",  # Hostname
    ],
    # Standard HTTP methods - RFC 7231 + PATCH (RFC 5789)
    "$ALL_HTTP_METHODS": [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    ],
    # Safe environment variables - non-sensitive system/shell vars
    "$SAFE_ENV_VARS": [
        # Shell environment
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        # Working directories
        "PWD",
        "OLDPWD",
        # Temporary directories
        "TMPDIR",
        "TMP",
        "TEMP",
        # Python environment
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
    ],
}

# Events that can execute native binaries or load shared libraries
EXEC_EVENTS = frozenset(
    {
        "subprocess.Popen",
        "os.exec",
        "os.spawn",
        "os.posix_spawn",
        "ctypes.dlopen",
    }
)

# Events that run shell commands (checked against allow_shell_commands)
SHELL_EVENTS = frozenset({"subprocess.Popen", "os.system"})

# Events that are info-only (never blocked, always logged for security awareness)
INFO_ONLY_EVENTS = frozenset(
    {
        # Encoding
        "encoding.base64",
        "encoding.hex",
        "encoding.zlib",
        "encoding.gzip",
        "encoding.bz2",
        "encoding.lzma",
        # Crypto
        "crypto.cipher",
        "crypto.fernet",
        "crypto.hmac",
        "crypto.kdf",
        "crypto.rsa",
        "crypto.aes",
        "crypto.chacha20",
        # Secrets
        "secrets.token",
        # Environment
        "os.putenv",
        "os.unsetenv",
        # Deserialization
        "pickle.find_class",
        "marshal.loads",
        # Archives
        "shutil.unpack_archive",
    }
)

# Security-sensitive paths that should NEVER be readable by default
# Even if a broader path like $OS_SYSTEM is allowed, these are blocked
SENSITIVE_PATHS = [
    # System credentials & secrets
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/security",
    "/etc/pam.d",
    "/etc/ssh/*_key",
    "/etc/ssl/private",
    "/root",
    # User SSH & GPG
    "$HOME/.ssh",
    "$HOME/.gnupg",
    "$HOME/.pgp",
    # Cloud provider credentials
    "$HOME/.aws",
    "$HOME/.azure",
    "$HOME/.config/gcloud",
    "$HOME/.kube",
    "$HOME/.docker/config.json",
    "$HOME/.terraform.d/credentials.tfrc.json",
    # macOS keychain & security
    "$HOME/Library/Keychains",
    "/Library/Keychains",
    "/System/Library/Keychains",
    "$HOME/Library/Cookies",
    "$HOME/Library/Application Support/com.apple.TCC",
    # Browser data (passwords, cookies, history)
    "$HOME/Library/Application Support/Google/Chrome",
    "$HOME/Library/Application Support/Firefox",
    "$HOME/Library/Application Support/Microsoft Edge",
    "$HOME/Library/Safari",
    "$HOME/.config/google-chrome",
    "$HOME/.config/chromium",
    "$HOME/.mozilla/firefox",
    "$HOME/.config/microsoft-edge",
    # Password managers
    "$HOME/Library/Application Support/1Password",
    "$HOME/Library/Application Support/Bitwarden",
    "$HOME/Library/Application Support/LastPass",
    "$HOME/.config/keepassxc",
    "$HOME/.local/share/keyrings",
    "$HOME/.password-store",
    # Messaging & communication
    "$HOME/Library/Messages",
    "$HOME/Library/Application Support/Slack",
    "$HOME/Library/Application Support/discord",
    "$HOME/.config/Signal",
    # Database credentials
    "$HOME/.pgpass",
    "$HOME/.my.cnf",
    "$HOME/.mongodb/credentials",
    "$HOME/.rediscli_history",
    # Development secrets
    "$HOME/.npmrc",
    "$HOME/.pypirc",
    "$HOME/.gem/credentials",
    "$HOME/.cargo/credentials",
    "$HOME/.netrc",
    "$HOME/.git-credentials",
    # Cryptocurrency wallets
    "$HOME/Library/Application Support/Bitcoin",
    "$HOME/Library/Application Support/Ethereum",
    "$HOME/.bitcoin",
    "$HOME/.ethereum",
    # Environment files (often contain secrets)
    "$PWD/.env",
    "$PWD/.env.local",
    "$PWD/.env.production",
]

# Environment variables that should NEVER be readable by default
SENSITIVE_ENV_VARS = [
    # API keys & tokens
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_API_KEY",
    "GCP_SERVICE_ACCOUNT",
    "GITHUB_TOKEN",
    "GITHUB_API_TOKEN",
    "GITLAB_TOKEN",
    "BITBUCKET_TOKEN",
    "HEROKU_API_KEY",
    "DIGITALOCEAN_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "STRIPE_SECRET_KEY",
    "STRIPE_API_KEY",
    "TWILIO_AUTH_TOKEN",
    "SENDGRID_API_KEY",
    "MAILGUN_API_KEY",
    "SLACK_TOKEN",
    "SLACK_WEBHOOK_URL",
    "DISCORD_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "HUGGINGFACE_TOKEN",
    # Database credentials
    "DATABASE_URL",
    "DATABASE_PASSWORD",
    "DB_PASSWORD",
    "POSTGRES_PASSWORD",
    "MYSQL_PASSWORD",
    "MYSQL_ROOT_PASSWORD",
    "MONGO_PASSWORD",
    "MONGODB_PASSWORD",
    "REDIS_PASSWORD",
    "REDIS_URL",
    # Authentication secrets
    "SECRET_KEY",
    "JWT_SECRET",
    "JWT_SECRET_KEY",
    "SESSION_SECRET",
    "COOKIE_SECRET",
    "ENCRYPTION_KEY",
    "SIGNING_KEY",
    "API_KEY",
    "API_SECRET",
    "PRIVATE_KEY",
    "AUTH_TOKEN",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    # SSH & certificates
    "SSH_PRIVATE_KEY",
    "SSH_KEY",
    "SSL_KEY",
    "TLS_KEY",
    "CERTIFICATE_KEY",
    # Package manager tokens
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "PYPI_PASSWORD",
    "GEM_HOST_API_KEY",
    "CARGO_REGISTRY_TOKEN",
    "DOCKER_PASSWORD",
    "DOCKER_AUTH_CONFIG",
    # CI/CD secrets
    "CI_JOB_TOKEN",
    "CIRCLE_TOKEN",
    "TRAVIS_TOKEN",
    "JENKINS_TOKEN",
    # Miscellaneous
    "PASSWORD",
    "PASSWD",
    "CREDENTIALS",
    "TOKEN",
]


class BoxEngine:
    """Permission engine for audit event enforcement.

    Reads configuration from a YAML file and enforces fine-grained
    permissions for file access, environment variables, subprocess
    execution, and network requests.
    """

    def __init__(
        self, config_path: str = ".malwi-box.toml", workdir: str | None = None
    ):
        """Initialize the BoxEngine.

        Args:
            config_path: Path to the YAML configuration file.
            workdir: Working directory for relative paths. Defaults to cwd.
        """
        self.config_path = Path(config_path)
        self.workdir = Path(workdir) if workdir else Path.cwd()
        self.config = self._load_config()
        self._decisions: list[dict[str, Any]] = []
        self._resolved_ips: set[str] = set()  # IPs resolved from allowed domains
        self._in_resolution = False  # Guard against recursive DNS resolution

    def _default_config(self) -> dict[str, Any]:
        """Return default configuration with pip-friendly permissions.

        Uses variables like $PYPI_DOMAINS to document what's allowed.
        All allow_* lists block when empty.
        """
        return {
            # File access
            "allow_read": [
                "$PWD",
                "$PYTHON_STDLIB",
                "$PYTHON_SITE_PACKAGES",
                "$PYTHON_PLATLIB",
                "$PIP_CACHE",
                "$TMPDIR",
                "$CACHE_HOME",
            ],
            "allow_create": ["$PWD", "$TMPDIR", "$PIP_CACHE"],
            "allow_modify": ["$TMPDIR", "$PIP_CACHE"],
            "allow_delete": ["$TMPDIR", "$PIP_CACHE"],
            # Network - using $PYPI_DOMAINS variable
            "allow_domains": ["$PYPI_DOMAINS"],
            "allow_ips": ["$LOCALHOST"],
            "allow_http_urls": ["$PYPI_DOMAINS/*"],
            "allow_http_methods": ["$ALL_HTTP_METHODS"],
            # Execution - empty = block all
            "allow_executables": [],
            "allow_shell_commands": [],
            # Environment
            "allow_env_var_reads": ["$SAFE_ENV_VARS"],
            # Sockets
            "allow_raw_sockets": False,
        }

    def _load_config(self) -> dict[str, Any]:
        """Load config from TOML file or return defaults."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    config = toml.load(f) or {}
                # Merge with defaults for any missing keys
                defaults = self._default_config()
                for key, value in defaults.items():
                    if key not in config:
                        config[key] = value
                return config
            except (toml.TOMLError, OSError) as e:
                sys.stderr.write(f"[malwi-box] Warning: Could not load config: {e}\n")
                return self._default_config()
        return self._default_config()

    def _get_cache_home(self) -> str:
        """Get XDG cache directory (cross-platform)."""
        if sys.platform == "darwin":
            return os.path.expanduser("~/Library/Caches")
        return os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))

    def _get_pip_cache(self) -> str:
        """Get pip cache directory."""
        return os.path.join(self._get_cache_home(), "pip")

    def _get_os_system_paths(self) -> list[str]:
        """Get OS system read-only paths."""
        if sys.platform == "darwin":
            return ["/System", "/Library", "/usr/lib", "/usr/share"]
        else:  # Linux
            return ["/usr/lib", "/usr/share", "/lib", "/lib64"]

    def _get_path_variable_mappings(self) -> list[tuple[str, str]]:
        """Return ordered list of (path, variable) mappings.

        Order matters - more specific paths first for correct matching
        when converting paths to variables.
        """
        return [
            # Python ecosystem (most specific)
            (self._get_pip_cache(), "$PIP_CACHE"),
            (os.environ.get("VIRTUAL_ENV", ""), "$VENV"),
            (sysconfig.get_path("purelib") or "", "$PYTHON_SITE_PACKAGES"),
            (sysconfig.get_path("platlib") or "", "$PYTHON_PLATLIB"),
            (sysconfig.get_path("stdlib") or "", "$PYTHON_STDLIB"),
            (sys.prefix, "$PYTHON_PREFIX"),
            # System paths - order: cache, PWD, TMPDIR, HOME
            (self._get_cache_home(), "$CACHE_HOME"),
            (str(self.workdir), "$PWD"),
            (tempfile.gettempdir(), "$TMPDIR"),
            (os.path.expanduser("~"), "$HOME"),
        ]

    def _expand_path_variables(self, path: str) -> str:
        """Expand variables in a path string.

        Supports:
          $PWD, $HOME, $TMPDIR, $CACHE_HOME
          $PYTHON_STDLIB, $PYTHON_SITE_PACKAGES, $PYTHON_PLATLIB, $PYTHON_PREFIX
          $PIP_CACHE, $VENV
          $ENV{VAR_NAME}
        """
        if "$" not in path:
            return path

        # Build dict from shared mappings (reversed: var -> path)
        variables = {var: value for value, var in self._get_path_variable_mappings()}

        result = path
        for var, value in variables.items():
            if var in result and value:  # Only replace if value is non-empty
                result = result.replace(var, value)

        # Handle $ENV{VAR_NAME} pattern
        def env_replace(match: re.Match) -> str:
            var_name = match.group(1)
            return os.environ.get(var_name, "")

        result = re.sub(r"\$ENV\{([^}]+)\}", env_replace, result)

        return result

    def _expand_list_variable(self, entry: str) -> list[str]:
        """Expand list variables like $PYPI_DOMAINS, $LOCALHOST, etc.

        Returns a list of expanded values, or [entry] if no expansion needed.
        """
        # Check for exact match first
        if entry in LIST_VARIABLES:
            return LIST_VARIABLES[entry]

        # Check for pattern like "$PYPI_DOMAINS/*"
        for var, values in LIST_VARIABLES.items():
            if entry.startswith(var):
                suffix = entry[len(var) :]
                return [v + suffix for v in values]

        return [entry]

    def _expand_config_list(self, config_key: str) -> list[str]:
        """Get config list with all variables expanded."""
        entries = self.config.get(config_key, [])
        result = []
        for entry in entries:
            result.extend(self._expand_list_variable(entry))
        return result

    def _path_to_variable(self, path: str) -> str:
        """Convert an absolute path to a variable if possible."""
        for prefix, var in self._get_path_variable_mappings():
            if prefix and path.startswith(prefix):
                return path.replace(prefix, var, 1)

        return path

    def _is_sensitive_path(self, path: str | Path) -> bool:
        """Check if a path is in the sensitive paths list.

        Sensitive paths are always blocked, even if they match an allow rule.
        """
        path_str = str(path)
        for sensitive in SENSITIVE_PATHS:
            expanded = self._expand_path_variables(sensitive)
            # Handle glob patterns
            if "*" in expanded:
                if fnmatch.fnmatch(path_str, expanded):
                    return True
            # Handle directory prefixes
            elif path_str == expanded or path_str.startswith(expanded + os.sep):
                return True
        return False

    def _is_sensitive_env_var(self, var_name: str) -> bool:
        """Check if an environment variable is in the sensitive list.

        Sensitive env vars are always blocked from being read.
        """
        # Handle bytes
        if isinstance(var_name, bytes):
            var_name = var_name.decode("utf-8", errors="replace")
        return var_name in SENSITIVE_ENV_VARS

    def is_info_only_env_read(self, event: str, args: tuple) -> bool:
        """Check if this is a non-sensitive env var read (info-only).

        Returns True if this is an env read event for a non-sensitive var.
        These should be logged as info events, not blocked.
        """
        if event not in ("os.getenv", "os.environ.get"):
            return False
        if not args:
            return False
        var_name = args[0]
        if isinstance(var_name, bytes):
            var_name = var_name.decode("utf-8", errors="replace")
        return not self._is_sensitive_env_var(var_name)

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

    def _check_file_permission(
        self,
        path: Path,
        config_key: str,
        check_hash: bool = False,
        check_sensitive: bool = False,
    ) -> bool:
        """Check if a file operation is permitted.

        Args:
            path: Resolved absolute path to check.
            config_key: Config key (e.g., "allow_read", "allow_modify").
            check_hash: If True, verify hash for entries that have one.
            check_sensitive: If True, block sensitive paths.

        Returns:
            True if operation is allowed.
        """
        if check_sensitive and self._is_sensitive_path(path):
            return False
        return self._check_path_permission(
            path, self.config.get(config_key, []), check_hash=check_hash
        )

    def _check_read_permission(self, path: Path) -> bool:
        """Check if reading a file is permitted."""
        return self._check_file_permission(
            path, "allow_read", check_hash=True, check_sensitive=True
        )

    def _check_create_permission(self, path: Path) -> bool:
        """Check if creating a new file is permitted."""
        return self._check_file_permission(path, "allow_create")

    def _check_modify_permission(self, path: Path) -> bool:
        """Check if modifying an existing file is permitted."""
        return self._check_file_permission(path, "allow_modify", check_hash=True)

    def _check_delete_permission(self, path: Path) -> bool:
        """Check if deleting a file is permitted."""
        return self._check_file_permission(path, "allow_delete", check_sensitive=True)

    def _check_file_delete(self, args: tuple) -> bool:
        """Check file deletion permission for 'os.remove'/'os.unlink' events."""
        if not args:
            return True

        path_arg = args[0]

        # Handle non-string paths
        if not isinstance(path_arg, (str, Path, bytes)):
            return True

        if isinstance(path_arg, bytes):
            path_arg = path_arg.decode("utf-8", errors="replace")

        resolved = self._resolve_path(path_arg)
        return self._check_delete_permission(resolved)

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

        # Check allowed domains (expand variables like $PYPI_DOMAINS)
        for entry in self._expand_config_list("allow_domains"):
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
            results = socket.getaddrinfo(domain, port or 443, proto=socket.IPPROTO_TCP)
            for _family, _type, _proto, _canonname, sockaddr in results:
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

        # Check static allow_ips config (expand variables like $LOCALHOST)
        for entry in self._expand_config_list("allow_ips"):
            allowed_ip, allowed_port = self._parse_ip_entry(entry)
            if allowed_port is not None and port != allowed_port:
                continue
            # Handle "localhost" hostname
            if allowed_ip == "localhost":
                if ip in ("127.0.0.1", "::1"):
                    return True
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

    def _domain_matches(self, host: str, pattern_host: str) -> bool:
        """Check if host matches pattern (exact or subdomain)."""
        if not host or not pattern_host:
            return False
        # Exact match or subdomain match
        return host == pattern_host or host.endswith("." + pattern_host)

    def _url_matches_pattern(self, url: str, pattern: str) -> bool:
        """Match URL against pattern with optional scheme.

        Args:
            url: The full URL to check (e.g., "https://api.example.com/v1/users")
            pattern: Pattern to match (e.g., "api.example.com/v1/*")

        Returns:
            True if URL matches pattern.
        """
        # Normalize URL - add scheme if missing
        if "://" not in url:
            url = f"https://{url}"
        parsed_url = urlparse(url)

        # Normalize pattern - add scheme if missing
        pattern_has_scheme = "://" in pattern
        if not pattern_has_scheme:
            pattern = f"https://{pattern}"
        parsed_pattern = urlparse(pattern)

        # If pattern has explicit scheme, it must match
        if pattern_has_scheme and parsed_url.scheme != parsed_pattern.scheme:
            return False

        # Extract host (without port) for comparison
        url_host = parsed_url.hostname or ""
        pattern_host = parsed_pattern.hostname or ""

        # Domain must match (exact or subdomain)
        if not self._domain_matches(url_host, pattern_host):
            return False

        # Port must match if pattern specifies one
        if parsed_pattern.port is not None and parsed_url.port != parsed_pattern.port:
            return False

        # Path must match (glob pattern)
        url_path = parsed_url.path or "/"
        pattern_path = parsed_pattern.path or "/"

        # Handle query string in pattern
        if parsed_pattern.query:
            url_full_path = (
                f"{url_path}?{parsed_url.query}" if parsed_url.query else url_path
            )
            pattern_full_path = f"{pattern_path}?{parsed_pattern.query}"
            return fnmatch.fnmatch(url_full_path, pattern_full_path)

        return fnmatch.fnmatch(url_path, pattern_path)

    def _check_url_request(self, args: tuple) -> bool:
        """Check if URL request is permitted.

        Args:
            args: (url, data, headers, method) from urllib.Request event
                  or (url, method) from http.request event

        Returns:
            True if allowed, False otherwise.
        """
        if not args:
            return True

        url = args[0]
        if not url or not isinstance(url, str):
            return True

        # Check HTTP method restrictions (expand variables like $ALL_HTTP_METHODS)
        method = args[3] if len(args) > 3 else (args[1] if len(args) > 1 else None)
        if isinstance(method, str):
            allowed_methods = self._expand_config_list("allow_http_methods")
            if not allowed_methods:
                return False  # Empty = block all methods
            upper_allowed = [m.upper() for m in allowed_methods]
            if method.upper() not in upper_allowed:
                return False

        # Check URL patterns (expand variables like $PYPI_DOMAINS/*)
        allow_urls = self._expand_config_list("allow_http_urls")
        if not allow_urls:
            return False  # Empty = block all URLs

        # Check against URL patterns
        return any(self._url_matches_pattern(url, pattern) for pattern in allow_urls)

    def _check_http_request(self, args: tuple) -> bool:
        """Check if HTTP request is permitted.

        Args:
            args: (url, method) from http.request event

        Returns:
            True if allowed, False otherwise.
        """
        return self._check_url_request(args)

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
        elif event in ("os.remove", "os.unlink"):
            return self._check_file_delete(args)
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
        elif event == "urllib.Request":
            return self._check_url_request(args)
        elif event == "http.request":
            return self._check_http_request(args)
        elif event == "socket.__new__":
            return self._check_raw_socket(args)

        # Events not explicitly handled are allowed
        return True

    def _check_raw_socket(self, args: tuple) -> bool:
        """Check if raw socket creation is permitted.

        Args:
            args: (family, type, proto) from socket.__new__ event
                  SOCK_RAW = 3

        Returns:
            True if allowed, False otherwise.
        """
        if len(args) >= 2:
            sock_type = args[1]
            # Check for SOCK_RAW (value 3)
            if sock_type == socket.SOCK_RAW:
                return self.config.get("allow_raw_sockets", False)
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

    def _build_entry_with_hash(
        self, path_var: str, resolved: Path | None, skip_dirs: bool = True
    ) -> str | dict:
        """Build config entry with hash if path is a readable file.

        Args:
            path_var: The path variable string (e.g., "$PWD/file.py").
            resolved: The resolved Path object, or None.
            skip_dirs: If True, return plain path_var for directories.

        Returns:
            Either path_var string or dict with path and hash.
        """
        if not resolved or not resolved.exists():
            return path_var
        if skip_dirs and resolved.is_dir():
            return path_var
        file_hash = self._compute_file_hash(resolved)
        if not file_hash:
            return path_var
        return {"path": path_var, "hash": file_hash}

    def _load_existing_config(self) -> dict[str, Any]:
        """Load existing config or return defaults."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    return toml.load(f) or {}
            except (toml.TOMLError, OSError):
                pass
        return self._default_config()

    def _write_config(self, config: dict[str, Any]) -> None:
        """Write config to file."""
        try:
            with open(self.config_path, "w") as f:
                toml.dump(config, f)
        except OSError as e:
            sys.stderr.write(f"[malwi-box] Warning: Could not save config: {e}\n")

    def _save_file_decision(self, config: dict, decision: dict) -> None:
        """Save a file access decision to config."""
        details = decision.get("details", {})
        path = details.get("path")
        if not path:
            return

        mode = details.get("mode") or "r"
        is_new = details.get("is_new_file", False)
        is_write = any(c in mode for c in "wax+")

        if is_write and is_new:
            key = "allow_create"
        elif is_write:
            key = "allow_modify"
        else:
            key = "allow_read"

        path_var = self._path_to_variable(path)
        existing = config.get(key, [])
        if self._entry_exists(existing, path_var):
            return

        if key in ("allow_read", "allow_modify"):
            entry = self._build_entry_with_hash(path_var, Path(path))
        else:
            entry = path_var
        config.setdefault(key, []).append(entry)

    def _save_exec_decision(self, config: dict, decision: dict) -> None:
        """Save an execution decision to config."""
        event = decision["event"]
        details = decision.get("details", {})

        exe = details.get("executable") or details.get("library")
        if exe:
            exe_path = self._resolve_executable(exe)
            exe_var = self._path_to_variable(exe)
            existing = config.get("allow_executables", [])
            if not self._entry_exists(existing, exe_var):
                entry = self._build_entry_with_hash(exe_var, exe_path, skip_dirs=False)
                config.setdefault("allow_executables", []).append(entry)

        if event == "subprocess.Popen":
            self._save_shell_command(config, details.get("command"))

    def _save_shell_command(self, config: dict, cmd: str | None) -> None:
        """Save a shell command to config if not already present.

        Commands are saved exactly as executed. Users can manually edit
        the config to use glob patterns (e.g., 'git clone *') for broader matching.
        """
        if not cmd:
            return

        existing = config.get("allow_shell_commands", [])
        # Check if any existing pattern already matches this command
        for existing_pattern in existing:
            if fnmatch.fnmatch(cmd, existing_pattern):
                return  # Already covered by existing pattern

        config.setdefault("allow_shell_commands", []).append(cmd)

    def _save_network_decision(self, config: dict, decision: dict) -> None:
        """Save a network-related decision to config."""
        event = decision["event"]
        details = decision.get("details", {})

        if event in ("socket.getaddrinfo", "socket.gethostbyname"):
            domain = details.get("domain")
            port = details.get("port")
            if domain:
                entry = f"{domain}:{port}" if port else domain
                if entry not in config.get("allow_domains", []):
                    config.setdefault("allow_domains", []).append(entry)

        elif event in ("urllib.Request", "http.request"):
            url = details.get("url")
            method = details.get("method")
            if url:
                parsed = urlparse(url)
                url_pattern = f"{parsed.netloc}{parsed.path}"
                if url_pattern not in config.get("allow_http_urls", []):
                    config.setdefault("allow_http_urls", []).append(url_pattern)
            if method:
                method_upper = method.upper()
                if method_upper not in config.get("allow_http_methods", []):
                    config.setdefault("allow_http_methods", []).append(method_upper)

    def save_decisions(self) -> None:
        """Merge recorded decisions into config file."""
        if not self._decisions:
            return

        config = self._load_existing_config()

        for decision in self._decisions:
            if not decision.get("allowed"):
                continue

            event = decision["event"]

            if event == "open":
                self._save_file_decision(config, decision)
            elif event in EXEC_EVENTS:
                self._save_exec_decision(config, decision)
            elif event == "os.system":
                cmd = decision.get("details", {}).get("command")
                self._save_shell_command(config, cmd)
            elif event in ("socket.getaddrinfo", "socket.gethostbyname",
                          "urllib.Request", "http.request"):
                self._save_network_decision(config, decision)

        self._write_config(config)

    def _check_env_read(self, args: tuple) -> bool:
        """Check if reading an env var is allowed.

        Args:
            args: (key,) - the environment variable name

        Returns:
            True if allowed, False otherwise.
        """
        if not args:
            return True

        key = args[0]
        if isinstance(key, bytes):
            key = key.decode("utf-8", errors="replace")

        # Sensitive env vars are always blocked
        if self._is_sensitive_env_var(key):
            return False

        allowed = self._expand_config_list("allow_env_var_reads")
        if not allowed:
            return False  # Empty = block all

        return key in allowed

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
                    sys.stderr.write(f"[malwi-box] WOULD BLOCK: {event}: {args}\n")

        return hook
