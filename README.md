<p align="center">
  <img src="malwi-box.png" alt="malwi-box logo" width="200">
</p>

<h1 align="center">malwi-box</h1>

<p align="center">
  <strong>Intercept, audit, and block critical Python operations at runtime.</strong>
</p>

<p align="center">
  <em>Shipped without any dependencies, except pip</em>
</p>

<p align="center">
  <img src="malwi-box.svg" alt="malwi-box demo" width="600">
</p>

## Use Cases

- 🔬 **Malware analysis** - Safely detonate suspicious Python code and observe its behavior
- 📦 **Dependency auditing** - Discover what file, network, and process access a package actually needs
- 🔒 **Runtime protection** - Enforce allowlists to block unauthorized operations in production

> **Warning**: This tool is not executed in isolation or virtualization, it runs on your actual machine, kernel and CPU. Use it at your own risk. Still it allows to reduce the blast radius of typical Python malware.

## Installation

```bash
pip install malwi-box
```

Or with uv:
```bash
uv tool install malwi-box
```

## Quick Start

```
$ malwi-box eval "open('/etc/passwd').read()"

[malwi-box] Blocked: Read file: /etc/passwd
```

## Commands

### run

Run a Python script or module with sandboxing.

```bash
malwi-box run script.py [args...]
malwi-box run --force script.py     # log violations without blocking
malwi-box run --review script.py    # approve/deny each operation
```

### eval

Execute a Python code string with sandboxing.

```bash
malwi-box eval "print('hello')"
malwi-box eval --force "import os; os.system('id')"
malwi-box eval --review "open('/etc/passwd').read()"
```

### install

Install pip packages with sandboxing. Most malware packages perform malicious activities at install-time.

```bash
malwi-box install package
malwi-box install package --version 1.2.3
malwi-box install -r requirements.txt
malwi-box install --review package  # approve/deny each operation
```

### config

Manage configuration.

```bash
malwi-box config create             # creates .malwi-box.toml
malwi-box config create --path FILE
```

## Configuration Reference

Config file: `.malwi-box.toml`

```toml
# File access permissions
allow_read = [
  "$PWD",                     # working directory
  "$PYTHON_STDLIB",           # Python standard library
  "$PYTHON_SITE_PACKAGES",    # installed packages
  "$HOME/.config/myapp",      # specific config directory
  "/etc/hosts",               # specific file
]

allow_create = [
  "$PWD",                     # allow creating files in workdir
  "$TMPDIR",                  # allow temp files
]

allow_modify = [
  "$PWD/data",                # only modify files in data/
  { path = "/etc/myapp.conf", hash = "sha256:abc123..." },
]

allow_delete = []             # no deletions allowed

# Network permissions
allow_domains = [
  "pypi.org",                 # allow any port
  "files.pythonhosted.org",
  "api.example.com:443",      # restrict to specific port
]

allow_ips = [
  "10.0.0.0/8",               # CIDR notation
  "192.168.1.100:8080",       # specific IP:port
  "[::1]:443",                # IPv6 with port
]

# HTTP URL path restrictions (optional, empty = domain-only mode)
allow_http_urls = [
  "api.example.com/v1/*",         # glob pattern for paths
  "cdn.example.com/assets/*",
  "https://secure.example.com/*", # explicit scheme
]

# HTTP methods allowed (optional, empty = all methods)
allow_http_methods = ["GET", "POST", "HEAD"]

# Raw socket access (default: false, blocks SOCK_RAW creation)
allow_raw_sockets = false

# Process execution
allow_executables = [
  "/usr/bin/git",             # allow by path
  "$PWD/.venv/bin/*",         # glob pattern
  { path = "/usr/bin/curl", hash = "sha256:abc123..." },
]

allow_shell_commands = [
  "/usr/bin/git *",           # glob pattern matching
  "/usr/bin/curl *",
]

# Environment variables
allow_env_var_reads = []      # restrict env access
allow_env_var_writes = ["PATH", "PYTHONPATH"]
```

### Path Variables
| Variable | Description |
|----------|-------------|
| `$PWD` | Working directory |
| `$HOME` | User home directory |
| `$TMPDIR` | System temp directory (macOS: `/var/folders/.../T`, Linux: `/tmp`) |
| `$CACHE_HOME` | User cache directory (macOS: `~/Library/Caches`, Linux: `~/.cache`) |
| `$PIP_CACHE` | pip cache directory |
| `$VENV` | Active virtualenv root (if `$VIRTUAL_ENV` is set) |
| `$PYTHON_STDLIB` | Python standard library |
| `$PYTHON_SITE_PACKAGES` | Installed packages (purelib) |
| `$PYTHON_PLATLIB` | Platform-specific packages |
| `$PYTHON_PREFIX` | Python installation prefix |
| `$ENV{VAR}` | Any environment variable |

### Sensitive Paths (Always Blocked)
The following paths are automatically blocked even if they match an allow rule:
- SSH keys and GPG (`~/.ssh`, `~/.gnupg`)
- Cloud credentials (`~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`)
- Browser data (Chrome, Firefox, Safari, Edge)
- Password managers (1Password, Bitwarden, KeePassXC, keychains)
- Development secrets (`~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.git-credentials`)
- System secrets (`/etc/shadow`, `/etc/sudoers`, `/etc/ssh/*_key`)

### Network Behavior
- Domains in `allow_domains` automatically permit their resolved IPs
- Direct IP access requires explicit `allow_ips` entries
- CIDR notation supported for IP ranges
- Port restrictions supported for both domains and IPs

### HTTP URL Path Allowlisting
- If `allow_http_urls` is empty, only domain-level checks apply (default behavior)
- If `allow_http_urls` is configured, requests must match both domain AND URL pattern
- Scheme (`http://`, `https://`) is optional in patterns - omit to match both
- Glob patterns supported for paths: `api.example.com/v1/*`
- Subdomain matching: `example.com/api/*` matches `api.example.com/api/*`

### HTTP Method Restrictions
- If `allow_http_methods` is empty, all HTTP methods are allowed
- If configured, only listed methods are permitted (e.g., `["GET", "HEAD"]`)

### HTTP Library Coverage
HTTP request interception covers:
- `urllib.request` (stdlib)
- `http.client` (stdlib)
- `urllib3`
- `requests`
- `httpx`
- `aiohttp`

**Bypass note:** Raw socket HTTP requests bypass library hooks but are blocked by default (`allow_raw_sockets = false`). The `socket.connect` event still captures all connections at the network level.

### Hash Verification
Executables and files can include SHA256 hashes:
```toml
allow_executables = [
  { path = "/usr/bin/git", hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
]
```

## How It Works

Uses Python's PEP 578 audit hooks via a C++ extension to intercept:
- File operations (`open`)
- Network requests (`socket.connect`, `socket.getaddrinfo`)
- HTTP requests (`urllib.Request` + profile hooks for `requests`, `httpx`, `urllib3`, `aiohttp`, `http.client`)
- Process execution (`subprocess.Popen`, `os.exec*`, `os.system`)
- Library loading (`ctypes.dlopen`)
- Raw socket creation (`socket.__new__` with `SOCK_RAW`)

**Protections against bypass:**
- Blocks `sys.addaudithook` to prevent registering competing hooks
- Blocks `sys.settrace` and `sys.setprofile` to prevent debugger-based evasion
- Blocks `ctypes.dlopen` by default to prevent loading native code that bypasses hooks

Blocked operations terminate immediately with exit code 78.

## Limitations

- Audit hooks cannot be bypassed from Python, but native code can
- Here it is important to review which executables are allow-listed
