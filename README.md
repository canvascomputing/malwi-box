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

```bash
# Block file access
$ malwi-box eval "open('/etc/passwd').read()"
[malwi-box] Blocked: Read file: /etc/passwd

# Block network requests
$ malwi-box eval "import urllib.request; urllib.request.urlopen('https://evil.com')"
[malwi-box] Blocked: DNS lookup: evil.com

# Block shell commands
$ malwi-box eval "import os; os.system('whoami')"
[malwi-box] Blocked: Shell command: /bin/sh -c whoami

# Block subprocess execution
$ malwi-box eval "import subprocess; subprocess.run(['curl', 'https://evil.com'])"
[malwi-box] Blocked: Execute: /usr/bin/curl

# Log suspicious encoding (info-only, not blocked)
$ malwi-box eval "import base64; base64.b64encode(b'secret')"
[malwi-box] Base64: b64encode
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
malwi-box install --review package # approve/deny each operation
```

### config

Manage configuration.

```bash
malwi-box config create # creates .malwi-box.toml
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

allow_delete = [
  "$TMPDIR",                  # allow temp cleanup
  "$PIP_CACHE",               # allow pip cache cleanup
]

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

# HTTP URL path restrictions (empty = block all)
allow_http_urls = [
  "$PYPI_DOMAINS/*",              # use variable for PyPI URLs
  "api.example.com/v1/*",         # glob pattern for paths
  "cdn.example.com/assets/*",
  "https://secure.example.com/*", # explicit scheme
]

# HTTP methods allowed (empty = block all)
allow_http_methods = ["$ALL_HTTP_METHODS"]  # variable for all standard methods

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

# Environment variables (empty = block all)
allow_env_var_reads = ["$SAFE_ENV_VARS"]  # variable for safe env vars
```

### Variables

Variables can be used in config values and are expanded at runtime.

| Variable | Expands To |
|----------|------------|
| **Path variables** | |
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
| **List variables** | *Expand to multiple values* |
| `$PYPI_DOMAINS` | `pypi.org`, `files.pythonhosted.org` |
| `$LOCALHOST` | `127.0.0.1`, `::1`, `localhost` |
| `$ALL_HTTP_METHODS` | `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS` |
| `$SAFE_ENV_VARS` | `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `PWD`, `OLDPWD`, `TMPDIR`, `TMP`, `TEMP`, `PYTHONPATH`, `VIRTUAL_ENV`, `CONDA_PREFIX` |

List variables can be combined with patterns: `$PYPI_DOMAINS/*` expands to `pypi.org/*`, `files.pythonhosted.org/*`.

### Allowlist Behavior
All `allow_*` attributes consistently block when empty. Use variables to document what's being allowed:

| Attribute | Empty Behavior | Default |
|-----------|---------------|---------|
| `allow_read` | Block all | `$PWD`, `$PYTHON_STDLIB`, `$PYTHON_SITE_PACKAGES`, `$PYTHON_PLATLIB`, `$PIP_CACHE`, `$TMPDIR`, `$CACHE_HOME` |
| `allow_create` | Block all | `$PWD`, `$TMPDIR`, `$PIP_CACHE` |
| `allow_modify` | Block all | `$TMPDIR`, `$PIP_CACHE` |
| `allow_delete` | Block all | `$TMPDIR`, `$PIP_CACHE` |
| `allow_domains` | Block all | `$PYPI_DOMAINS` |
| `allow_ips` | Block all | `$LOCALHOST` |
| `allow_http_urls` | Block all | `$PYPI_DOMAINS/*` |
| `allow_http_methods` | Block all | `$ALL_HTTP_METHODS` |
| `allow_executables` | Block all | (none) |
| `allow_shell_commands` | Block all | (none) |
| `allow_env_var_reads` | Block all | `$SAFE_ENV_VARS` |

### Network Behavior
- Domains in `allow_domains` automatically permit their resolved IPs
- Direct IP access requires explicit `allow_ips` entries
- CIDR notation supported for IP ranges
- Port restrictions supported for both domains and IPs

### HTTP Request Interception

Supported libraries:
- `urllib.request` (stdlib)
- `http.client` (stdlib)
- `urllib3`
- `requests`
- `httpx`
- `aiohttp`

**URL allowlisting:**
- If `allow_http_urls` is empty, all HTTP requests are blocked
- Default uses `$PYPI_DOMAINS/*` to allow pip install
- Requests must match both domain AND URL pattern
- Scheme (`http://`, `https://`) is optional in patterns - omit to match both
- Glob patterns supported for paths: `api.example.com/v1/*`
- Subdomain matching: `example.com/api/*` matches `api.example.com/api/*`

**Method restrictions:**
- If `allow_http_methods` is empty, all HTTP requests are blocked
- Default uses `$ALL_HTTP_METHODS` to allow all standard methods
- If configured, only listed methods are permitted (e.g., `["GET", "HEAD"]`)

**Bypass note:** Raw socket HTTP requests bypass library hooks but are blocked by default (`allow_raw_sockets = false`). The `socket.connect` event still captures all connections at the network level.

### Hash Verification
Executables and files can include SHA256 hashes:
```toml
allow_executables = [
  { path = "/usr/bin/git", hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
]
```

## Information Events

Some operations are logged for auditing but never blocked. They help identify potentially suspicious behavior during program analysis:

### Encoding & Compression

| Event | Description | Example Output | Malware Indicator |
|-------|-------------|----------------|-------------------|
| `encoding.base64` | Base64 encode/decode | `Base64: b64encode` | Payload obfuscation |
| `encoding.hex` | Hex encode/decode | `Hex: hexlify` | Payload obfuscation |
| `encoding.zlib` | zlib compress/decompress | `Zlib: compress` | Packed payloads |
| `encoding.gzip` | gzip compress/decompress | `Gzip: compress` | Packed payloads |
| `encoding.bz2` | bz2 compress/decompress | `Bz2: compress` | Packed payloads |
| `encoding.lzma` | lzma/xz compress/decompress | `LZMA: compress` | Packed payloads |

### Cryptography

| Event | Description | Example Output | Malware Indicator |
|-------|-------------|----------------|-------------------|
| `crypto.cipher` | Low-level cipher ops | `Cipher: Encrypt` | Generic encryption |
| `crypto.fernet` | Fernet encryption | `Fernet: encrypt` | Symmetric encryption |
| `crypto.hmac` | HMAC keyed hashing | `HMAC: new` | C2 authentication |
| `crypto.rsa` | RSA key operations | `RSA: generate (2048 bits)` | Ransomware key exchange |
| `crypto.aes` | AES encryption | `AES: init (CBC)` | File encryption |
| `crypto.chacha20` | ChaCha20 encryption | `ChaCha20: init` | Modern symmetric encryption |
| `secrets.token` | Secure token generation | `SecureRandom: 32 bytes` | Key generation |

### Deserialization

| Event | Description | Example Output | Malware Indicator |
|-------|-------------|----------------|-------------------|
| `pickle.find_class` | Class during unpickling | `Pickle: builtins.list` | Code execution |
| `marshal.loads` | Loading bytecode | `Marshal: loads` | Bytecode injection |

### Archive Extraction

| Event | Description | Example Output | Malware Indicator |
|-------|-------------|----------------|-------------------|
| `shutil.unpack_archive` | Archive extraction | `Unpack: file.zip -> /tmp` | Zip bombs, path traversal |

### Environment

| Event | Description | Example Output | Malware Indicator |
|-------|-------------|----------------|-------------------|
| `os.putenv` | Set environment variable | `Set env var: PATH=/tmp` | Env manipulation |
| `os.unsetenv` | Unset environment variable | `Unset env var: DEBUG` | Env manipulation |


## Bypass Protection

- Blocks `sys.addaudithook` to prevent registering competing hooks
- Blocks `sys.settrace` and `sys.setprofile` to prevent debugger-based evasion
- Blocks `ctypes.dlopen` by default to prevent loading native code that bypasses hooks

## Limitations

- Audit hooks cannot be bypassed from Python, but native code can
- Here it is important to review which executables are allow-listed
