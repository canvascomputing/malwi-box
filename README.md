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

## Use Cases

- 🔬 **Malware analysis** - Safely detonate suspicious Python code and observe its behavior
- 📦 **Dependency auditing** - Discover what file, network, and process access a package actually needs
- 🔒 **Runtime protection** - Enforce allowlists to block unauthorized operations in production

> **Warning**: This tool is not a sandbox with isolated execution, it runs on your actual machine, kernel and CPU. Use at your own risk.

## Installation

```bash
pip install malwi-box
```

Or with uv:
```bash
uv tool install malwi-box
```

## Commands

| Command | Description |
|---------|-------------|
| `malwi-box run script.py` | Block operations not allowed in `.malwi-box.toml` |
| `malwi-box run --review script.py` | Approve/deny each operation, save to config |
| `malwi-box run --force script.py` | Log violations without blocking |
| `malwi-box install package` | Install pip package with config restrictions |
| `malwi-box config create` | Create default `.malwi-box.toml` |

## Quick Start

```bash
malwi-box config create
malwi-box run script.py
```

## Examples

### Audit a suspicious package
```bash
malwi-box install --review sketchy-package
```

### Allow network access
```bash
malwi-box run examples/network_request.py
```
`.malwi-box.toml`:
```toml
allow_domains = ["httpbin.org"]
```

### Allow file reads
```bash
malwi-box run examples/file_read.py
```
`.malwi-box.toml`:
```toml
allow_read = ["/etc/passwd"]
```

### Allow shell commands
```bash
malwi-box run examples/system_command.py
```
`.malwi-box.toml`:
```toml
allow_shell_commands = ["/bin/ls *"]
```

### Allow executables
```bash
malwi-box run examples/executable_control.py
```
`.malwi-box.toml`:
```toml
allow_executables = [
  "/usr/bin/echo",
  { path = "/usr/bin/git", hash = "sha256:e3b0c44..." },
]
```

### Review mode
```bash
malwi-box run --review examples/network_request.py
# 'y' to approve, 'n' to deny, 'i' to inspect call stack
# Approved operations saved to .malwi-box.toml
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
- Process execution (`subprocess.Popen`, `os.exec*`, `os.system`)
- Library loading (`ctypes.dlopen`)

**Protections against bypass:**
- Blocks `sys.addaudithook` to prevent registering competing hooks
- Blocks `sys.settrace` and `sys.setprofile` to prevent debugger-based evasion
- Blocks `ctypes.dlopen` by default to prevent loading native code that bypasses hooks

Blocked operations terminate immediately with exit code 78.

## Limitations

- Audit hooks cannot be bypassed from Python, but native code can
- `ctypes.dlopen` is blocked by default to prevent native bypasses
- Requires Python 3.10+
