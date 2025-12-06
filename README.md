<p align="center">
  <img src="malwi-box.png" alt="malwi-box logo" width="200">
</p>

<h1 align="center">malwi-box</h1>

<p align="center">
  <em>Intercept, audit, and block critical Python operations at runtime.</em>
</p>

## Use Cases

- **Malware analysis** - Observe and restrict what suspicious Python code attempts to do
- **Supply chain security** - Audit what packages access during installation
- **Critical systems** - Enforce least-privilege access for Python scripts

> **Note**: This is an observation/enforcement layer, not a full sandbox. Run in an isolated environment (VM/container) for analyzing truly malicious code.

## Quick Start

```bash
# Create default config
malwi-box config create

# Run script with enforcement
malwi-box run script.py

# Interactive review mode - approve/deny each operation
malwi-box run --review script.py

# Sandboxed pip install
malwi-box install requests
```

## Examples

### Analyze a suspicious package
```bash
malwi-box config create
malwi-box install --review sketchy-package
```

### Build script with no network access
```bash
cat > .malwi-box.yaml << 'EOF'
allow_read:
  - $PWD
  - $PYTHON_STDLIB
  - $PYTHON_SITE_PACKAGES
allow_create:
  - $PWD/dist
  - $PWD/build
allow_modify:
  - $PWD/dist
  - $PWD/build
allow_domains: []
allow_executables:
  - $PWD/.venv/bin/*
EOF
malwi-box run build.py
```

### API client with single allowed endpoint
```bash
cat > .malwi-box.yaml << 'EOF'
allow_read:
  - $PWD
  - $PYTHON_STDLIB
  - $PYTHON_SITE_PACKAGES
allow_domains:
  - api.example.com:443
allow_create:
  - $PWD/data
EOF
malwi-box run fetch_data.py
```

### Audit existing application
```bash
# Review mode shows all operations, you approve/deny each
malwi-box run --review myapp.py
# Approved operations are saved to .malwi-box.yaml for future runs
```

### Run git commands only
```bash
cat > .malwi-box.yaml << 'EOF'
allow_read:
  - $PWD
  - $PYTHON_STDLIB
  - $PYTHON_SITE_PACKAGES
  - $HOME/.gitconfig
allow_create:
  - $PWD
allow_modify:
  - $PWD
allow_domains:
  - github.com
  - gitlab.com
allow_executables:
  - path: /usr/bin/git
    hash: sha256:...  # pin to specific binary
allow_shell_commands:
  - /usr/bin/git *
EOF
malwi-box run git_automation.py
```

## Configuration Reference

Config file: `.malwi-box.yaml`

```yaml
# File access permissions
allow_read:
  - $PWD                      # working directory
  - $PYTHON_STDLIB            # Python standard library
  - $PYTHON_SITE_PACKAGES     # installed packages
  - $HOME/.config/myapp       # specific config directory
  - /etc/hosts                # specific file

allow_create:
  - $PWD                      # allow creating files in workdir
  - $TMPDIR                   # allow temp files

allow_modify:
  - $PWD/data                 # only modify files in data/
  - path: /etc/myapp.conf     # modify specific file
    hash: sha256:abc123...    # only if hash matches

allow_delete: []              # no deletions allowed

# Network permissions
allow_domains:
  - pypi.org                  # allow any port
  - files.pythonhosted.org
  - api.example.com:443       # restrict to specific port

allow_ips:
  - 10.0.0.0/8                # CIDR notation
  - 192.168.1.100:8080        # specific IP:port
  - "[::1]:443"               # IPv6 with port

# Process execution
allow_executables:
  - /usr/bin/git              # allow by path
  - $PWD/.venv/bin/*          # glob pattern
  - path: /usr/bin/curl       # with hash verification
    hash: sha256:abc123...

allow_shell_commands:
  - /usr/bin/git *            # glob pattern matching
  - /usr/bin/curl *

# Environment variables
allow_env_var_reads: []       # restrict env access
allow_env_var_writes:
  - PATH
  - PYTHONPATH
```

### Path Variables
| Variable | Description |
|----------|-------------|
| `$PWD` | Working directory |
| `$HOME` | User home directory |
| `$TMPDIR` | System temp directory |
| `$PYTHON_STDLIB` | Python standard library |
| `$PYTHON_SITE_PACKAGES` | Installed packages |
| `$PYTHON_PLATLIB` | Platform-specific packages |
| `$PYTHON_PREFIX` | Python installation prefix |
| `$ENV{VAR}` | Any environment variable |

### Network Behavior
- Domains in `allow_domains` automatically permit their resolved IPs
- Direct IP access requires explicit `allow_ips` entries
- CIDR notation supported for IP ranges
- Port restrictions supported for both domains and IPs

### Hash Verification
Executables and files can include SHA256 hashes:
```yaml
allow_executables:
  - path: /usr/bin/git
    hash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
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
