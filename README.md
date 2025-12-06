# malwi-box

Intercept, audit, and block critical Python operations at runtime.

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

## Configuration

Config file: `.malwi-box` (JSON)

```json
{
  "allow_read": ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"],
  "allow_create": ["$PWD"],
  "allow_modify": [],
  "allow_delete": [],
  "allow_domains": ["pypi.org", "files.pythonhosted.org"],
  "allow_ips": [],
  "allow_executables": [],
  "allow_shell_commands": []
}
```

### Path Variables
- `$PWD` - Working directory
- `$HOME` - User home
- `$TMPDIR` - Temp directory
- `$PYTHON_STDLIB` - Python standard library
- `$PYTHON_SITE_PACKAGES` - Installed packages

### Network
- Domains in `allow_domains` automatically permit their resolved IPs
- Direct IP access requires explicit `allow_ips` entries (CIDR supported)

### Executables
Entries can include SHA256 hashes for verification:
```json
{
  "allow_executables": [
    {"path": "/usr/bin/git", "hash": "sha256:abc123..."}
  ]
}
```

## Examples

### Analyze a suspicious package
```bash
# Create restrictive config
malwi-box config create
# Install with review - see exactly what it does
malwi-box install --review sketchy-package
```

### Run untrusted script with network restrictions
```bash
# Only allow specific API
cat > .malwi-box << 'EOF'
{
  "allow_read": ["$PWD", "$PYTHON_STDLIB", "$PYTHON_SITE_PACKAGES"],
  "allow_domains": ["api.example.com"],
  "allow_create": ["$PWD/output"]
}
EOF
malwi-box run untrusted_script.py
```

### Audit existing application
```bash
# Review mode shows all operations, you approve/deny each
malwi-box run --review myapp.py
# Approved operations are saved to .malwi-box for future runs
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
