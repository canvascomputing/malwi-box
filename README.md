# malwi-box

A Python sandbox tool for security inspection using audit hooks. Built with a C++ extension that leverages Python's [PEP 578](https://peps.python.org/pep-0578/) runtime audit hook API to intercept and monitor security-sensitive operations.

## Features

- **Runtime audit monitoring** - Intercept all Python audit events (file access, code execution, imports, network operations, etc.)
- **C++ performance** - Native extension for minimal overhead on audit hook callbacks
- **Flexible callbacks** - Define custom Python callbacks to inspect, log, or block operations
- **CLI launcher** - Run any Python script with audit hooks automatically injected

## Installation

```bash
uv sync
```

## Usage

### CLI

Run a Python script with audit logging enabled:

```bash
malwi-box script.py [args...]
```

All audit events are logged to stderr:

```
[AUDIT] open: ('/path/to/file.py', 'r', 524288)
[AUDIT] compile: (None, '/path/to/file.py')
[AUDIT] exec: (<code object>,)
```

### Python API

Install custom hooks programmatically:

```python
from malwi_box import install_hook, uninstall_hook

def my_hook(event: str, args: tuple):
    print(f"[AUDIT] {event}: {args}")

install_hook(my_hook)
# ... your code ...
uninstall_hook()
```

## Defining Policies

Policies are Python functions that receive audit events and decide how to handle them. Here are common patterns:

### Logging Policy

Log all events for analysis:

```python
import sys

def logging_policy(event: str, args: tuple):
    print(f"[{event}] {args}", file=sys.stderr)
```

### Allowlist Policy

Only permit specific operations:

```python
ALLOWED_EVENTS = {"import", "compile"}

def allowlist_policy(event: str, args: tuple):
    if event not in ALLOWED_EVENTS:
        raise RuntimeError(f"Blocked event: {event}")
```

### File Access Policy

Restrict file system access to specific directories:

```python
from pathlib import Path

ALLOWED_PATHS = [Path("/tmp"), Path.home() / "safe_dir"]

def file_policy(event: str, args: tuple):
    if event == "open":
        path = Path(args[0]).resolve()
        if not any(path.is_relative_to(allowed) for allowed in ALLOWED_PATHS):
            raise PermissionError(f"Access denied: {path}")
```

### Network Policy

Block or monitor network operations:

```python
BLOCKED_HOSTS = {"malicious.com", "tracking.net"}

def network_policy(event: str, args: tuple):
    if event == "socket.connect":
        address = args[1]
        if isinstance(address, tuple) and address[0] in BLOCKED_HOSTS:
            raise ConnectionError(f"Blocked connection to: {address[0]}")
```

### Combined Policy

Compose multiple policies:

```python
def combined_policy(event: str, args: tuple):
    logging_policy(event, args)
    file_policy(event, args)
    network_policy(event, args)

install_hook(combined_policy)
```

## Common Audit Events

| Event | Description | Args |
|-------|-------------|------|
| `open` | File open | `(path, mode, flags)` |
| `exec` | Code execution | `(code_object,)` |
| `import` | Module import | `(module, filename, sys.path, sys.meta_path, sys.path_hooks)` |
| `compile` | Code compilation | `(source, filename)` |
| `socket.connect` | Network connection | `(socket, address)` |
| `subprocess.Popen` | Process spawn | `(executable, args, cwd, env)` |
| `ctypes.dlopen` | Load shared library | `(name,)` |

See the [full audit events table](https://docs.python.org/3/library/audit_events.html) for all available events.

## Limitations

- Audit hooks cannot be removed once registered (PEP 578 design). Use `uninstall_hook()` to disable the callback while keeping the hook registered.
- Some C extension modules may not emit all expected audit events.
- Requires Python 3.10+.

## License

MIT
