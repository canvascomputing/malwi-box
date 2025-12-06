"""Example: Executable control with allow_executables.

Tests the `allow_executables` config option which controls what native binaries
can be executed via subprocess.Popen, os.exec, os.spawn, os.posix_spawn, and
ctypes.dlopen.

Usage:
    # Will be blocked - default config has allow_executables: []
    uv run malwi-box run examples/executable_control.py

    # Use review mode to allow interactively
    uv run malwi-box run --review examples/executable_control.py

Config examples:
    # Block all executables (default)
    "allow_executables": []

    # Allow ALL executables (use "*" glob pattern)
    "allow_executables": ["*"]

    # Allow specific executables
    "allow_executables": ["/bin/ls", "/usr/bin/git"]

    # Allow with hash verification
    "allow_executables": [
        {"path": "/bin/ls", "hash": "sha256:abc123..."}
    ]

    # Allow all executables in a directory (glob pattern)
    "allow_executables": ["/usr/bin/*", "$PWD/.venv/bin/*"]

    # Allow with path variables
    "allow_executables": ["$PYTHON_PREFIX/bin/python"]

Glob patterns:
    - "*" matches any path (allows ALL executables)
    - "/usr/bin/*" matches any executable in /usr/bin/
    - "$PWD/.venv/bin/*" matches any executable in your project's venv
"""

import subprocess


def main():
    executables = ["/bin/ls", "/bin/echo", "/usr/bin/env"]

    for exe in executables:
        print(f"\nAttempting to run: {exe}")
        try:
            result = subprocess.run([exe, "--version"], capture_output=True, text=True)
            print(f"  Exit code: {result.returncode}")
            output = result.stdout or result.stderr
            print(f"  Output: {output[:100].strip()}")
        except FileNotFoundError:
            print(f"  Not found: {exe}")
        except Exception as e:
            print(f"  Failed: {e}")


if __name__ == "__main__":
    main()
