"""Example: Loading shared libraries with ctypes.

Tests the `allow_executables` config option for ctypes.dlopen events.
Shared libraries (.so, .dylib, .dll) are controlled by the same config
as native executables.

Usage:
    # Will be blocked if allow_executables is configured and library not listed
    uv run malwi-box run examples/ctypes_dlopen.py

    # Use review mode to allow interactively
    uv run malwi-box run --review examples/ctypes_dlopen.py

Config to allow:
    "allow_executables": ["/usr/lib/libc.dylib"]

    Or allow a library directory:
    "allow_executables": ["/usr/lib"]

Note: ctypes.dlopen triggers the same allow_executables check as subprocess.
"""

import ctypes
import sys


def main():
    # Different library paths for different platforms
    if sys.platform == "darwin":
        libs = ["/usr/lib/libc.dylib", "/usr/lib/libSystem.B.dylib"]
    elif sys.platform.startswith("linux"):
        libs = ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]
    else:
        libs = ["msvcrt.dll"]

    for lib_path in libs:
        print(f"\nAttempting to load: {lib_path}")
        try:
            lib = ctypes.CDLL(lib_path)
            print(f"  Loaded successfully: {lib}")
        except OSError as e:
            print(f"  Failed to load: {e}")
        except Exception as e:
            print(f"  Error: {e}")


if __name__ == "__main__":
    main()
