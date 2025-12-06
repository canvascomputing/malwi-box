"""Example: Low-level os.exec* functions.

Tests the `allow_executables` config option for os.exec family of functions.
These are low-level POSIX functions that replace the current process.

Usage:
    # Will be blocked if allow_executables is configured and /bin/echo not listed
    uv run malwi-box run examples/os_exec.py

    # Use review mode to allow interactively
    uv run malwi-box run --review examples/os_exec.py

Config to allow:
    "allow_executables": ["/bin/echo"]

Note: os.exec* functions REPLACE the current process, so only one can run.
      This example uses os.fork() to demonstrate without terminating.
"""

import os
import sys


def main():
    print("Testing os.execv (low-level exec)")
    print("Note: os.exec* replaces the process, so we fork first\n")

    # Fork to avoid replacing the current process
    pid = os.fork()

    if pid == 0:
        # Child process - will be replaced by exec
        print("Child: About to exec /bin/echo...")
        try:
            os.execv("/bin/echo", ["/bin/echo", "Hello from exec!"])
        except Exception as e:
            print(f"Child: exec failed: {e}")
            sys.exit(1)
    else:
        # Parent process - wait for child
        _, status = os.waitpid(pid, 0)
        print(f"Parent: Child exited with status {status}")


if __name__ == "__main__":
    if sys.platform == "win32":
        print("This example requires Unix (fork/exec)")
    else:
        main()
