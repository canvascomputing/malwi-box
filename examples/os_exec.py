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
    # Fork to avoid replacing the current process
    pid = os.fork()

    if pid == 0:
        # Child process - will be replaced by exec
        try:
            os.execv("/bin/echo", ["/bin/echo", "Hello from exec!"])
        except Exception as e:
            print(f"exec failed: {e}")
            sys.exit(1)
    else:
        # Parent process - wait for child
        _, status = os.waitpid(pid, 0)
        exit_code = status >> 8
        if exit_code != 0:
            sys.exit(exit_code)


if __name__ == "__main__":
    if sys.platform == "win32":
        print("This example requires Unix (fork/exec)")
    else:
        main()
