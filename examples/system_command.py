"""Example: Running system commands.

Tests the `allow_system_commands` config option.

Usage:
    # Will be blocked - ls is not in allow_system_commands
    uv run malwi-box run examples/system_command.py

    # Use review mode to allow interactively
    uv run malwi-box review examples/system_command.py

Config to allow:
    "allow_system_commands": ["ls *"]

    Or more specific:
    "allow_system_commands": ["/bin/ls -la /tmp"]

Note: Patterns use glob matching (fnmatch).
"""

import subprocess


def main():
    cmd = ["ls", "-la", "/tmp"]
    print(f"Attempting to run: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(f"Exit code: {result.returncode}")
        print(f"Output:\n{result.stdout[:500]}")
    except Exception as e:
        print(f"Failed: {e}")


if __name__ == "__main__":
    main()
