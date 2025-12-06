"""Example: Running shell commands.

Tests the `allow_shell_commands` config option which controls what shell
commands can be executed via subprocess.Popen and os.system.

Usage:
    # Will be blocked - default config has allow_shell_commands: []
    uv run malwi-box run examples/system_command.py

    # Use review mode to allow interactively
    uv run malwi-box run --review examples/system_command.py

Config examples:
    # Block all shell commands (default)
    "allow_shell_commands": []

    # Allow ALL shell commands (use "*" glob pattern)
    "allow_shell_commands": ["*"]

    # Allow specific commands
    "allow_shell_commands": ["ls *", "git status"]

    # Allow with exact arguments
    "allow_shell_commands": ["/bin/ls -la /tmp"]

Glob patterns:
    - "*" matches any command (allows ALL shell commands)
    - "ls *" matches any ls command with any arguments
    - "git *" matches any git command
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
