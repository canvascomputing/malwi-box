"""Example: Creating files outside allowed paths.

Tests the `allow_create` config option.

Usage:
    # Will be blocked - /tmp is not in allow_create by default
    uv run malwi-box run examples/file_create.py

    # Use review mode to allow interactively
    uv run malwi-box review examples/file_create.py

Config to allow:
    "allow_create": ["/tmp"]
"""

import os


def main():
    # Use a file in /tmp which is outside the default allow_create
    filepath = "/tmp/malwi-box-test-create.txt"

    print(f"Attempting to create {filepath}...")
    try:
        with open(filepath, "w") as f:
            f.write("Hello from malwi-box!\n")
        print(f"Successfully created {filepath}")

        # Clean up
        os.remove(filepath)
        print("Cleaned up test file")
    except Exception as e:
        print(f"Failed: {e}")


if __name__ == "__main__":
    main()
