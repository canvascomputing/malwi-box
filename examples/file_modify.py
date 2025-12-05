"""Example: Modifying existing files outside allowed paths.

Tests the `allow_modify` config option.

Usage:
    # Will be blocked - /tmp is not in allow_modify by default
    uv run malwi-box run examples/file_modify.py

    # Use review mode to allow interactively
    uv run malwi-box review examples/file_modify.py

Config to allow:
    "allow_modify": ["/tmp/malwi-box-test-modify.txt"]

    Or with hash verification:
    "allow_modify": [{"path": "/tmp/malwi-box-test-modify.txt", "hash": "sha256:..."}]
"""

import os


def main():
    filepath = "/tmp/malwi-box-test-modify.txt"

    # First create the file (outside sandbox to set up test)
    print(f"Setting up: creating {filepath}...")
    with open(filepath, "w") as f:
        f.write("Original content\n")

    # Now try to modify it (this is what gets blocked)
    print(f"Attempting to modify {filepath}...")
    try:
        with open(filepath, "w") as f:
            f.write("Modified content\n")
        print(f"Successfully modified {filepath}")

        # Show the content
        with open(filepath) as f:
            print(f"New content: {f.read().strip()}")

        # Clean up
        os.remove(filepath)
        print("Cleaned up test file")
    except Exception as e:
        print(f"Failed: {e}")
        # Try to clean up anyway
        if os.path.exists(filepath):
            os.remove(filepath)


if __name__ == "__main__":
    main()
