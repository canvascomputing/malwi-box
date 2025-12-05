"""Example: Deleting files (future feature).

Tests the `allow_delete` config option.

Note: Delete permission checking is not yet implemented in the audit hook.
This example shows what will be possible once os.remove/os.unlink hooks are added.

Usage:
    # Currently runs without blocking (delete not hooked yet)
    uv run malwi-box run examples/file_delete.py

Config to allow (future):
    "allow_delete": ["/tmp"]
"""

import os


def main():
    filepath = "/tmp/malwi-box-test-delete.txt"

    # Create a test file
    print(f"Creating test file: {filepath}")
    with open(filepath, "w") as f:
        f.write("Delete me!\n")

    # Try to delete it
    print(f"Attempting to delete {filepath}...")
    try:
        os.remove(filepath)
        print("Successfully deleted the file")
    except Exception as e:
        print(f"Failed: {e}")

    # Verify
    if os.path.exists(filepath):
        print("File still exists (delete was blocked)")
        os.remove(filepath)  # Clean up
    else:
        print("File no longer exists")


if __name__ == "__main__":
    main()
