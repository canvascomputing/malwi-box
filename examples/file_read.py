"""Example: Reading files outside allowed paths.

Tests the `allow_read` config option.

Usage:
    # Will be blocked - /etc/passwd is not in allow_read
    uv run malwi-box run examples/file_read.py

    # Use review mode to allow interactively
    uv run malwi-box review examples/file_read.py

Config to allow:
    "allow_read": ["/etc/passwd"]
"""


def main():
    print("Attempting to read /etc/passwd...")
    try:
        with open("/etc/passwd") as f:
            content = f.read()
        print(f"Read {len(content)} bytes")
        print("First 200 chars:")
        print(content[:200])
    except Exception as e:
        print(f"Failed: {e}")


if __name__ == "__main__":
    main()
