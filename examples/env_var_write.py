"""Example: Writing environment variables.

Tests the `allow_env_var_writes` config option.

Usage:
    # Will be blocked - MY_SECRET is not in allow_env_var_writes
    uv run malwi-box run examples/env_var_write.py

    # Use review mode to allow interactively
    uv run malwi-box review examples/env_var_write.py

Config to allow:
    "allow_env_var_writes": ["MY_SECRET", "MY_CONFIG"]
"""

import os


def main():
    key = "MY_SECRET"
    value = "super-secret-value"

    print(f"Attempting to set {key}={value}")
    try:
        os.environ[key] = value
        print(f"Successfully set {key}")
        print(f"Verify: {key}={os.environ.get(key)}")

        # Clean up
        del os.environ[key]
        print(f"Cleaned up {key}")
    except Exception as e:
        print(f"Failed: {e}")


if __name__ == "__main__":
    main()
