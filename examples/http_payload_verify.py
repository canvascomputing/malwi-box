"""Example: HTTP URL path restrictions and payload hash verification.

Tests the `allow_http_urls` and `allow_http_payload_hashes` config options.

Usage:
    # Will be blocked - URL path not in allow_http_urls
    uv run malwi-box run examples/http_payload_verify.py

    # Use review mode to allow interactively
    uv run malwi-box run --review examples/http_payload_verify.py

Config to allow URL paths:
    allow_domains = ["httpbin.org"]
    allow_http_urls = ["httpbin.org/get", "httpbin.org/bytes/*"]
    allow_http_methods = ["GET"]

Config to verify payload hash:
    allow_http_payload_hashes = [
      { url = "httpbin.org/bytes/16", hash = "sha256:..." },
    ]

Note: If allow_http_urls is empty, only domain-level checks apply.
When allow_http_urls is configured, requests must match both domain AND URL pattern.
"""

import hashlib
import urllib.request


def fetch_url(url: str) -> bytes:
    """Fetch content from a URL."""
    print(f"Fetching: {url}")
    with urllib.request.urlopen(url) as response:
        return response.read()


def main():
    # Example 1: Simple GET request - tests allow_urls
    print("=== Test 1: URL path allowlisting ===")
    url = "https://httpbin.org/get"
    try:
        content = fetch_url(url)
        print(f"Success! Response length: {len(content)} bytes\n")
    except Exception as e:
        print(f"Blocked or failed: {e}\n")

    # Example 2: Download binary data - tests allow_payload_hashes
    print("=== Test 2: Payload hash verification ===")
    url = "https://httpbin.org/bytes/16"
    try:
        content = fetch_url(url)
        actual_hash = hashlib.sha256(content).hexdigest()
        print(f"Success! Downloaded {len(content)} bytes")
        print(f"SHA256: {actual_hash}")
    except Exception as e:
        print(f"Blocked or failed: {e}")


if __name__ == "__main__":
    main()
