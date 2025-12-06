"""Example: Making network requests to external domains.

Tests the `allow_domains` config option.

Usage:
    # Will be blocked - httpbin.org is not in allow_domains
    uv run malwi-box run examples/network_request.py

    # Use review mode to allow interactively
    uv run malwi-box review examples/network_request.py

Config to allow:
    "allow_domains": ["httpbin.org"]

    Or with specific port:
    "allow_domains": ["httpbin.org:443"]

Note: PyPI domains (pypi.org, files.pythonhosted.org) are included
in allow_domains by default.
"""

import urllib.request


def fetch_url(url: str) -> str:
    """Fetch content from a URL."""
    print(f"Attempting to fetch: {url}")
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8")[:500]


def main():
    # This request should trigger a socket.connect audit event
    url = "https://httpbin.org/get"
    try:
        content = fetch_url(url)
        print(f"Response (first 500 chars):\n{content}")
    except Exception as e:
        print(f"Request failed: {e}")


if __name__ == "__main__":
    main()
