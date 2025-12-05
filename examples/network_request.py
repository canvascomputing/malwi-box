"""Example script that makes a network request.

This can be used to test the review command's ability to block network access.

Usage:
    # Run with review mode to interactively approve/deny the request
    uv run malwi-box review examples/network_request.py

    # Run normally - will be blocked because httpbin.org is not PyPI
    # and no other hosts are allowed by default
    uv run malwi-box run examples/network_request.py

Expected behavior:
    - In review mode: You'll be prompted to allow the socket.connect event
    - In run mode: The request will be blocked with exit code 78

The default config only allows connections to PyPI hosts (pypi.org,
files.pythonhosted.org). All other network requests are blocked.
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
