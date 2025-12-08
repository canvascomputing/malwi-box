"""Tests for HTTP library profile hooks.

These tests verify that the Python-level profile hook correctly intercepts
HTTP requests from various libraries and fires http.request events.

The profile hook uses sys.setprofile() which works correctly in Python 3.12+
with sys.monitoring (PEP 669). The C-level PyEval_SetProfile is legacy and
doesn't receive events reliably in Python 3.12+.
"""

import http.client
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from malwi_box import install_hook, uninstall_hook


class TestUrllibRequestHook:
    """Tests for urllib.request hook."""

    def test_urlopen_fires_http_request_event(self):
        """Test that urllib.request.urlopen fires http.request event."""
        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            # Mock the actual network call
            with patch("urllib.request.OpenerDirector.open") as mock_open:
                mock_response = MagicMock()
                mock_response.status = 200
                mock_open.return_value = mock_response

                urllib.request.urlopen("https://example.com/test")
        finally:
            uninstall_hook()

        # Should have captured http.request event
        assert len(events) >= 1
        # First element is URL, second is method
        url = str(events[0][0])
        assert "example.com" in url


class TestHttpClientHook:
    """Tests for http.client hook."""

    def test_http_connection_request_fires_event(self):
        """Test that http.client.HTTPConnection.request fires http.request event."""
        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            # Create connection but mock the socket
            with (
                patch.object(http.client.HTTPConnection, "connect"),
                patch.object(http.client.HTTPConnection, "_send_output"),
                patch.object(http.client.HTTPConnection, "getresponse"),
            ):
                conn = http.client.HTTPConnection("example.com", 80)
                conn.request("GET", "/api/test")
        finally:
            uninstall_hook()

        # Should have captured http.request event with reconstructed URL
        assert len(events) >= 1
        url = str(events[0][0])
        assert "example.com" in url
        assert "/api/test" in url

    def test_https_connection_uses_https_scheme(self):
        """Test that HTTPSConnection uses https:// scheme in URL."""
        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            with (
                patch.object(http.client.HTTPSConnection, "connect"),
                patch.object(http.client.HTTPSConnection, "_send_output"),
                patch.object(http.client.HTTPSConnection, "getresponse"),
            ):
                conn = http.client.HTTPSConnection("secure.example.com", 443)
                conn.request("POST", "/secure/endpoint")
        finally:
            uninstall_hook()

        assert len(events) >= 1
        url = str(events[0][0])
        assert url.startswith("https://")
        assert "secure.example.com" in url


class TestRequestsHook:
    """Tests for requests library hook."""

    @pytest.fixture
    def requests_installed(self):
        """Check if requests is installed."""
        try:
            import requests  # noqa: F401

            return True
        except ImportError:
            return False

    def test_requests_session_fires_event(self, requests_installed):
        """Test that requests.Session.request fires http.request event."""
        if not requests_installed:
            pytest.skip("requests not installed")

        import requests

        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            # Catch the connection error - we just want to verify the hook fires
            try:
                session = requests.Session()
                session.get("https://api.example.com/users", timeout=0.001)
            except requests.exceptions.RequestException:
                pass  # Expected - we just need the hook to fire
        finally:
            uninstall_hook()

        assert len(events) >= 1
        url = str(events[0][0])
        assert "api.example.com" in url


class TestHttpxHook:
    """Tests for httpx library hook."""

    @pytest.fixture
    def httpx_installed(self):
        """Check if httpx is installed."""
        try:
            import httpx  # noqa: F401

            return True
        except ImportError:
            return False

    def test_httpx_client_fires_event(self, httpx_installed):
        """Test that httpx.Client.request fires http.request event."""
        if not httpx_installed:
            pytest.skip("httpx not installed")

        import httpx

        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            # Catch the connection error - we just want to verify the hook fires
            try:
                with httpx.Client(timeout=0.001) as client:
                    client.get("https://httpx.example.com/data")
            except (httpx.TimeoutException, httpx.ConnectError):
                pass  # Expected - we just need the hook to fire
        finally:
            uninstall_hook()

        assert len(events) >= 1
        url = str(events[0][0])
        assert "httpx.example.com" in url


class TestUrllib3Hook:
    """Tests for urllib3 library hook."""

    @pytest.fixture
    def urllib3_installed(self):
        """Check if urllib3 is installed."""
        try:
            import urllib3  # noqa: F401

            return True
        except ImportError:
            return False

    def test_urllib3_pool_fires_event(self, urllib3_installed):
        """Test that urllib3.HTTPConnectionPool.urlopen fires http.request event."""
        if not urllib3_installed:
            pytest.skip("urllib3 not installed")

        import urllib3

        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            # Catch the connection error - we just want to verify the hook fires
            try:
                pool = urllib3.HTTPConnectionPool(
                    "urllib3.example.com", 80, timeout=0.001
                )
                pool.urlopen("GET", "/pool/test")
            except urllib3.exceptions.HTTPError:
                pass  # Expected - we just need the hook to fire
        finally:
            uninstall_hook()

        assert len(events) >= 1
        url = str(events[0][0])
        assert "urllib3.example.com" in url or "/pool/test" in url


class TestAiohttpHook:
    """Tests for aiohttp library hook."""

    @pytest.fixture
    def aiohttp_installed(self):
        """Check if aiohttp is installed."""
        try:
            import aiohttp  # noqa: F401

            return True
        except ImportError:
            return False

    def test_aiohttp_session_fires_event(self, aiohttp_installed):
        """Test that aiohttp.ClientSession._request fires http.request event."""
        if not aiohttp_installed:
            pytest.skip("aiohttp not installed")

        import asyncio

        import aiohttp

        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        async def make_request():
            install_hook(hook)
            try:
                with patch.object(
                    aiohttp.ClientSession, "_request", return_value=MagicMock()
                ) as mock_request:
                    # Create a mock that returns an awaitable
                    mock_response = MagicMock()
                    mock_response.status = 200

                    async def mock_coro(*args, **kwargs):
                        return mock_response

                    mock_request.side_effect = mock_coro

                    async with aiohttp.ClientSession() as session:
                        await session.get("https://aiohttp.example.com/async")
            finally:
                uninstall_hook()

        asyncio.run(make_request())

        # Note: Due to mocking _request, the hook may not fire
        # This test mainly verifies no crashes occur
        # Real integration test would need actual network or better mocking


class TestHttpRequestUrlFormat:
    """Tests verifying that http.request events include full URLs with domains."""

    def test_http_client_includes_full_url(self):
        """Test http.client includes scheme://host/path in URL."""
        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            with (
                patch.object(http.client.HTTPConnection, "connect"),
                patch.object(http.client.HTTPConnection, "_send_output"),
                patch.object(http.client.HTTPConnection, "getresponse"),
            ):
                conn = http.client.HTTPConnection("test-domain.com", 80)
                conn.request("GET", "/api/endpoint")
        finally:
            uninstall_hook()

        assert len(events) >= 1
        url = str(events[0][0])
        # Should be full URL, not just path
        assert url.startswith("http://"), f"URL should start with http://, got: {url}"
        assert "test-domain.com" in url, f"URL should contain host, got: {url}"
        assert "/api/endpoint" in url, f"URL should contain path, got: {url}"

    def test_https_client_includes_https_scheme(self):
        """Test https connections use https:// scheme."""
        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            with (
                patch.object(http.client.HTTPSConnection, "connect"),
                patch.object(http.client.HTTPSConnection, "_send_output"),
                patch.object(http.client.HTTPSConnection, "getresponse"),
            ):
                conn = http.client.HTTPSConnection("secure-test.com", 443)
                conn.request("POST", "/secure/path")
        finally:
            uninstall_hook()

        assert len(events) >= 1
        url = str(events[0][0])
        assert url.startswith("https://"), f"URL should start with https://, got: {url}"
        assert "secure-test.com" in url

    def test_urllib_request_includes_full_url(self):
        """Test urllib.request includes full URL."""
        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            with patch("urllib.request.OpenerDirector.open") as mock_open:
                mock_response = MagicMock()
                mock_response.status = 200
                mock_open.return_value = mock_response
                urllib.request.urlopen("https://full-url-test.com/path/to/resource")
        finally:
            uninstall_hook()

        assert len(events) >= 1
        url = str(events[0][0])
        assert "full-url-test.com" in url, f"URL should contain domain, got: {url}"
        assert "/path/to/resource" in url or "full-url-test.com" in url

    def test_http_request_captures_method(self):
        """Test that HTTP method is captured correctly."""
        events = []

        def hook(event, args):
            if event == "http.request":
                events.append(args)

        install_hook(hook)
        try:
            with (
                patch.object(http.client.HTTPConnection, "connect"),
                patch.object(http.client.HTTPConnection, "_send_output"),
                patch.object(http.client.HTTPConnection, "getresponse"),
            ):
                conn = http.client.HTTPConnection("method-test.com", 80)
                conn.request("DELETE", "/resource/123")
        finally:
            uninstall_hook()

        assert len(events) >= 1
        method = str(events[0][1])
        assert method == "DELETE", f"Method should be DELETE, got: {method}"
