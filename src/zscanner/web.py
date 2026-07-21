"""Helpers for working with web scan results."""

from zscanner.profiles import HTTPS_PORTS, WEB_PORTS
from zscanner.scanner import ScanResult


def result_to_url(result: ScanResult) -> str | None:
    """Return a URL for an open web scan result."""
    if not result.is_open or result.port not in WEB_PORTS:
        return None
    scheme = "https" if result.port in HTTPS_PORTS else "http"
    if (scheme, result.port) in {("http", 80), ("https", 443)}:
        return f"{scheme}://{result.host}"
    return f"{scheme}://{result.host}:{result.port}"
