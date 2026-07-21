"""Lightweight HTTP probing helpers."""

import http.client
import ssl

from zscanner.profiles import HTTPS_PORTS, WEB_PORTS


def probe_http_server(host: str, port: int, timeout: float = 1.0) -> str | None:
    """Return the HTTP Server header for a web port, if one is available."""
    if not host.strip():
        raise ValueError("host cannot be empty")
    if port not in WEB_PORTS:
        return None
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    connection = _make_connection(host, port, timeout)
    try:
        connection.request("HEAD", "/", headers={"User-Agent": "zscanner"})
        response = connection.getresponse()
        server = response.getheader("Server")
        response.read()
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()
    return server.strip() if server else None


def _make_connection(
    host: str, port: int, timeout: float
) -> http.client.HTTPConnection | http.client.HTTPSConnection:
    if port in HTTPS_PORTS:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    return http.client.HTTPConnection(host, port, timeout=timeout)
