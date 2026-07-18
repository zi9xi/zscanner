"""Banner probing for open TCP services."""

import socket
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ServiceBanner:
    raw: bytes
    text: str
    probe: str | None = None
    truncated: bool = False

    @property
    def is_empty(self) -> bool:
        return not self.raw


_PROBES: tuple[tuple[bytes, str | None], ...] = (
    (b"", "passive"),
    (b"\r\n", "crlf"),
    (b"HEAD / HTTP/1.0\r\n\r\n", "http-head"),
)


def read_banner(sock: socket.socket, timeout: float = 1.0, max_bytes: int = 4096) -> ServiceBanner:
    """Read a service banner from a connected socket without raising."""
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if max_bytes < 1:
        raise ValueError("max_bytes must be at least 1")

    try:
        sock.setblocking(True)
        sock.settimeout(timeout)
    except OSError:
        return ServiceBanner(b"", "", None)

    for payload, probe_name in _PROBES:
        try:
            if payload:
                sock.sendall(payload)
            data = sock.recv(max_bytes)
        except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            continue
        if data:
            text = data.decode("utf-8", errors="replace").strip()
            return ServiceBanner(data, text[:512], probe_name, len(data) >= max_bytes)

    return ServiceBanner(b"", "", None)


def grab_banner(host: str, port: int, timeout: float = 1.0) -> ServiceBanner:
    """Connect to a TCP service and read its banner."""
    if not host.strip():
        raise ValueError("host cannot be empty")
    if not 1 <= port <= 65_535:
        raise ValueError("port must be between 1 and 65535")

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return read_banner(sock, timeout)
    except OSError:
        return ServiceBanner(b"", "", None)
