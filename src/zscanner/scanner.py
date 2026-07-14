"""Simple cross-platform TCP Connect scanner."""

import errno
import select
import socket
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanResult:
    host: str
    port: int
    is_open: bool
    latency_ms: float
    error: str | None = None


_IN_PROGRESS = {
    errno.EINPROGRESS,
    errno.EWOULDBLOCK,
    errno.EALREADY,
    getattr(errno, "WSAEWOULDBLOCK", 10035),
}


def _connect_with_timeout(
    sock: socket.socket, address: tuple[str, int], timeout: float
) -> tuple[bool, str | None]:
    """Connect without blocking and wait for completion on Windows and Unix."""
    sock.setblocking(False)
    code = sock.connect_ex(address)
    if code == 0:
        return True, None
    if code not in _IN_PROGRESS:
        return False, str(code)

    _, writable, exceptional = select.select([], [sock], [sock], timeout)
    if not writable and not exceptional:
        return False, "timeout"

    error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    return (True, None) if error == 0 else (False, str(error))


def scan_port(host: str, port: int, timeout: float = 1.0) -> ScanResult:
    """Try to connect to one TCP port."""
    if not host.strip():
        raise ValueError("host cannot be empty")
    if not 1 <= port <= 65_535:
        raise ValueError("port must be between 1 and 65535")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    started = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            is_open, error = _connect_with_timeout(sock, (host, port), timeout)
    except OSError as exc:
        is_open = False
        error = str(exc)

    latency = (time.perf_counter() - started) * 1000
    return ScanResult(host, port, is_open, latency, error)


def scan(host: str, ports: list[int], timeout: float = 1.0) -> list[ScanResult]:
    """Scan ports in order. This loop can later be replaced by a thread pool."""
    return [scan_port(host, port, timeout) for port in ports]
