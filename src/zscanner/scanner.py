"""Simple cross-platform TCP Connect scanner."""

import errno
import select
import socket
import threading
import time
from collections.abc import Callable
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


ProgressCallback = Callable[[int, int], None]


def scan(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int | None = None,
    on_progress: ProgressCallback | None = None,
) -> list[ScanResult]:
    """Scan ports sequentially or with a fixed number of worker threads."""
    if workers is not None and workers < 1:
        raise ValueError("workers must be at least 1")
    if workers in (None, 1):
        return _scan_sequential(host, ports, timeout, on_progress)

    from zscanner.concurrent import ScanPool

    done = 0
    lock = threading.Lock()
    total = len(ports)

    def report_progress(_result: ScanResult) -> None:
        nonlocal done
        with lock:
            done += 1
            if on_progress:
                on_progress(done, total)

    return ScanPool(workers, report_progress).scan(host, ports, timeout)


def _scan_sequential(
    host: str,
    ports: list[int],
    timeout: float,
    on_progress: ProgressCallback | None,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    total = len(ports)
    for done, port in enumerate(ports, 1):
        results.append(scan_port(host, port, timeout))
        if on_progress:
            on_progress(done, total)
    return results
