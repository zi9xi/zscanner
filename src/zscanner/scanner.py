"""Simple TCP Connect scanner built with sockets."""

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
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
        error = None if code == 0 else str(code)
        is_open = code == 0
    except OSError as exc:
        is_open = False
        error = str(exc)

    return ScanResult(host, port, is_open, (time.perf_counter() - started) * 1000, error)


def scan(host: str, ports: list[int], timeout: float = 1.0) -> list[ScanResult]:
    """Scan ports in order. This loop can later be replaced by a thread pool."""
    return [scan_port(host, port, timeout) for port in ports]
