"""Cross-platform TCP Connect scanner."""

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
    service: str | None = None
    banner: str | None = None


@dataclass(frozen=True, slots=True)
class ScanOptions:
    timeout: float = 1.0
    workers: int | None = None
    identify_service: bool = False
    grab_banner: bool = False
    max_tasks: int | None = 10_000


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


def scan_port(
    host: str,
    port: int,
    timeout: float = 1.0,
    *,
    identify_service: bool = False,
    grab_banner: bool = False,
) -> ScanResult:
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
            banner = None
            if is_open and grab_banner:
                from zscanner.probe import read_banner

                banner_result = read_banner(sock, timeout)
                banner = banner_result.text
    except OSError as exc:
        is_open = False
        error = str(exc)
        banner = None

    latency = (time.perf_counter() - started) * 1000
    service = None
    if identify_service or grab_banner:
        from zscanner.fingerprint import guess_short

        service = guess_short(port)
    return ScanResult(host, port, is_open, latency, error, service, banner)


ProgressCallback = Callable[[int, int], None]
ScanTask = tuple[str, int]


def scan(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int | None = None,
    on_progress: ProgressCallback | None = None,
    *,
    identify_service: bool = False,
    grab_banner: bool = False,
) -> list[ScanResult]:
    """Scan ports sequentially or with a fixed number of worker threads."""
    options = ScanOptions(
        timeout=timeout,
        workers=workers,
        identify_service=identify_service,
        grab_banner=grab_banner,
    )
    return scan_many(
        [host],
        ports,
        options,
        on_progress=on_progress,
    )


def scan_many(
    targets: list[str],
    ports: list[int],
    options: ScanOptions | None = None,
    on_progress: ProgressCallback | None = None,
) -> list[ScanResult]:
    """Scan multiple targets and ports in stable target-then-port order."""
    options = options or ScanOptions()
    _validate_options(options)
    scan_tasks = _build_scan_tasks(targets, ports, options.max_tasks)

    if options.workers in (None, 1):
        return _scan_sequential(scan_tasks, options, on_progress)

    from zscanner.concurrent import ScanPool

    done = 0
    lock = threading.Lock()
    total = len(scan_tasks)

    def report_progress(_result: ScanResult) -> None:
        nonlocal done
        with lock:
            done += 1
            if on_progress:
                on_progress(done, total)

    return ScanPool(options.workers, report_progress).scan_tasks(
        scan_tasks,
        options.timeout,
        _make_port_scanner(options),
    )


def _validate_options(options: ScanOptions) -> None:
    if options.workers is not None and options.workers < 1:
        raise ValueError("workers must be at least 1")
    if options.max_tasks is not None and options.max_tasks < 1:
        raise ValueError("max_tasks must be at least 1")
    if options.timeout <= 0:
        raise ValueError("timeout must be greater than zero")


def _make_port_scanner(options: ScanOptions) -> Callable[[str, int, float], ScanResult] | None:
    if not options.identify_service and not options.grab_banner:
        return None

    def scan_one(task_host: str, port: int, task_timeout: float) -> ScanResult:
        return scan_port(
            task_host,
            port,
            task_timeout,
            identify_service=options.identify_service,
            grab_banner=options.grab_banner,
        )

    return scan_one


def _build_scan_tasks(
    targets: list[str], ports: list[int], max_tasks: int | None
) -> list[ScanTask]:
    if not targets or not ports:
        return []
    if any(not target.strip() for target in targets):
        raise ValueError("target cannot be empty")

    total = len(targets) * len(ports)
    if max_tasks is not None and total > max_tasks:
        raise ValueError(f"scan task count exceeds limit: {max_tasks}")
    return [(target, port) for target in targets for port in ports]


def _scan_sequential(
    scan_tasks: list[ScanTask],
    options: ScanOptions,
    on_progress: ProgressCallback | None,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    total = len(scan_tasks)
    scan_one = _make_port_scanner(options) or scan_port
    for done, (host, port) in enumerate(scan_tasks, 1):
        result = scan_one(host, port, options.timeout)
        results.append(result)
        if on_progress:
            on_progress(done, total)
    return results
