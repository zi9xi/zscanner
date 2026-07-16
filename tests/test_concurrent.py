import threading
import time

import pytest

from zscanner.concurrent import ScanPool
from zscanner.scanner import ScanResult, scan


def result(port: int) -> ScanResult:
    return ScanResult("localhost", port, True, 1.0)


def test_pool_rejects_invalid_worker_count() -> None:
    with pytest.raises(ValueError, match="workers"):
        ScanPool(0)


def test_pool_returns_empty_result_without_threads() -> None:
    assert ScanPool(4).scan("localhost", []) == []


def test_pool_preserves_input_order(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_scan(_host: str, port: int, _timeout: float) -> ScanResult:
        time.sleep((4 - port) * 0.005)
        return result(port)

    monkeypatch.setattr("zscanner.scanner.scan_port", fake_scan)
    results = ScanPool(3).scan("localhost", [1, 2, 3])
    assert [item.port for item in results] == [1, 2, 3]


def test_pool_limits_concurrency(monkeypatch: pytest.MonkeyPatch) -> None:
    active = 0
    maximum = 0
    lock = threading.Lock()

    def fake_scan(_host: str, port: int, _timeout: float) -> ScanResult:
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return result(port)

    monkeypatch.setattr("zscanner.scanner.scan_port", fake_scan)
    ScanPool(2).scan("localhost", [1, 2, 3, 4])
    assert maximum == 2


def test_pool_propagates_worker_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_host: str, _port: int, _timeout: float) -> ScanResult:
        raise RuntimeError("worker failed")

    monkeypatch.setattr("zscanner.scanner.scan_port", fail)
    with pytest.raises(RuntimeError, match="worker failed"):
        ScanPool(2).scan("localhost", [80, 443])


def test_pool_propagates_callback_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "zscanner.scanner.scan_port", lambda _host, port, _timeout: result(port)
    )

    def fail(_result: ScanResult) -> None:
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="callback failed"):
        ScanPool(2, fail).scan("localhost", [80, 443])


@pytest.mark.parametrize("workers", [None, 1, 3])
def test_scan_reports_progress(monkeypatch: pytest.MonkeyPatch, workers: int | None) -> None:
    monkeypatch.setattr(
        "zscanner.scanner.scan_port", lambda _host, port, _timeout: result(port)
    )
    progress: list[tuple[int, int]] = []
    results = scan(
        "localhost",
        [3, 1, 2],
        workers=workers,
        on_progress=lambda done, total: progress.append((done, total)),
    )
    assert [item.port for item in results] == [3, 1, 2]
    assert sorted(progress) == [(1, 3), (2, 3), (3, 3)]


def test_scan_rejects_invalid_workers() -> None:
    with pytest.raises(ValueError, match="workers"):
        scan("localhost", [80], workers=0)
