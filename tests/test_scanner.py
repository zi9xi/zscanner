import errno
import socket

import pytest

from zscanner import scanner
from zscanner.scanner import (
    ScanOptions,
    ScanResult,
    open_only,
    scan,
    scan_many,
    scan_port,
    scan_web_targets,
)


class FakeSocket:
    def __init__(self, code: int = 0, socket_error: int = 0) -> None:
        self.code = code
        self.socket_error = socket_error
        self.blocking: bool | None = None
        self.address: tuple[str, int] | None = None

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def setblocking(self, blocking: bool) -> None:
        self.blocking = blocking

    def connect_ex(self, address: tuple[str, int]) -> int:
        self.address = address
        return self.code

    def getsockopt(self, _level: int, _option: int) -> int:
        return self.socket_error


def install_socket(monkeypatch: pytest.MonkeyPatch, fake: FakeSocket) -> None:
    monkeypatch.setattr(socket, "socket", lambda *_args: fake)


def test_scan_port_open(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeSocket()
    install_socket(monkeypatch, fake)
    result = scan_port("127.0.0.1", 80, 0.5)
    assert result.is_open is True
    assert result.error is None
    assert result.latency_ms >= 0
    assert fake.blocking is False
    assert fake.address == ("127.0.0.1", 80)


def test_scan_port_uses_banner_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    install_socket(monkeypatch, FakeSocket())
    monkeypatch.setattr(
        "zscanner.scanner._grab_banner",
        lambda _host, _port, _sock, _timeout: "nginx",
    )

    result = scan_port("127.0.0.1", 80, 0.5, grab_banner=True, banner_timeout=0.2)

    assert result.banner == "nginx"
    assert result.service == "http"


def test_scan_result_as_dict() -> None:
    result = ScanResult("localhost", 80, True, 1.25, service="http")

    assert result.as_dict() == {
        "host": "localhost",
        "port": 80,
        "is_open": True,
        "latency_ms": 1.25,
        "error": None,
        "service": "http",
        "banner": None,
    }


def test_scan_port_handles_immediate_error(monkeypatch: pytest.MonkeyPatch) -> None:
    install_socket(monkeypatch, FakeSocket(10061))
    result = scan_port("localhost", 443)
    assert result.is_open is False
    assert result.error == "10061"


@pytest.mark.parametrize("code", [10035, errno.EINPROGRESS])
def test_in_progress_connection_can_open(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    fake = FakeSocket(code)
    monkeypatch.setattr(scanner.select, "select", lambda *_args: ([], [fake], []))
    result = scanner._connect_with_timeout(fake, ("localhost", 80), 0.5)  # type: ignore[arg-type]
    assert result == (True, None)


def test_in_progress_connection_can_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeSocket(10035, 10061)
    monkeypatch.setattr(scanner.select, "select", lambda *_args: ([], [fake], []))
    result = scanner._connect_with_timeout(fake, ("localhost", 80), 0.5)  # type: ignore[arg-type]
    assert result == (False, "10061")


def test_in_progress_connection_can_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeSocket(10035)
    monkeypatch.setattr(scanner.select, "select", lambda *_args: ([], [], []))
    result = scanner._connect_with_timeout(fake, ("localhost", 80), 0.5)  # type: ignore[arg-type]
    assert result == (False, "timeout")


@pytest.mark.parametrize(
    ("host", "port", "timeout", "message"),
    [
        ("", 80, 1.0, "host cannot be empty"),
        ("localhost", 0, 1.0, "port must be between"),
        ("localhost", 65_536, 1.0, "port must be between"),
        ("localhost", 80, 0, "timeout must be greater"),
    ],
)
def test_scan_port_validation(host: str, port: int, timeout: float, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        scan_port(host, port, timeout)


def test_scan_port_rejects_invalid_banner_timeout() -> None:
    with pytest.raises(ValueError, match="banner_timeout"):
        scan_port("localhost", 80, banner_timeout=0)


def test_scan_preserves_order(monkeypatch: pytest.MonkeyPatch) -> None:
    install_socket(monkeypatch, FakeSocket())
    results = scan("localhost", [443, 80], 0.2)
    assert [result.port for result in results] == [443, 80]
    assert all(isinstance(result, ScanResult) for result in results)


def test_scan_with_no_ports_returns_empty_list() -> None:
    assert scan("", []) == []


def test_scan_many_preserves_target_then_port_order(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "zscanner.scanner.scan_port",
        lambda host, port, _timeout: result(host, port),
    )

    results = scan_many(["host-a", "host-b"], [80, 443], ScanOptions(workers=1))

    assert [(item.host, item.port) for item in results] == [
        ("host-a", 80),
        ("host-a", 443),
        ("host-b", 80),
        ("host-b", 443),
    ]


def test_scan_many_rejects_excessive_task_count() -> None:
    with pytest.raises(ValueError, match="task count"):
        scan_many(["a", "b"], [80, 443], ScanOptions(max_tasks=3))


def test_scan_many_rejects_invalid_banner_timeout() -> None:
    with pytest.raises(ValueError, match="banner_timeout"):
        scan_many(["localhost"], [80], ScanOptions(banner_timeout=0))


def test_open_only_filters_closed_results() -> None:
    results = [
        ScanResult("localhost", 80, True, 1.0),
        ScanResult("localhost", 81, False, 1.0),
    ]

    assert open_only(results) == [results[0]]


def test_scan_web_targets_uses_web_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[tuple[list[str], list[int], ScanOptions | None]] = []

    def fake_scan_many(
        targets: list[str],
        ports: list[int],
        options: ScanOptions | None = None,
        *_args: object,
        **_kwargs: object,
    ) -> list[ScanResult]:
        received.append((targets, ports, options))
        return []

    monkeypatch.setattr("zscanner.scanner.scan_many", fake_scan_many)

    assert scan_web_targets(["localhost"]) == []
    targets, ports, options = received[0]
    assert targets == ["localhost"]
    assert ports[:4] == [80, 443, 8080, 8443]
    assert options == ScanOptions(workers=50, identify_service=True, grab_banner=True)


def result(host: str, port: int) -> ScanResult:
    return ScanResult(host, port, True, 1.0)
