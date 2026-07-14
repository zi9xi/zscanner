import errno
import socket

import pytest

from zscanner import scanner
from zscanner.scanner import ScanResult, scan, scan_port


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


def test_scan_preserves_order(monkeypatch: pytest.MonkeyPatch) -> None:
    install_socket(monkeypatch, FakeSocket())
    results = scan("localhost", [443, 80], 0.2)
    assert [result.port for result in results] == [443, 80]
    assert all(isinstance(result, ScanResult) for result in results)


def test_scan_with_no_ports_returns_empty_list() -> None:
    assert scan("", []) == []
