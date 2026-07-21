import http.client

import pytest

from zscanner.http_probe import probe_http_server


class FakeResponse:
    def __init__(self, server: str | None = "nginx") -> None:
        self.server = server

    def getheader(self, name: str) -> str | None:
        return self.server if name == "Server" else None

    def read(self) -> bytes:
        return b""


class FakeConnection:
    def __init__(self, _host: str, _port: int, timeout: float, **_kwargs: object) -> None:
        self.timeout = timeout
        self.closed = False

    def request(self, _method: str, _path: str, headers: dict[str, str]) -> None:
        assert headers["User-Agent"] == "zscanner"

    def getresponse(self) -> FakeResponse:
        return FakeResponse()

    def close(self) -> None:
        self.closed = True


def test_probe_http_server_reads_server_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http.client, "HTTPConnection", FakeConnection)

    assert probe_http_server("127.0.0.1", 80) == "nginx"


def test_probe_http_server_supports_https_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConnection)

    assert probe_http_server("127.0.0.1", 443) == "nginx"


def test_probe_http_server_ignores_non_web_ports() -> None:
    assert probe_http_server("127.0.0.1", 22) is None


def test_probe_http_server_returns_none_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailingConnection(FakeConnection):
        def request(self, _method: str, _path: str, headers: dict[str, str]) -> None:
            raise http.client.HTTPException("bad response")

    monkeypatch.setattr(http.client, "HTTPConnection", FailingConnection)

    assert probe_http_server("127.0.0.1", 80) is None


def test_probe_http_server_validates_inputs() -> None:
    with pytest.raises(ValueError, match="host"):
        probe_http_server("", 80)
    with pytest.raises(ValueError, match="timeout"):
        probe_http_server("127.0.0.1", 80, timeout=0)
