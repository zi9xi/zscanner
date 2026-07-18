import pytest

from zscanner.probe import grab_banner, read_banner


class FakeBannerSocket:
    def __init__(self, response: bytes = b"SSH-2.0-test\r\n") -> None:
        self.response = response
        self.sent: list[bytes] = []
        self.blocking: bool | None = None
        self.timeout: float | None = None

    def setblocking(self, value: bool) -> None:
        self.blocking = value

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)

    def recv(self, _size: int) -> bytes:
        return self.response


def test_read_banner_decodes_response() -> None:
    fake = FakeBannerSocket()

    banner = read_banner(fake)  # type: ignore[arg-type]

    assert banner.text == "SSH-2.0-test"
    assert banner.probe == "passive"
    assert fake.blocking is True


def test_read_banner_returns_empty_on_timeout() -> None:
    class TimeoutSocket(FakeBannerSocket):
        def recv(self, _size: int) -> bytes:
            raise TimeoutError

    assert read_banner(TimeoutSocket()).is_empty  # type: ignore[arg-type]


def test_read_banner_validates_timeout() -> None:
    with pytest.raises(ValueError, match="timeout"):
        read_banner(FakeBannerSocket(), timeout=0)  # type: ignore[arg-type]


def test_grab_banner_validation() -> None:
    with pytest.raises(ValueError, match="host"):
        grab_banner("", 80)
