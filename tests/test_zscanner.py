import pytest

from zscanner.cli import parse_ports
from zscanner.scanner import scan_port


def test_parse_ports() -> None:
    assert parse_ports("443,80,80,8000-8002") == [80, 443, 8000, 8001, 8002]


@pytest.mark.parametrize("value", ["", "0", "65536", "90-80", "abc", "1,"])
def test_invalid_ports(value: str) -> None:
    with pytest.raises(ValueError):
        parse_ports(value)


def test_scan_port_rejects_invalid_port() -> None:
    with pytest.raises(ValueError):
        scan_port("localhost", 0)
