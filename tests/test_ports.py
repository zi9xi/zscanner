from pathlib import Path

import pytest

from zscanner.ports import parse


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("80", [80]),
        ("443,80,80", [80, 443]),
        ("8000-8002", [8000, 8001, 8002]),
        ("22, 80, 8000-8002", [22, 80, 8000, 8001, 8002]),
    ],
)
def test_parse(value: str, expected: list[int]) -> None:
    assert parse(value) == expected


def test_parse_file(tmp_path: Path) -> None:
    port_file = tmp_path / "ports.txt"
    port_file.write_text("# common ports\n80,443\n\n8000-8002\n", encoding="utf-8")
    assert parse(f"@{port_file}") == [80, 443, 8000, 8001, 8002]


@pytest.mark.parametrize(
    "value",
    ["", "@", "80,", "abc", "90-80", "1-2-3", "0", "65536"],
)
def test_parse_rejects_invalid_values(value: str) -> None:
    with pytest.raises((ValueError, OSError)):
        parse(value)


def test_parse_missing_file() -> None:
    with pytest.raises(OSError):
        parse("@missing-ports-file.txt")
