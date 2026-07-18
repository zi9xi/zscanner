from pathlib import Path

import pytest

from zscanner.targets import parse


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("127.0.0.1", ["127.0.0.1"]),
        ("example.com,127.0.0.1,example.com", ["example.com", "127.0.0.1"]),
        ("192.168.1.0/30", ["192.168.1.1", "192.168.1.2"]),
    ],
)
def test_parse_targets(value: str, expected: list[str]) -> None:
    assert parse(value) == expected


def test_parse_targets_file(tmp_path: Path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("# lab targets\n127.0.0.1\n192.168.1.0/30\n", encoding="utf-8")

    assert parse(f"@{target_file}") == ["127.0.0.1", "192.168.1.1", "192.168.1.2"]


@pytest.mark.parametrize("value", ["", " ", "@", "127.0.0.1,", "192.168.1.0/bad"])
def test_parse_targets_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        parse(value)


def test_parse_targets_rejects_excessive_target_count() -> None:
    with pytest.raises(ValueError, match="target count"):
        parse("192.168.1.0/24", max_targets=2)


def test_parse_targets_rejects_invalid_limit() -> None:
    with pytest.raises(ValueError, match="max_targets"):
        parse("127.0.0.1", max_targets=0)
