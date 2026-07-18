import pytest

from zscanner import cli
from zscanner.scanner import ScanResult


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("80", [80]),
        ("22,80,443", [22, 80, 443]),
        ("80, 443,8000-8002", [80, 443, 8000, 8001, 8002]),
        ("80,80", [80]),
    ],
)
def test_parse_ports(value: str, expected: list[int]) -> None:
    assert cli.parse_ports(value) == expected


@pytest.mark.parametrize("value", ["", " ", "0", "65536", "90-80", "abc", "1--2", "80,"])
def test_parse_ports_rejects_invalid_input(value: str) -> None:
    with pytest.raises(ValueError):
        cli.parse_ports(value)


def test_main_prints_results(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli,
        "scan",
        lambda *_args, **_kwargs: [
            ScanResult("localhost", 80, True, 0.5),
            ScanResult("localhost", 81, False, 0.7, "refused"),
        ],
    )
    assert cli.main(["localhost", "-p", "80-81", "--all"]) == 0
    captured = capsys.readouterr()
    output = captured.out
    assert "only scan devices you own" in captured.err
    assert "80/tcp" in output and "open" in output
    assert "81/tcp" in output and "closed" in output
    assert "Open ports: 1" in output


def test_main_reports_invalid_arguments() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["localhost", "-p", "invalid"])
    assert exc.value.code == 2


def test_main_forwards_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[int | None] = []

    def fake_scan(
        _host: str,
        _ports: list[int],
        _timeout: float,
        workers: int | None,
        **_kwargs: object,
    ) -> list[ScanResult]:
        received.append(workers)
        return []

    monkeypatch.setattr(cli, "scan", fake_scan)
    assert cli.main(["localhost", "-p", "80", "--workers", "8"]) == 0
    assert received == [8]


def test_main_writes_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli,
        "scan",
        lambda *_args, **_kwargs: [ScanResult("localhost", 80, True, 0.5, service="http")],
    )
    assert cli.main(["localhost", "-p", "80", "--service", "--json"]) == 0
    output = capsys.readouterr().out
    assert '"port": 80' in output
    assert '"service": "http"' in output


def test_main_writes_csv(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli,
        "scan",
        lambda *_args, **_kwargs: [ScanResult("localhost", 80, True, 0.5, service="http")],
    )
    assert cli.main(["localhost", "-p", "80", "--csv"]) == 0
    output = capsys.readouterr().out
    assert "host,port,state,latency_ms,service,banner,error" in output
    assert "localhost,80,open,0.50,http,," in output


def test_main_enables_banner_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[dict[str, object]] = []

    def fake_scan(*_args: object, **kwargs: object) -> list[ScanResult]:
        received.append(kwargs)
        return []

    monkeypatch.setattr(cli, "scan", fake_scan)
    assert cli.main(["localhost", "-p", "80", "--banner"]) == 0
    assert received == [{"identify_service": True, "grab_banner": True}]
