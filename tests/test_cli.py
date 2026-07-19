import pytest

from zscanner import cli
from zscanner.scanner import ScanOptions, ScanResult


def test_main_prints_results(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli,
        "scan_many",
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
        _targets: list[str],
        _ports: list[int],
        options: ScanOptions,
        **_kwargs: object,
    ) -> list[ScanResult]:
        received.append(options.workers)
        return []

    monkeypatch.setattr(cli, "scan_many", fake_scan)
    assert cli.main(["localhost", "-p", "80", "--workers", "8"]) == 0
    assert received == [8]


def test_main_writes_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli,
        "scan_many",
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
        "scan_many",
        lambda *_args, **_kwargs: [ScanResult("localhost", 80, True, 0.5, service="http")],
    )
    assert cli.main(["localhost", "-p", "80", "--csv"]) == 0
    output = capsys.readouterr().out
    assert "host,port,state,latency_ms,service,banner,error" in output
    assert "localhost,80,open,0.50,http,," in output


def test_main_enables_banner_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[ScanOptions] = []

    def fake_scan(
        _targets: list[str], _ports: list[int], options: ScanOptions
    ) -> list[ScanResult]:
        received.append(options)
        return []

    monkeypatch.setattr(cli, "scan_many", fake_scan)
    assert cli.main(["localhost", "-p", "80", "--banner"]) == 0
    assert received == [ScanOptions(workers=1, identify_service=True, grab_banner=True)]


def test_main_accepts_scan_subcommand(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[list[str]] = []

    def fake_scan(
        targets: list[str],
        _ports: list[int],
        *_args: object,
        **_kwargs: object,
    ) -> list[ScanResult]:
        received.append(targets)
        return []

    monkeypatch.setattr(cli, "scan_many", fake_scan)
    assert cli.main(["scan", "127.0.0.1,127.0.0.2", "-p", "80"]) == 0
    assert received == [["127.0.0.1", "127.0.0.2"]]


def test_main_forwards_safety_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[int | None] = []

    def fake_scan(
        _targets: list[str], _ports: list[int], options: ScanOptions
    ) -> list[ScanResult]:
        received.append(options.max_tasks)
        return []

    monkeypatch.setattr(cli, "scan_many", fake_scan)
    assert cli.main(["scan", "127.0.0.1", "-p", "80", "--max-tasks", "5"]) == 0
    assert received == [5]


def test_main_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["version"]) == 0
    assert "zscanner 0.4.2" in capsys.readouterr().out
