import json

from zscanner.output import to_csv, to_json, to_text
from zscanner.scanner import ScanResult


def test_text_output_filters_closed_ports_by_default() -> None:
    results = [
        ScanResult("localhost", 80, True, 1.25, service="http", banner="HTTP/1.0 200 OK"),
        ScanResult("localhost", 81, False, 1.0, "refused", service="unknown"),
    ]

    output = to_text(results, show_service=True, show_banner=True)

    assert "80/tcp" in output
    assert "http" in output
    assert "HTTP/1.0 200 OK" in output
    assert "81/tcp" not in output
    assert "Open ports: 1" in output


def test_text_output_groups_multiple_hosts() -> None:
    results = [
        ScanResult("host-a", 80, True, 1.0),
        ScanResult("host-b", 443, True, 1.0),
    ]

    output = to_text(results)

    assert "Host: host-a" in output
    assert "Host: host-b" in output
    assert "80/tcp" in output
    assert "443/tcp" in output


def test_json_output_is_machine_readable() -> None:
    output = to_json([ScanResult("localhost", 80, True, 1.25, service="http")])
    data = json.loads(output)

    assert data[0]["host"] == "localhost"
    assert data[0]["port"] == 80
    assert data[0]["service"] == "http"


def test_csv_output_has_stable_columns() -> None:
    output = to_csv([ScanResult("localhost", 80, True, 1.25, service="http")])

    assert output.splitlines()[0] == "host,port,state,latency_ms,service,banner,error"
    assert output.splitlines()[1] == "localhost,80,open,1.25,http,,"
