from zscanner.scanner import ScanResult
from zscanner.web import result_to_url


def test_result_to_url_for_default_ports() -> None:
    assert result_to_url(ScanResult("example.com", 80, True, 1.0)) == "http://example.com"
    assert result_to_url(ScanResult("example.com", 443, True, 1.0)) == "https://example.com"


def test_result_to_url_for_alternate_ports() -> None:
    assert result_to_url(ScanResult("example.com", 8080, True, 1.0)) == (
        "http://example.com:8080"
    )
    assert result_to_url(ScanResult("example.com", 8443, True, 1.0)) == (
        "https://example.com:8443"
    )


def test_result_to_url_returns_none_for_closed_or_non_web_results() -> None:
    assert result_to_url(ScanResult("example.com", 80, False, 1.0)) is None
    assert result_to_url(ScanResult("example.com", 22, True, 1.0)) is None
