from zscanner.profiles import COMMON_PORTS, HTTP_PORTS, HTTPS_PORTS, WEB_PORTS


def test_web_ports_include_common_http_ports() -> None:
    assert WEB_PORTS[:4] == [80, 443, 8080, 8443]
    assert 3000 in WEB_PORTS
    assert HTTP_PORTS[:2] == [80, 8080]
    assert HTTPS_PORTS[:2] == [443, 8443]


def test_common_ports_include_web_ports_subset() -> None:
    assert 80 in COMMON_PORTS
    assert 443 in COMMON_PORTS
    assert 22 in COMMON_PORTS
