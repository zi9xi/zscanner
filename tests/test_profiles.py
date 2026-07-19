from zscanner.profiles import COMMON_PORTS, WEB_PORTS


def test_web_ports_include_common_http_ports() -> None:
    assert WEB_PORTS[:4] == [80, 443, 8080, 8443]
    assert 3000 in WEB_PORTS


def test_common_ports_include_web_ports_subset() -> None:
    assert 80 in COMMON_PORTS
    assert 443 in COMMON_PORTS
    assert 22 in COMMON_PORTS
