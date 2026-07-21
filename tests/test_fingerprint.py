from zscanner.fingerprint import guess_service, guess_short


def test_guess_short_known_port() -> None:
    assert guess_short(22) == "ssh"
    assert guess_short(443) == "https"
    assert guess_short(3000) == "http-dev"
    assert guess_short(9443) == "https-alt"


def test_guess_service_unknown_port() -> None:
    assert guess_service(65000) == ("unknown", "Unknown service")
