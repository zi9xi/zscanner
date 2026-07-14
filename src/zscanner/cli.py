"""Command-line interface."""

import argparse
from collections.abc import Sequence

from zscanner.scanner import scan


def parse_ports(value: str) -> list[int]:
    """Parse ``22,80,8000-8010`` into a sorted list."""
    if not value.strip():
        raise ValueError(f"no valid ports found in: {value}")

    ports: set[int] = set()
    try:
        for item in value.split(","):
            item = item.strip()
            if not item:
                raise ValueError
            if "-" in item:
                parts = item.split("-")
                if len(parts) != 2:
                    raise ValueError
                start, end = map(int, parts)
                if start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                ports.add(int(item))
    except ValueError:
        raise ValueError(f"invalid ports: {value}") from None

    if min(ports) < 1 or max(ports) > 65_535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("host", help="IPv4 address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="ports to scan")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="timeout in seconds")
    parser.add_argument("--all", action="store_true", help="show closed ports")
    args = parser.parse_args(argv)

    print("Notice: only scan devices you own or have permission to test.")
    try:
        results = scan(args.host, parse_ports(args.ports), args.timeout)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    for result in results:
        if result.is_open or args.all:
            state = "open" if result.is_open else "closed"
            detail = f" ({result.error})" if result.error else ""
            print(f"{result.port:5}/tcp  {state:6}  {result.latency_ms:8.2f} ms{detail}")

    print(f"Open ports: {sum(result.is_open for result in results)}")
    return 0
