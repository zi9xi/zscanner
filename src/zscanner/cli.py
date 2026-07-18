"""Command-line interface."""

import argparse
import sys
from collections.abc import Sequence

from zscanner import __version__
from zscanner.output import to_csv, to_json, to_text
from zscanner.ports import parse as parse_ports
from zscanner.scanner import scan_many as scan
from zscanner.targets import parse as parse_targets


def main(argv: Sequence[str] | None = None) -> int:
    args_list = list(argv) if argv is not None else sys.argv[1:]
    if args_list[:1] == ["version"]:
        print(f"zscanner {__version__}")
        return 0
    if args_list[:1] == ["scan"]:
        args_list = args_list[1:]

    parser = argparse.ArgumentParser(description="TCP port scanner with service discovery")
    parser.add_argument("targets", help="target, comma-separated targets, CIDR, or @file")
    parser.add_argument("-p", "--ports", default="1-1024", help="ports to scan")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="timeout in seconds")
    parser.add_argument(
        "-w", "--workers", type=int, default=1, help="concurrent workers (default: 1)"
    )
    parser.add_argument("--max-targets", type=int, default=256, help="target safety limit")
    parser.add_argument("--max-tasks", type=int, default=10_000, help="scan task safety limit")
    parser.add_argument("--open", action="store_true", help="show open ports only")
    parser.add_argument("--all", action="store_true", help="show closed ports")
    parser.add_argument("--service", action="store_true", help="show common service names")
    parser.add_argument("--banner", action="store_true", help="grab banners from open ports")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", help="write JSON to stdout")
    output_group.add_argument("--csv", action="store_true", help="write CSV to stdout")
    args = parser.parse_args(args_list)

    print("Notice: only scan devices you own or have permission to test.", file=sys.stderr)
    try:
        results = scan(
            parse_targets(args.targets, max_targets=args.max_targets),
            parse_ports(args.ports),
            args.timeout,
            args.workers,
            identify_service=args.service or args.banner,
            grab_banner=args.banner,
            max_tasks=args.max_tasks,
        )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    show_all = bool(args.all and not args.open)
    if args.json:
        print(to_json(results, show_all=show_all))
    elif args.csv:
        print(to_csv(results, show_all=show_all))
    else:
        print(
            to_text(
                results,
                show_all=show_all,
                show_service=args.service or args.banner,
                show_banner=args.banner,
            )
        )
    return 0
