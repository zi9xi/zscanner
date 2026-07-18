"""Command-line interface."""

import argparse
import sys
from collections.abc import Callable, Sequence

from zscanner import __version__
from zscanner.output import to_csv, to_json, to_text
from zscanner.ports import parse as parse_ports
from zscanner.scanner import ScanOptions, scan_many
from zscanner.targets import parse as parse_targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zscanner",
        description="Multi-target TCP scanner with service discovery",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan TCP ports")
    scan_parser.add_argument("targets", help="target, comma-separated targets, CIDR, or @file")
    scan_parser.add_argument("-p", "--ports", default="1-1024", help="ports to scan")
    scan_parser.add_argument("-t", "--timeout", type=float, default=1.0, help="timeout in seconds")
    scan_parser.add_argument(
        "-w", "--workers", type=int, default=1, help="concurrent workers (default: 1)"
    )
    scan_parser.add_argument("--max-targets", type=int, default=256, help="target safety limit")
    scan_parser.add_argument("--max-tasks", type=int, default=10_000, help="scan task safety limit")
    scan_parser.add_argument("--all", action="store_true", help="show closed ports")
    scan_parser.add_argument("--service", action="store_true", help="show common service names")
    scan_parser.add_argument("--banner", action="store_true", help="grab banners from open ports")
    output_group = scan_parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", help="write JSON to stdout")
    output_group.add_argument("--csv", action="store_true", help="write CSV to stdout")
    scan_parser.set_defaults(func=_run_scan)

    version_parser = subparsers.add_parser("version", help="show version")
    version_parser.set_defaults(func=_run_version)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args_list = list(argv) if argv is not None else sys.argv[1:]
    if _is_legacy_scan(args_list):
        args_list = ["scan", *args_list]
    parser = build_parser()
    args = parser.parse_args(args_list)
    command: Callable[[argparse.Namespace], int] = args.func
    try:
        return command(args)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    return 2


def _is_legacy_scan(args: list[str]) -> bool:
    return bool(args) and args[0] not in {"scan", "version", "-h", "--help"}


def _run_scan(args: argparse.Namespace) -> int:
    print("Notice: only scan devices you own or have permission to test.", file=sys.stderr)
    options = ScanOptions(
        timeout=args.timeout,
        workers=args.workers,
        identify_service=args.service or args.banner,
        grab_banner=args.banner,
        max_tasks=args.max_tasks,
    )
    results = scan_many(
        parse_targets(args.targets, max_targets=args.max_targets),
        parse_ports(args.ports),
        options,
    )

    show_all = bool(args.all)
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


def _run_version(_args: argparse.Namespace) -> int:
    print(f"zscanner {__version__}")
    return 0
