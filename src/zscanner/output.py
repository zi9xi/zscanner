"""Render scan results for humans and machines."""

import csv
import io
import json

from zscanner.scanner import ScanResult


def filter_results(results: list[ScanResult], *, show_all: bool = False) -> list[ScanResult]:
    """Return visible results according to the selected output policy."""
    if show_all:
        return results
    return [result for result in results if result.is_open]


def to_text(
    results: list[ScanResult],
    *,
    show_all: bool = False,
    show_service: bool = False,
    show_banner: bool = False,
) -> str:
    """Render scan results as aligned terminal text."""
    visible = filter_results(results, show_all=show_all)
    lines: list[str] = []
    hosts = _ordered_hosts(results)
    group_by_host = len(hosts) > 1

    if group_by_host:
        for host in hosts:
            host_results = [result for result in visible if result.host == host]
            if not host_results:
                continue
            if lines:
                lines.append("")
            lines.append(f"Host: {host}")
            lines.extend(
                _format_result(result, show_service=show_service, show_banner=show_banner)
                for result in host_results
            )
    else:
        lines.extend(
            _format_result(result, show_service=show_service, show_banner=show_banner)
            for result in visible
        )

    lines.append(f"Open ports: {sum(result.is_open for result in results)}")
    return "\n".join(lines)


def _ordered_hosts(results: list[ScanResult]) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for result in results:
        if result.host not in seen:
            seen.add(result.host)
            hosts.append(result.host)
    return hosts


def _format_result(result: ScanResult, *, show_service: bool, show_banner: bool) -> str:
    state = "open" if result.is_open else "closed"
    detail = f" ({result.error})" if result.error else ""
    columns = [f"{result.port:5}/tcp", f"{state:6}", f"{result.latency_ms:8.2f} ms"]
    if show_service:
        columns.append(f"{result.service or 'unknown':12}")
    if show_banner:
        columns.append(result.banner or "-")
    return "  ".join(columns) + detail


def to_json(results: list[ScanResult], *, show_all: bool = False) -> str:
    """Render scan results as stable JSON."""
    visible = filter_results(results, show_all=show_all)
    return json.dumps([result.as_dict() for result in visible], ensure_ascii=False, indent=2)


def to_csv(results: list[ScanResult], *, show_all: bool = False) -> str:
    """Render scan results as CSV."""
    visible = filter_results(results, show_all=show_all)
    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=["host", "port", "state", "latency_ms", "service", "banner", "error"],
        lineterminator="\n",
    )
    writer.writeheader()
    for result in visible:
        writer.writerow(
            {
                "host": result.host,
                "port": result.port,
                "state": "open" if result.is_open else "closed",
                "latency_ms": f"{result.latency_ms:.2f}",
                "service": result.service or "",
                "banner": result.banner or "",
                "error": result.error or "",
            }
        )
    return stream.getvalue().rstrip("\n")
