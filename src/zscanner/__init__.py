"""zscanner public API."""

from zscanner.ports import parse as parse_ports
from zscanner.probe import ServiceBanner, grab_banner
from zscanner.profiles import COMMON_PORTS, WEB_PORTS
from zscanner.scanner import (
    ScanOptions,
    ScanResult,
    open_only,
    scan,
    scan_many,
    scan_port,
    scan_web_targets,
)
from zscanner.targets import parse as parse_targets

parse = parse_ports

__all__ = [
    "ScanOptions",
    "ScanResult",
    "ServiceBanner",
    "COMMON_PORTS",
    "WEB_PORTS",
    "grab_banner",
    "open_only",
    "parse_ports",
    "parse_targets",
    "scan",
    "scan_many",
    "scan_port",
    "scan_web_targets",
]
__version__ = "0.4.2"
