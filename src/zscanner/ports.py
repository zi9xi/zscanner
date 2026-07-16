"""Port specification parsing and file input."""

from pathlib import Path


def parse(value: str) -> list[int]:
    """Parse ports, ranges, or an ``@file`` into sorted unique ports."""
    original = value
    if value.startswith("@"):
        path = value[1:].strip()
        if not path:
            raise ValueError("port file path cannot be empty")
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        value = ",".join(
            line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")
        )

    if not value.strip():
        raise ValueError(f"no valid ports found in: {original}")

    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            raise ValueError(f"empty port entry in: {original}")
        if "-" in item:
            parts = item.split("-")
            if len(parts) != 2:
                raise ValueError(f"invalid port entry: {item}")
            try:
                start, end = map(int, parts)
            except ValueError:
                raise ValueError(f"invalid port entry: {item}") from None
            if start > end:
                raise ValueError(f"reversed range: {item}")
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(item))
            except ValueError:
                raise ValueError(f"invalid port entry: {item}") from None

    if min(ports) < 1 or max(ports) > 65_535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)
