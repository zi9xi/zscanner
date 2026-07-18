"""Target specification parsing."""

from ipaddress import ip_network
from pathlib import Path


def parse(value: str, *, max_targets: int | None = 256) -> list[str]:
    """Parse target specifications into a stable, deduplicated target list."""
    if max_targets is not None and max_targets < 1:
        raise ValueError("max_targets must be at least 1")

    raw_items = _read_items(value)
    targets: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        for target in _expand_item(item):
            if target in seen:
                continue
            seen.add(target)
            targets.append(target)
            if max_targets is not None and len(targets) > max_targets:
                raise ValueError(f"target count exceeds limit: {max_targets}")

    if not targets:
        raise ValueError("no valid targets found")
    return targets


def _read_items(value: str) -> list[str]:
    value = value.strip()
    if not value:
        raise ValueError("target cannot be empty")
    if value == "@":
        raise ValueError("target file path cannot be empty")
    if value.startswith("@"):
        raw = Path(value[1:]).read_text(encoding="utf-8")
        value = ",".join(
            stripped
            for line in raw.splitlines()
            if (stripped := line.strip()) and not stripped.startswith("#")
        )
    return [item.strip() for item in value.split(",") if item.strip()]


def _expand_item(item: str) -> list[str]:
    if "/" not in item:
        return [item]
    try:
        network = ip_network(item, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR target: {item}") from exc
    return [str(address) for address in network.hosts()]
