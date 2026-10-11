#!/usr/bin/env python3
"""Check that a built U-Boot .config holds every setting in its config fragments.

Fragments are applied in order, so a later fragment overrides an earlier one
that sets the same symbol. Lines that are neither "CONFIG_X=..." nor
"# CONFIG_X is not set" are ignored.

    python3 cc/uboot/check_config.py build/.config cc/uboot/p2.config cc/uboot/qemu.config

Exits 1 if any setting is missing. Standard library only.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

SET = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=")
UNSET = re.compile(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$")


def symbol(line: str) -> str | None:
    m = SET.match(line) or UNSET.match(line)
    return m.group(1) if m else None


def expected(fragments: list[Path]) -> dict[str, str]:
    """Map each symbol to the line the last fragment that sets it expects."""
    want: dict[str, str] = {}
    for frag in fragments:
        for line in frag.read_text().splitlines():
            name = symbol(line.strip())
            if name:
                want[name] = line.strip()
    return want


def check(config: Path, fragments: list[Path]) -> list[dict]:
    have = set(config.read_text().splitlines())
    return [{"kind": "config", "pattern": line, "ok": line in have} for line in expected(fragments).values()]


def diff(config: Path, base: Path) -> list[str]:
    """Settings in `config` that differ from `base` (added or changed lines)."""
    a = {symbol(l): l for l in base.read_text().splitlines() if symbol(l)}
    b = {symbol(l): l for l in config.read_text().splitlines() if symbol(l)}
    return sorted(line for name, line in b.items() if a.get(name) != line) + \
        sorted(f"# {name} removed" for name in a if name not in b)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        return 2
    checks = check(Path(argv[0]), [Path(p) for p in argv[1:]])
    for c in checks:
        if not c["ok"]:
            print(f"not applied: {c['pattern']}", file=sys.stderr)
    return 0 if all(c["ok"] for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
