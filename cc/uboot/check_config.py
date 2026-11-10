#!/usr/bin/env python3
"""Check that a built U-Boot .config holds every setting in its config fragments.

Fragments are applied in order, so a later fragment overrides an earlier one
that sets the same symbol. Lines that are neither "CONFIG_X=..." nor
"# CONFIG_X is not set" are ignored.

    python3 cc/uboot/check_config.py build/.config cc/uboot/p2.config cc/uboot/qemu.config

That comparison cannot see a line that is missing from the fragments
themselves. A second mode checks a built .config against the boot-loader
policy of SR-005.1, written out in this file and independent of any fragment
or board:

    python3 cc/uboot/check_config.py --policy build/.config

Exits 1 if any setting is missing or any policy rule is broken. Standard
library only.
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


# --- the boot-loader policy -----------------------------------------------------
#
# SR-005.1 as settings (docs/02 section 2.3), written out here and not read from
# the fragments. check() above compares a .config with the fragments it was
# built from, so it cannot notice a hardening line that was dropped from a
# fragment. These rules can. They name no board: the DEBIX build must pass them
# too, where the defconfig keeps the environment in MMC.

POLICY_ON = {
    "fit-signature": ("CONFIG_FIT_SIGNATURE", "signed FIT configurations are verified"),
    "env-nowhere": ("CONFIG_ENV_IS_NOWHERE", "the environment is the one compiled into the image"),
    "measured-boot": ("CONFIG_MEASURED_BOOT", "what is booted is measured into the TPM"),
    "measure-devicetree": ("CONFIG_MEASURE_DEVICETREE", "the devicetree is measured too"),
}
POLICY_OFF = {
    "no-legacy-image": ("CONFIG_LEGACY_IMAGE_FORMAT", "legacy uImages, which carry no signature, are not booted"),
    "no-standard-boot": ("CONFIG_BOOTSTD_BOOTCOMMAND", "no scan of disks for unsigned scripts or extlinux.conf"),
    "no-preboot": ("CONFIG_USE_PREBOOT", "no preboot command runs before the boot command"),
}
ENV_STORAGE = re.compile(r"^(CONFIG_ENV_IS_IN_[A-Z0-9_]+)=y$")
RESET_LAST = re.compile(r';\s*reset\s*"$')


def settings(config: Path) -> dict[str, str]:
    """Each symbol a .config sets, with its value as written."""
    out = {}
    for line in config.read_text().splitlines():
        m = SET.match(line)
        if m:
            out[m.group(1)] = line[m.end():]
    return out


def policy(config: Path) -> list[dict]:
    """The fixed policy checks for a built .config, in the harness's check format."""
    have = settings(config)
    checks = []

    def add(rule: str, pattern: str, ok: bool, observed) -> None:
        checks.append({"kind": "policy", "rule": rule, "pattern": pattern, "ok": ok, "observed": observed})

    for rule, (name, why) in POLICY_ON.items():
        add(rule, f"{name}=y: {why}", have.get(name) == "y", have.get(name))
    for rule, (name, why) in POLICY_OFF.items():
        add(rule, f"{name} is off: {why}", name not in have, have.get(name))
    stored = sorted(m.group(1) for m in map(ENV_STORAGE.match, config.read_text().splitlines()) if m)
    add("env-not-stored", "no CONFIG_ENV_IS_IN_* is on: no environment is read from flash, MMC or a file system",
        not stored, stored)
    add("no-autoboot-delay", "CONFIG_BOOTDELAY=-2: autoboot with no check for a keypress",
        have.get("CONFIG_BOOTDELAY") == "-2", have.get("CONFIG_BOOTDELAY"))
    command = have.get("CONFIG_BOOTCOMMAND", "")
    add("reset-after-boot-command", "the boot command is used and ends in reset, so a refused boot reaches no prompt",
        have.get("CONFIG_USE_BOOTCOMMAND") == "y" and bool(RESET_LAST.search(command)), command or None)
    return checks


def violated(config: Path) -> list[str]:
    """The policy rules a .config breaks, by rule name."""
    return sorted(c["rule"] for c in policy(config) if not c["ok"])


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--policy":
        failed = [c for c in policy(Path(argv[1])) if not c["ok"]]
        for c in failed:
            print(f"policy: {c['pattern']} (found {c['observed']!r})", file=sys.stderr)
        return 1 if failed else 0
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
