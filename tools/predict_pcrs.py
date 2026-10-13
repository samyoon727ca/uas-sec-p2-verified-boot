#!/usr/bin/env python3
"""Predict the PCRs U-Boot measures from the release artifacts, and check an event log against them.

With MEASURED_BOOT, U-Boot v2026.07 extends these events while bootm runs, in
this order (boot/bootm.c, lib/tpm_tcg2.c; docs/03 section 3.1):

  PCR 0    EV_S_CRTM_VERSION          U-Boot version string, with its NUL
  PCR 8    EV_COMPACT_HASH "linux"    kernel data as stored in the FIT
  PCR 9    EV_COMPACT_HASH "initrd"   initramfs data as stored in the FIT
  PCR 1    EV_TABLE_OF_DEVICES "dts"  devicetree from the FIT
  PCR 1    EV_PLATFORM_CONFIG_FLAGS   bootargs, with its NUL
  PCR 0-7  EV_SEPARATOR               0xFFFFFFFF, or 0x00000001 if a measurement failed

Everything measured comes from two release artifacts: the signed FIT, and the
U-Boot binary, which holds the version string and the compiled-in bootargs.
This tool predicts every event and the SHA-256 PCRs 0, 1, 8 and 9 that the
sealing policy binds to (SR-010.1). Given a TCG2 event log, it also checks
the log's events against the prediction and replays the log; given measured
PCR values, it compares those too (TC-10).

Usage:
    python3 tools/predict_pcrs.py --fit cc.itb --uboot u-boot.bin
    python3 tools/predict_pcrs.py --fit cc.itb --uboot u-boot.bin \\
        --eventlog binary_bios_measurements --measured pcrs.txt

--measured reads lines of the form "<pcr> <sha256 hex>", optionally prefixed
with "P2-PCR sha256 " as the emulated initramfs prints them. Exit status 1 if
a given log or measured value does not match. Standard library only.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

POLICY_PCRS = (0, 1, 8, 9)      # SR-010.1
SEPARATOR_PCRS = range(8)       # tcg2_measurement_term() closes PCRs 0 to 7
SEPARATOR_OK = struct.pack("<I", 0xFFFFFFFF)

EV_NO_ACTION = 0x3
EV_SEPARATOR = 0x4
EV_S_CRTM_VERSION = 0x8
EV_PLATFORM_CONFIG_FLAGS = 0xA
EV_TABLE_OF_DEVICES = 0xB
EV_COMPACT_HASH = 0xC
EVENT_NAMES = {EV_NO_ACTION: "EV_NO_ACTION", EV_SEPARATOR: "EV_SEPARATOR", EV_S_CRTM_VERSION: "EV_S_CRTM_VERSION",
               EV_PLATFORM_CONFIG_FLAGS: "EV_PLATFORM_CONFIG_FLAGS", EV_TABLE_OF_DEVICES: "EV_TABLE_OF_DEVICES",
               EV_COMPACT_HASH: "EV_COMPACT_HASH"}

TPM_ALG_SHA256 = 0x000B
DIGEST_SIZES = {0x0004: 20, 0x000B: 32, 0x000C: 48, 0x000D: 64, 0x0012: 32}   # SHA-1/256/384/512, SM3
SPEC_ID_SIGNATURE = b"Spec ID Event03\0"

# The version string in common/version.c: U_BOOT_VERSION " (" date " - " time " " zone ")" IDENT_STRING.
# "U-Boot " followed by a digit excludes the SPL's "U-Boot SPL ..." string.
VERSION_STRING = re.compile(rb"U-Boot \d{4}\.\d{2}[^\0()]* \([A-Z][a-z]{2} \d{2} \d{4} - \d{2}:\d{2}:\d{2} [^)\0]*\)[^\0]*\0")
# One entry of the compiled-in default environment.
BOOTARGS = re.compile(rb"\0bootargs=([^\0]*)\0")


# --- flattened devicetree -------------------------------------------------------

@dataclasses.dataclass
class Node:
    props: dict[str, bytes] = dataclasses.field(default_factory=dict)
    children: dict[str, "Node"] = dataclasses.field(default_factory=dict)

    def get(self, path: str) -> "Node":
        node = self
        for part in filter(None, path.split("/")):
            if part not in node.children:
                raise KeyError(f"no node {path}")
            node = node.children[part]
        return node

    def string(self, prop: str) -> str:
        return self.strings(prop)[0]

    def strings(self, prop: str) -> list[str]:
        if prop not in self.props:
            raise KeyError(f"no property {prop}")
        return [s.decode() for s in self.props[prop].split(b"\0") if s]


def parse_fdt(blob: bytes) -> Node:
    """Parse a flattened devicetree (FIT or DTB) into a tree of nodes."""
    if len(blob) < 40:
        raise ValueError("not a flattened devicetree")
    magic, total, off_struct, off_strings = struct.unpack_from(">IIII", blob, 0)
    if magic != 0xD00DFEED or total > len(blob):
        raise ValueError("not a flattened devicetree")
    root, stack, pos = None, [], off_struct
    while True:
        (tok,) = struct.unpack_from(">I", blob, pos)
        pos += 4
        if tok == 1:  # FDT_BEGIN_NODE
            end = blob.index(b"\0", pos)
            node = Node()
            if stack:
                stack[-1].children[blob[pos:end].decode()] = node
            else:
                root = node
            stack.append(node)
            pos = (end + 4) & ~3
        elif tok == 2:  # FDT_END_NODE
            stack.pop()
        elif tok == 3:  # FDT_PROP
            length, nameoff = struct.unpack_from(">II", blob, pos)
            pos += 8
            start = off_strings + nameoff
            stack[-1].props[blob[start:blob.index(b"\0", start)].decode()] = bytes(blob[pos:pos + length])
            pos = (pos + length + 3) & ~3
        elif tok == 4:  # FDT_NOP
            continue
        elif tok == 9:  # FDT_END
            if root is None or stack:
                raise ValueError("unbalanced devicetree")
            return root
        else:
            raise ValueError(f"bad FDT token {tok} at {pos - 4}")


@dataclasses.dataclass
class FitImages:
    config: str
    kernel: bytes
    ramdisk: bytes
    fdt: bytes


def fit_images(blob: bytes, config: str | None = None) -> FitImages:
    """The kernel, ramdisk and devicetree bytes bootm measures for a FIT configuration.

    The kernel and ramdisk are measured as stored in the FIT. The devicetree is
    measured as fdt_totalsize() bytes of the blob bootm uses, so a compressed
    devicetree is refused rather than predicted wrongly.
    """
    fit = parse_fdt(blob)
    configs = fit.get("/configurations")
    name = config or configs.string("default")
    conf = configs.get(name)

    def data(kind: str) -> tuple[str, bytes]:
        names = conf.strings(kind)
        if len(names) != 1:
            raise ValueError(f"configuration {name}: expected one {kind}, found {names}")
        image = fit.get(f"/images/{names[0]}")
        if "data" not in image.props:
            raise ValueError(f"image {names[0]}: external data is not supported")
        return names[0], image.props["data"]

    _, kernel = data("kernel")
    _, ramdisk = data("ramdisk")
    fdt_name, fdt = data("fdt")
    if fit.get(f"/images/{fdt_name}").props.get("compression", b"none\0") != b"none\0":
        raise ValueError(f"image {fdt_name}: a compressed devicetree is not supported")
    total = parse_fdt_header_size(fdt)
    return FitImages(name, kernel, ramdisk, fdt[:total])


def parse_fdt_header_size(blob: bytes) -> int:
    magic, total = struct.unpack_from(">II", blob, 0)
    if magic != 0xD00DFEED or total > len(blob):
        raise ValueError("devicetree image is not a flattened devicetree")
    return total


# --- U-Boot binary --------------------------------------------------------------

def uboot_version(binary: bytes) -> bytes:
    """The version string U-Boot measures into PCR 0, with its NUL."""
    found = set(VERSION_STRING.findall(binary))
    if len(found) != 1:
        raise ValueError(f"expected one U-Boot version string in the binary, found {len(found)}")
    return found.pop()


def uboot_bootargs(binary: bytes) -> bytes:
    """The compiled-in bootargs U-Boot measures into PCR 1, with its NUL."""
    found = set(BOOTARGS.findall(binary))
    if len(found) != 1:
        raise ValueError(f"expected one bootargs entry in the default environment, found {len(found)}; "
                         "pass --bootargs")
    return found.pop() + b"\0"


# --- prediction -----------------------------------------------------------------

@dataclasses.dataclass
class Event:
    pcr: int
    type: int
    digest: str      # SHA-256, hex
    data: bytes      # the event field as logged

    def describe(self) -> dict:
        text = self.data.rstrip(b"\0").decode("latin-1")
        shown = text if text and text.isascii() and text.isprintable() else self.data.hex()
        return {"pcr": self.pcr, "type": EVENT_NAMES.get(self.type, hex(self.type)), "sha256": self.digest,
                "event": shown}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def predict_events(version: bytes, images: FitImages, bootargs: bytes) -> list[Event]:
    """The events bootm_measure() logs, in order, with their SHA-256 digests."""
    events = [
        Event(0, EV_S_CRTM_VERSION, sha256(version), version),
        Event(8, EV_COMPACT_HASH, sha256(images.kernel), b"linux\0"),
        Event(9, EV_COMPACT_HASH, sha256(images.ramdisk), b"initrd\0"),
        Event(1, EV_TABLE_OF_DEVICES, sha256(images.fdt), b"dts\0"),
        Event(1, EV_PLATFORM_CONFIG_FLAGS, sha256(bootargs), bootargs),
    ]
    events += [Event(i, EV_SEPARATOR, sha256(SEPARATOR_OK), SEPARATOR_OK) for i in SEPARATOR_PCRS]
    return events


def replay(events: list[Event]) -> dict[int, str]:
    """Extend each event's digest into PCRs that start at zero."""
    pcrs: dict[int, bytes] = {}
    for ev in events:
        pcrs[ev.pcr] = hashlib.sha256(pcrs.get(ev.pcr, bytes(32)) + bytes.fromhex(ev.digest)).digest()
    return {i: v.hex() for i, v in sorted(pcrs.items())}


@dataclasses.dataclass
class Prediction:
    version: bytes
    bootargs: bytes
    config: str
    events: list[Event]
    pcrs: dict[int, str]

    def to_json(self) -> dict:
        return {"uboot_version": self.version.rstrip(b"\0").decode(), "bootargs": self.bootargs.rstrip(b"\0").decode(),
                "fit_configuration": self.config, "events": [e.describe() for e in self.events],
                "pcrs_sha256": {str(i): v for i, v in self.pcrs.items()},
                "policy_pcrs": list(POLICY_PCRS)}


def predict(fit: bytes, uboot: bytes, bootargs: str | None = None, config: str | None = None) -> Prediction:
    images = fit_images(fit, config)
    version = uboot_version(uboot)
    args = bootargs.encode() + b"\0" if bootargs is not None else uboot_bootargs(uboot)
    events = predict_events(version, images, args)
    return Prediction(version, args, images.config, events, replay(events))


# --- TCG2 event log ------------------------------------------------------------

def parse_event_log(blob: bytes) -> list[Event]:
    """Parse a crypto-agile TCG2 event log; return its events with their SHA-256 digests.

    The first event is the Spec ID event (SHA-1 format), which lists the digest
    algorithms of every later event. Parsing stops at the end of the data or at
    an all-zero remainder, as left in an event-log region that is not full.
    """
    pos = 0
    pcr, etype = struct.unpack_from("<II", blob, pos)
    pos += 8 + 20
    (size,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    spec = blob[pos:pos + size]
    pos += size
    if etype != EV_NO_ACTION or pcr != 0 or not spec.startswith(SPEC_ID_SIGNATURE):
        raise ValueError("event log does not start with a TCG2 Spec ID event")
    (count,) = struct.unpack_from("<I", spec, 24)
    sizes = dict(struct.unpack_from("<HH", spec, 28 + 4 * i) for i in range(count))
    if TPM_ALG_SHA256 not in sizes:
        raise ValueError("event log has no SHA-256 digests")

    events = []
    while pos < len(blob) and any(blob[pos:]):
        pcr, etype, ndigests = struct.unpack_from("<III", blob, pos)
        pos += 12
        digest = None
        for _ in range(ndigests):
            (alg,) = struct.unpack_from("<H", blob, pos)
            if alg not in sizes:
                raise ValueError(f"event at offset {pos}: algorithm {alg:#x} is not in the Spec ID event")
            if alg == TPM_ALG_SHA256:
                digest = blob[pos + 2:pos + 2 + sizes[alg]].hex()
            pos += 2 + sizes[alg]
        (size,) = struct.unpack_from("<I", blob, pos)
        pos += 4
        if pos + size > len(blob):
            raise ValueError("event log is truncated")
        if digest is None:
            raise ValueError(f"event {len(events)} has no SHA-256 digest")
        events.append(Event(pcr, etype, digest, bytes(blob[pos:pos + size])))
        pos += size
    return [e for e in events if e.type != EV_NO_ACTION]


# --- comparison ------------------------------------------------------------------

def compare(pred: Prediction, log: list[Event] | None = None,
            measured: dict[int, str] | None = None) -> list[dict]:
    """Checks, in the harness's format: logged events, replayed and measured PCRs against the prediction."""
    checks = []
    if log is not None:
        want = [e.describe() for e in pred.events]
        got = [e.describe() for e in log]
        first = next((i for i, (w, g) in enumerate(zip(want, got)) if w != g), None)
        if first is None and len(want) != len(got):
            first = min(len(want), len(got))
        checks.append({"kind": "eventlog", "pattern": f"the event log holds the {len(want)} predicted events, in order",
                       "ok": first is None,
                       "observed": f"{len(got)} events" if first is None else
                       {"index": first, "predicted": want[first] if first < len(want) else None,
                        "logged": got[first] if first < len(got) else None}})
        replayed = replay(log)
        for i in POLICY_PCRS:
            checks.append({"kind": "replayed", "pattern": f"PCR {i}: event-log replay equals the prediction",
                           "ok": replayed.get(i) == pred.pcrs[i], "observed": replayed.get(i)})
    if measured is not None:
        for i in POLICY_PCRS:
            got = (measured.get(i) or "").lower()
            checks.append({"kind": "measured", "pattern": f"PCR {i}: measured value equals the prediction",
                           "ok": got == pred.pcrs[i], "observed": got or None})
    return checks


MEASURED_LINE = re.compile(r"^(?:P2-PCR sha256 )?(\d+) ([0-9a-fA-F]{64})$")


def parse_measured(text: str) -> dict[int, str]:
    out = {}
    for line in text.replace("\r", "").splitlines():
        m = MEASURED_LINE.match(line.strip())
        if m:
            out[int(m.group(1))] = m.group(2).lower()
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fit", type=Path, required=True, help="signed FIT the CC boots")
    parser.add_argument("--uboot", type=Path, required=True, help="U-Boot binary (u-boot.bin or u-boot-nodtb.bin)")
    parser.add_argument("--bootargs", help="kernel command line, if not read from the U-Boot binary")
    parser.add_argument("--config", help="FIT configuration (default: the FIT's default)")
    parser.add_argument("--eventlog", type=Path, help="TCG2 event log to check and replay")
    parser.add_argument("--measured", type=Path, help="measured PCR values to compare")
    parser.add_argument("--json", action="store_true", help="print the prediction and checks as JSON")
    args = parser.parse_args(argv)

    pred = predict(args.fit.read_bytes(), args.uboot.read_bytes(), args.bootargs, args.config)
    log = parse_event_log(args.eventlog.read_bytes()) if args.eventlog else None
    measured = parse_measured(args.measured.read_text(errors="replace")) if args.measured else None
    checks = compare(pred, log, measured)
    ok = all(c["ok"] for c in checks)
    if args.json:
        print(json.dumps({**pred.to_json(), "checks": checks, "ok": ok}, indent=2))
    else:
        print(f"U-Boot: {pred.to_json()['uboot_version']}")
        print(f"bootargs: {pred.to_json()['bootargs']}")
        print(f"FIT configuration: {pred.config}")
        for i in POLICY_PCRS:
            print(f"PCR {i} sha256 {pred.pcrs[i]}")
        for c in checks:
            print(f"{'ok  ' if c['ok'] else 'FAIL'} {c['pattern']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
