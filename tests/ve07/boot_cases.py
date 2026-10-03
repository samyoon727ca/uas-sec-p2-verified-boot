#!/usr/bin/env python3
"""VE-07, emulated: verified-boot test cases TC-01, TC-03 and TC-04.

Boots the hardened U-Boot built by cc/build.sh on QEMU virt with swtpm and
checks that only the chain signed with the dev K-CC-OS key boots:

  TC-01  the signed chain boots to the initramfs (positive control)
  TC-03  a FIT with one byte changed in the kernel, initramfs or devicetree
         is refused
  TC-04  boot configuration cannot be changed: the built .config holds the
         P2 settings; an added unsigned configuration, an unsigned FIT, a
         FIT signed by a rogue key with the same key name, a legacy uImage
         and an environment injected into flash are all refused or ignored;
         keystrokes never reach a console prompt

Control runs repeat the environment, legacy-image and console cases on stock
qemu_arm64_defconfig and must show the attack succeeding there, so each test
can be seen to detect what it looks for. A negative case counts only if the
positive control passed in the same run.

Keys are generated per run in a temporary directory and deleted; evidence
records only public-key SHA-256 values. Writes one console log per case and
summary.json/summary.md to --out. Exit status 0 only if every case passes.

Usage:
    python3 tests/ve07/boot_cases.py --build build --out evidence/ve07-ci/<run>

Standard library only. Needs qemu-system-aarch64, swtpm, openssl, dtc and
fdtput on PATH, and mkimage/mkenvimage from the U-Boot build.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

KEY_NAME = "cc-os-dev"
FIT_ADDR_SLOT_BYTES = 64 * 1024 * 1024   # matches "virtio read 0x50000000 0 0x20000"
FLASH_BYTES = 64 * 1024 * 1024           # QEMU virt flash bank size
ENV_SIZE = 0x40000                       # stock qemu_arm64 CONFIG_ENV_SIZE (flash1 offset 0)
EVENT_LOG = (0x60000000, 0x10000)        # TPM event-log region handed to Linux
CASE_TIMEOUT = 240

# Console patterns.
VERIFIED = rf"sha256,rsa3072:{KEY_NAME}\+ OK"
BOOTED = r"P2-INITRAMFS-OK"
KERNEL_START = r"Starting kernel"
LINUX = r"Linux version \d"
PROMPT = r"(?m)^=> "
RESET = r"resetting \.\.\."
ENV_MARK = r"P2-ENV-INJECTED"
REQUIRED_FAIL = rf"Failed to verify required signature 'key-{KEY_NAME}'"
REFUSED = [KERNEL_START, BOOTED, PROMPT, ENV_MARK]

# Settings the built hardened .config must hold (from cc/uboot/*.config).
FRAGMENTS = [ROOT / "cc/uboot/p2.config", ROOT / "cc/uboot/qemu.config"]


# --- small helpers ----------------------------------------------------------

def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def first_line(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired):
        return "unavailable"


# --- FDT: find a property's value inside a FIT, to tamper after signing -----

def fdt_prop(blob: bytes | bytearray, node: str, prop: str) -> tuple[int, int]:
    """Return (offset, length) of property `prop` of `node` in a flattened devicetree."""
    magic, _total, off_struct, off_strings = struct.unpack_from(">IIII", blob, 0)
    if magic != 0xD00DFEED:
        raise ValueError("not a flattened devicetree")
    pos, path = off_struct, []
    while True:
        (tok,) = struct.unpack_from(">I", blob, pos)
        pos += 4
        if tok == 1:  # FDT_BEGIN_NODE
            end = blob.index(b"\0", pos)
            path.append(blob[pos:end].decode())
            pos = (end + 4) & ~3
        elif tok == 2:  # FDT_END_NODE
            path.pop()
        elif tok == 3:  # FDT_PROP
            length, nameoff = struct.unpack_from(">II", blob, pos)
            pos += 8
            start = off_strings + nameoff
            name = blob[start:blob.index(b"\0", start)].decode()
            if "/" + "/".join(p for p in path if p) == node and name == prop:
                return pos, length
            pos = (pos + length + 3) & ~3
        elif tok == 4:  # FDT_NOP
            continue
        elif tok == 9:  # FDT_END
            raise KeyError(f"{node}:{prop} not found")
        else:
            raise ValueError(f"bad FDT token {tok} at {pos - 4}")


def flip_byte(src: Path, dst: Path, node: str) -> int:
    blob = bytearray(src.read_bytes())
    off, length = fdt_prop(blob, node, "data")
    at = off + length // 2
    blob[at] ^= 0xFF
    dst.write_bytes(blob)
    return at


# --- QEMU and swtpm ----------------------------------------------------------

@dataclasses.dataclass
class Machine:
    bios: Path
    slot: Path
    flash1: Path
    dtb: Path | None
    tpm_sock: Path

    def argv(self, dumpdtb: Path | None = None) -> list[str]:
        machine = "virt,gic-version=3" + (f",dumpdtb={dumpdtb}" if dumpdtb else "")
        argv = [
            "qemu-system-aarch64", "-machine", machine, "-cpu", "cortex-a57", "-smp", "1", "-m", "2G",
            "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-nic", "none",
            "-bios", str(self.bios),
            "-chardev", f"socket,id=chrtpm,path={self.tpm_sock}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis-device,tpmdev=tpm0",
            "-drive", f"if=none,id=slot,file={self.slot},format=raw,readonly=on",
            "-device", "virtio-blk-device,drive=slot",
            "-drive", f"if=pflash,unit=1,file={self.flash1},format=raw,readonly=on",
        ]
        if self.dtb and not dumpdtb:
            argv += ["-dtb", str(self.dtb)]
        return argv


class Swtpm:
    """A fresh swtpm instance: a new TPM with no state, as at first power-on."""

    def __init__(self, state: Path) -> None:
        state.mkdir(parents=True, exist_ok=True)
        self.sock = state / "sock"
        self.proc = subprocess.Popen(
            ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
             "--ctrl", f"type=unixio,path={self.sock}", "--log", f"file={state}/swtpm.log,level=1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if self.sock.exists():
                return
            time.sleep(0.05)
        self.stop()
        raise RuntimeError("swtpm did not start")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def boot(machine: Machine, timeout: int, keys: bool = False, stop: str | None = None) -> tuple[str, str, float]:
    """Run QEMU until it exits, `stop` appears on the console, or timeout.

    With keys=True, keystrokes are typed at the console throughout, as an
    attacker with serial access would. Returns (console text, end reason, seconds).
    """
    start = time.monotonic()
    proc = subprocess.Popen(machine.argv(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    chunks: list[bytes] = []

    def reader() -> None:
        for chunk in iter(lambda: proc.stdout.read1(4096), b""):
            chunks.append(chunk)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    reason, ticks = "exited", 0
    while proc.poll() is None:
        if time.monotonic() - start > timeout:
            reason = "timeout"
            break
        if stop and re.search(stop, b"".join(chunks).decode("utf-8", "replace")):
            reason = "stopped"
            break
        if keys:
            try:
                proc.stdin.write(b"help\r" if ticks % 5 == 0 else b"\r")
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            ticks += 1
        time.sleep(0.2)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
    thread.join(5)
    text = b"".join(chunks).decode("utf-8", "replace").replace("\r", "")
    return text, reason, time.monotonic() - start


# --- artifacts ---------------------------------------------------------------

FIT_ITS = """/dts-v1/;
/ {{
	description = "P2 emulated CC boot chain";
	#address-cells = <1>;
	images {{
		kernel {{
			description = "Ubuntu 6.8.0-146-generic arm64";
			data = /incbin/("Image.gz");
			type = "kernel"; arch = "arm64"; os = "linux"; compression = "gzip";
			load = <0x40400000>; entry = <0x40400000>;
			hash {{ algo = "sha256"; }};
		}};
		fdt {{
			data = /incbin/("kernel.dtb");
			type = "flat_dt"; arch = "arm64"; compression = "none";
			hash {{ algo = "sha256"; }};
		}};
		ramdisk {{
			data = /incbin/("initramfs.cpio.gz");
			type = "ramdisk"; arch = "arm64"; os = "linux"; compression = "none";
			hash {{ algo = "sha256"; }};
		}};
	}};
	configurations {{
		default = "conf";
		conf {{
			kernel = "kernel"; fdt = "fdt"; ramdisk = "ramdisk";
{signature}		}};
	}};
}};
"""
SIGNATURE = f"""\t\t\tsignature {{
\t\t\t\talgo = "sha256,rsa3072"; key-name-hint = "{KEY_NAME}";
\t\t\t\tsign-images = "kernel", "fdt", "ramdisk";
\t\t\t}};
"""


class Artifacts:
    """Keys, devicetrees, FIT variants, slot disks and flash images for one run."""

    def __init__(self, build: Path, work: Path, short: Path) -> None:
        self.build, self.work, self.short = build, work, short
        self.mkimage, self.mkenvimage = build / "mkimage", build / "mkenvimage"
        self.uboot = {"hardened": build / "u-boot-hardened.bin", "stock": build / "u-boot-stock.bin"}
        self.env = dict(os.environ, SOURCE_DATE_EPOCH=os.environ.get("SOURCE_DATE_EPOCH", "1783381843"))
        self.slots: dict[str, Path] = {}
        self.flash: dict[str, Path] = {}
        self.public_keys: dict[str, str] = {}
        self.notes: dict[str, str] = {}

    def keypair(self, keydir: Path, label: str) -> None:
        keydir.mkdir(parents=True, exist_ok=True)
        key, crt = keydir / f"{KEY_NAME}.key", keydir / f"{KEY_NAME}.crt"
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)])
        run(["openssl", "req", "-batch", "-new", "-x509", "-days", "1", "-key", str(key), "-out", str(crt),
             "-subj", f"/CN={KEY_NAME} ({label})"])
        der = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                             check=True, capture_output=True).stdout
        self.public_keys[label] = hashlib.sha256(der).hexdigest()

    def devicetree(self) -> None:
        """Dump QEMU's devicetree with the exact command line used to boot, then add
        the TPM event-log region and drop the per-boot random seeds."""
        blank_slot, blank_flash = self.disk("blank-slot", b""), self.flash_image("blank", b"")
        tpm = Swtpm(self.short / "tpm-dump")
        try:
            dumped = self.work / "qemu.dtb"
            m = Machine(self.uboot["hardened"], blank_slot, blank_flash, None, tpm.sock)
            subprocess.run(m.argv(dumpdtb=dumped), capture_output=True, timeout=60)
        finally:
            tpm.stop()
        dts = run(["dtc", "-q", "-I", "dtb", "-O", "dts", str(dumped)]).stdout
        bus = re.search(r"platform-bus@[0-9a-f]+", dts).group(0)
        tpm_node = re.search(r"tpm[_a-z]*@[0-9a-f]+", dts).group(0)
        base, size = EVENT_LOG
        overlay = (
            "/ {\n\treserved-memory {\n\t\t#address-cells = <2>;\n\t\t#size-cells = <2>;\n\t\tranges;\n"
            f"\t\ttpm-event-log@{base:x} {{ reg = <0x0 {base:#x} 0x0 {size:#x}>; }};\n\t}};\n}};\n"
            f"&{{/{bus}/{tpm_node}}} {{\n\tlinux,sml-base = <0x0 {base:#x}>;\n\tlinux,sml-size = <{size:#x}>;\n}};\n"
        )
        board = self.work / "board.dtb"
        subprocess.run(["dtc", "-q", "-I", "dts", "-O", "dtb", "-o", str(board), "-"],
                       input=dts + overlay, text=True, check=True)
        for prop in ("kaslr-seed", "rng-seed"):
            subprocess.run(["fdtput", "-d", str(board), "/chosen", prop], capture_output=True)
        shutil.copy(board, self.work / "kernel.dtb")   # handed to Linux inside the FIT
        shutil.copy(board, self.work / "ctrl.dtb")     # U-Boot control DT; receives K-CC-OS
        self.notes["tpm_node"] = f"/{bus}/{tpm_node}"

    def disk(self, name: str, payload: bytes) -> Path:
        if len(payload) > FIT_ADDR_SLOT_BYTES:
            raise ValueError(f"{name}: {len(payload)} bytes does not fit the raw slot")
        path = self.work / f"slot-{name}.img"
        with path.open("wb") as f:
            f.write(payload)
            f.truncate(FIT_ADDR_SLOT_BYTES)
        self.slots[name] = path
        return path

    def flash_image(self, name: str, payload: bytes) -> Path:
        path = self.work / f"flash1-{name}.img"
        path.write_bytes(payload + b"\xff" * (FLASH_BYTES - len(payload)))
        self.flash[name] = path
        return path

    def make_image(self, *args: str) -> None:
        run([str(self.mkimage), *args], cwd=self.work, env=self.env)

    def build_all(self) -> None:
        self.keypair(self.short / "keys", "K-CC-OS dev")
        self.keypair(self.short / "rogue", "rogue")
        self.devicetree()
        for f in ("Image.gz", "initramfs.cpio.gz"):
            shutil.copy(self.build / f, self.work / f)
        (self.work / "fit.its").write_text(FIT_ITS.format(signature=SIGNATURE))
        (self.work / "fit-unsigned.its").write_text(FIT_ITS.format(signature=""))

        # Signed FIT; the public key goes into the control DT as a required key.
        self.make_image("-f", "fit.its", "-K", "ctrl.dtb", "-k", str(self.short / "keys"), "-r", "good.itb")
        good = self.work / "good.itb"
        self.disk("good", good.read_bytes())

        # TC-03: one byte changed after signing, in each payload.
        for node in ("kernel", "ramdisk", "fdt"):
            dst = self.work / f"tamper-{node}.itb"
            at = flip_byte(good, dst, f"/images/{node}")
            self.notes[f"tamper-{node}"] = f"byte {at} inverted in /images/{node}/data"
            self.disk(f"tamper-{node}", dst.read_bytes())

        # TC-04: a configuration added after signing and made the default.
        added = self.work / "added-config.itb"
        shutil.copy(good, added)
        for cmd in (["-c", str(added), "/configurations/conf-alt"],
                    ["-t", "s", str(added), "/configurations/conf-alt", "kernel", "kernel"],
                    ["-t", "s", str(added), "/configurations/conf-alt", "fdt", "fdt"],
                    ["-t", "s", str(added), "/configurations", "default", "conf-alt"]):
            run(["fdtput", *cmd])
        self.notes["added-config"] = "conf-alt (kernel and fdt, no initramfs, unsigned) added and made default"
        self.disk("added-config", added.read_bytes())

        # TC-04: no signature at all.
        self.make_image("-f", "fit-unsigned.its", "unsigned.itb")
        self.disk("unsigned", (self.work / "unsigned.itb").read_bytes())

        # TC-04: signed by a rogue key that carries the same key name.
        shutil.copy(self.work / "ctrl.dtb", self.work / "rogue-ctrl.dtb")
        self.make_image("-f", "fit.its", "-K", "rogue-ctrl.dtb", "-k", str(self.short / "rogue"), "-r", "rogue.itb")
        self.disk("rogue", (self.work / "rogue.itb").read_bytes())

        # TC-04: legacy uImage (no signature format exists for it).
        self.make_image("-A", "arm64", "-O", "linux", "-T", "kernel", "-C", "gzip", "-a", "0x40400000",
                     "-e", "0x40400000", "-n", "p2-legacy", "-d", "Image.gz", "legacy.uimg")
        self.disk("legacy", (self.work / "legacy.uimg").read_bytes())

        # TC-04: boot-loader environment injected at stock U-Boot's env location.
        (self.work / "env.txt").write_text(
            "bootdelay=1\n"
            "bootcmd=echo P2-ENV-INJECTED; virtio scan; virtio read 0x50000000 0 0x20000; "
            "bootm 0x50000000 - ${fdtcontroladdr}\n"
            "bootargs=console=ttyAMA0 rdinit=/init panic=-1\n")
        run([str(self.mkenvimage), "-s", hex(ENV_SIZE), "-o", str(self.work / "env.bin"), str(self.work / "env.txt")])
        self.flash_image("env", (self.work / "env.bin").read_bytes())

    def hashes(self) -> dict[str, str]:
        names = ["ctrl.dtb", "kernel.dtb", "good.itb", "unsigned.itb", "rogue.itb", "added-config.itb",
                 "tamper-kernel.itb", "tamper-ramdisk.itb", "tamper-fdt.itb", "legacy.uimg", "env.bin"]
        out = {n: sha256(self.work / n) for n in names}
        for n in ("u-boot-hardened.bin", "u-boot-stock.bin", "u-boot-hardened.config", "u-boot-stock.config",
                  "Image.gz", "initramfs.cpio.gz"):
            out[n] = sha256(self.build / n)
        return out


# --- cases -------------------------------------------------------------------

@dataclasses.dataclass
class Case:
    id: str
    tc: str
    role: str            # positive | test | control
    title: str
    uboot: str = "hardened"
    slot: str = "good"
    flash: str = "blank"
    keys: bool = False
    expect: list[str] = dataclasses.field(default_factory=list)
    forbid: list[str] = dataclasses.field(default_factory=list)
    stop: str | None = None


CASES = [
    Case("TC-01", "TC-01", "positive", "Signed chain boots to the initramfs",
         expect=[VERIFIED, KERNEL_START, BOOTED], forbid=[PROMPT, ENV_MARK]),
    # TC-03: the configuration signature still verifies (the signed hash values are
    # untouched); the per-image hash check catches the changed byte.
    Case("TC-03a", "TC-03", "test", "Kernel changed after signing", slot="tamper-kernel",
         expect=[VERIFIED, r"Bad hash value for 'hash' hash node in 'kernel' image node", RESET],
         forbid=REFUSED),
    Case("TC-03b", "TC-03", "test", "Initramfs changed after signing", slot="tamper-ramdisk",
         expect=[VERIFIED, r"Bad hash value for 'hash' hash node in 'ramdisk' image node", RESET],
         forbid=REFUSED),
    Case("TC-03c", "TC-03", "test", "Devicetree changed after signing", slot="tamper-fdt",
         expect=[VERIFIED, r"Bad hash value for 'hash' hash node in 'fdt' image node", RESET],
         forbid=REFUSED),
    Case("TC-04b", "TC-04", "test", "Unsigned configuration added after signing and made default",
         slot="added-config",
         expect=[r"Using 'conf-alt' configuration", r"No 'signature' subnode found for 'conf-alt' config node",
                 REQUIRED_FAIL, RESET],
         forbid=REFUSED),
    Case("TC-04c", "TC-04", "test", "Unsigned FIT", slot="unsigned",
         expect=[r"No 'signature' subnode found for 'conf' config node", REQUIRED_FAIL, RESET],
         forbid=REFUSED + [VERIFIED]),
    Case("TC-04d", "TC-04", "test", "FIT signed by a rogue key with the same key name", slot="rogue",
         expect=[rf"sha256,rsa3072:{KEY_NAME}-\s+error!", r"Verification failed for 'conf' config node",
                 REQUIRED_FAIL, RESET],
         forbid=REFUSED + [VERIFIED]),
    Case("TC-04e", "TC-04", "test", "Legacy uImage in the boot slot", slot="legacy",
         expect=[r"Wrong Image Type for bootm command", RESET], forbid=REFUSED + [LINUX]),
    Case("TC-04e-control", "TC-04", "control", "Stock U-Boot boots the same legacy uImage (via injected environment)",
         uboot="stock", slot="legacy", flash="env",
         expect=[ENV_MARK, r"Booting kernel from Legacy Image", KERNEL_START, LINUX]),
    Case("TC-04f", "TC-04", "test", "Environment injected into flash is ignored", flash="env",
         expect=[VERIFIED, BOOTED], forbid=[ENV_MARK, PROMPT]),
    Case("TC-04f-control", "TC-04", "control", "Stock U-Boot runs the injected environment",
         uboot="stock", flash="env", expect=[ENV_MARK]),
    Case("TC-04g", "TC-04", "test", "Keystrokes during a good boot do not interrupt it",
         keys=True, expect=[VERIFIED, BOOTED], forbid=[PROMPT]),
    Case("TC-04h", "TC-04", "test", "Keystrokes after a refused boot reach no prompt",
         slot="tamper-kernel", keys=True, expect=[RESET], forbid=REFUSED),
    Case("TC-04g-control", "TC-04", "control", "Keystrokes stop stock U-Boot at a prompt",
         uboot="stock", keys=True, expect=[PROMPT], stop=PROMPT),
]


def check_config(path: Path) -> list[dict]:
    """TC-04a: every line of the P2 fragments is present in the built .config."""
    text = set(path.read_text().splitlines())
    checks = []
    for frag in FRAGMENTS:
        for line in frag.read_text().splitlines():
            if line.startswith("CONFIG_") or re.match(r"^# CONFIG_\S+ is not set$", line):
                checks.append({"kind": "config", "pattern": line, "ok": line in text})
    return checks


def evaluate(case: Case, text: str, reason: str) -> list[dict]:
    checks = [{"kind": "expect", "pattern": p, "ok": bool(re.search(p, text))} for p in case.expect]
    checks += [{"kind": "forbid", "pattern": p, "ok": not re.search(p, text)} for p in case.forbid]
    ended_ok = reason == ("stopped" if case.stop else "exited")
    checks.append({"kind": "end", "pattern": f"run ended: {reason}", "ok": ended_ok})
    return checks


# --- main --------------------------------------------------------------------

def git_state() -> dict[str, str]:
    try:
        commit = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.strip()
        dirty = bool(run(["git", "-C", str(ROOT), "status", "--porcelain", "--", "cc", "tests"]).stdout.strip())
        return {"commit": commit, "cc_or_tests_modified": str(dirty).lower()}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "unknown", "cc_or_tests_modified": "unknown"}


def write_markdown(out: Path, summary: dict) -> None:
    lines = [
        "# VE-07 emulated run: verified boot (TC-01, TC-03, TC-04)", "",
        f"- Date (UTC): {summary['date_utc']}",
        f"- Code commit: `{summary['git']['commit']}` (cc/ or tests/ modified: {summary['git']['cc_or_tests_modified']})",
        f"- Result: **{'PASS' if summary['passed'] else 'FAIL'}**",
        "", "| Test case | Result |", "|---|---|",
    ]
    lines += [f"| {tc} | {res} |" for tc, res in summary["test_cases"].items()]
    lines += ["", "| Run | Role | What | Result | Seconds | Log |", "|---|---|---|---|---|---|"]
    for r in summary["runs"]:
        log = f"[{r['log']}]({r['log']})" if r.get("log") else "–"
        lines.append(f"| {r['id']} | {r['role']} | {r['title']} | {'pass' if r['ok'] else '**FAIL**'} | "
                     f"{r.get('seconds', 0):.0f} | {log} |")
    lines += ["", "Every check behind each result is in `summary.json`.", ""]
    (out / "summary.md").write_text("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--build", type=Path, default=ROOT / "build", help="cc/build.sh output")
    parser.add_argument("--out", type=Path, required=True, help="evidence folder to create")
    parser.add_argument("--work", type=Path, help="keep intermediate files here (default: temporary)")
    parser.add_argument("--only", nargs="*", help="run only these case IDs (TC-01 always runs)")
    args = parser.parse_args(argv)

    out = args.out.resolve()
    build = args.build.resolve()
    out.mkdir(parents=True, exist_ok=True)
    short = Path(tempfile.mkdtemp(prefix="p2ve07-"))   # short path: swtpm socket and keys
    work = args.work.resolve() if args.work else Path(tempfile.mkdtemp(prefix="p2ve07-work-"))
    work.mkdir(parents=True, exist_ok=True)
    try:
        art = Artifacts(build, work, short)
        art.build_all()

        runs = []
        cfg_checks = check_config(build / "u-boot-hardened.config")
        runs.append({"id": "TC-04a", "tc": "TC-04", "role": "test",
                     "title": "Built .config holds every P2 setting", "ok": all(c["ok"] for c in cfg_checks),
                     "checks": cfg_checks, "log": None})

        selected = [c for c in CASES if not args.only or c.id in args.only or c.id == "TC-01"]
        for case in selected:
            tpm = Swtpm(short / f"tpm-{case.id}")
            try:
                m = Machine(art.uboot[case.uboot], art.slots[case.slot], art.flash[case.flash],
                            work / "ctrl.dtb", tpm.sock)
                text, reason, secs = boot(m, CASE_TIMEOUT, keys=case.keys, stop=case.stop)
            finally:
                tpm.stop()
            log = f"{case.id}.log"
            (out / log).write_text(text)
            checks = evaluate(case, text, reason)
            ok = all(c["ok"] for c in checks)
            runs.append({"id": case.id, "tc": case.tc, "role": case.role, "title": case.title,
                         "uboot": case.uboot, "slot": case.slot, "flash": case.flash, "keys": case.keys,
                         "ok": ok, "checks": checks, "end": reason, "seconds": round(secs, 1), "log": log})
            print(f"{'PASS' if ok else 'FAIL'}  {case.id:15} {case.title} ({secs:.0f}s, {reason})", flush=True)

        positive = next(r for r in runs if r["role"] == "positive")
        test_cases = {}
        for r in runs:
            tc = r["tc"]
            if not positive["ok"] and r is not positive:
                r["ok"] = False
                r["note"] = "not counted: the positive control (TC-01) failed in this run"
            test_cases[tc] = "passed" if test_cases.get(tc, "passed") == "passed" and r["ok"] else "failed"

        summary = {
            "event": "VE-07", "environment": "ci (emulated)",
            "date_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "git": git_state(),
            "passed": all(r["ok"] for r in runs),
            "test_cases": dict(sorted(test_cases.items())),
            "host": {
                "os": platform.platform(), "python": platform.python_version(),
                "qemu": first_line(["qemu-system-aarch64", "--version"]),
                "swtpm": first_line(["swtpm", "--version"]),
                "openssl": first_line(["openssl", "version"]),
                "dtc": first_line(["dtc", "--version"]),
                "mkimage": first_line([str(art.mkimage), "-V"]),
            },
            "pins": {
                "u-boot": (ROOT / "cc/uboot/pin.txt").read_text(),
                "guest": (ROOT / "cc/emu/guest.lock").read_text(),
            },
            "public_keys_sha256_der": art.public_keys,
            "artifacts_sha256": art.hashes(),
            "notes": art.notes,
            "runs": runs,
        }
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        write_markdown(out, summary)
        print(f"{'PASS' if summary['passed'] else 'FAIL'}: {sum(r['ok'] for r in runs)}/{len(runs)} runs; "
              + ", ".join(f"{k} {v}" for k, v in sorted(test_cases.items())))
        return 0 if summary["passed"] else 1
    finally:
        shutil.rmtree(short, ignore_errors=True)   # removes the per-run private keys
        if not args.work:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
