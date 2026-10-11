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

Each attack that would succeed against a weaker setup has a control run that
shows it succeeding there: the environment and legacy-image cases on stock
qemu_arm64_defconfig, and the two console cases on the P2 build with exactly
one setting changed (the autoboot delay, or the final reset). A negative case
counts only if the positive control passed in the same run.

Keys are generated per run in a temporary directory and deleted; evidence
records only public-key SHA-256 values. Writes one console log per case and
summary.json/summary.md to --out. Exit status 0 only if every case passes.

Usage:
    python3 tests/ve07/boot_cases.py --build build --out evidence/ve07-ci/<run>

Standard library only. Needs qemu-system-aarch64, swtpm, openssl, dtc,
fdtget and fdtput on PATH, and mkimage/mkenvimage from the U-Boot build.
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
sys.path.insert(0, str(ROOT / "cc" / "uboot"))
import check_config  # noqa: E402

KEY_NAME = "cc-os-dev"
FIT_SOURCE = ROOT / "cc/fit/cc.its"
FIT_ADDR_SLOT_BYTES = 64 * 1024 * 1024   # matches "virtio read 0x50000000 0 0x20000"
FLASH_BYTES = 64 * 1024 * 1024           # QEMU virt flash bank size
ENV_SIZE = 0x40000                       # stock qemu_arm64 CONFIG_ENV_SIZE (flash1 offset 0)
EVENT_LOG = (0x60000000, 0x10000)        # TPM event-log region handed to Linux
CASE_TIMEOUT = 240
KEY_TICK = 0.2                           # seconds between keystrokes
MIN_KEYS = 5                             # a keystroke case must type at least this many

# The P2 build and the variants used only for control runs (cc/build.sh).
FRAGMENTS = [ROOT / "cc/uboot/p2.config", ROOT / "cc/uboot/qemu.config"]
CONTROL_FRAGMENTS = {
    "ctl-bootdelay": ROOT / "cc/uboot/controls/bootdelay.config",
    "ctl-noreset": ROOT / "cc/uboot/controls/noreset.config",
}
UBOOT_VARIANTS = ["hardened", "stock", *CONTROL_FRAGMENTS]

# Console patterns, matched after ANSI escape sequences are removed.
VERIFIED = rf"sha256,rsa3072:{KEY_NAME}\+ OK"
BOOTED = r"P2-INITRAMFS-OK kernel=\S+"
KERNEL_START = r"Starting kernel"
# Typed input echoed back by the Linux console: keystrokes were still arriving after U-Boot.
ECHOED_IN_LINUX = r"(?s)Starting kernel.*\n\s*help\s*\n"
LINUX = r"Linux version \d"
BANNER = r"(?m)^U-Boot 20\d\d\.\d\d"
CONSOLE_UP = r"(?m)^In:\s+serial"          # U-Boot's console is ready for input
PROMPT = r"(?m)^=> "
AUTOBOOT = r"Hit any key to stop autoboot"
HELP_OUT = r"(?m)^bootm\s+- boot application image"
UNKNOWN_CMD = r"Unknown command"
BOOTFLOW_SCAN = r"Scanning for bootflows"
RESET = r"resetting \.\.\."
ENV_MARK = r"(?m)^P2-ENV-INJECTED$"
REQUIRED_FAIL = rf"Failed to verify required signature 'key-{KEY_NAME}'"
BAD_KERNEL = r"Bad hash value for 'hash' hash node in 'kernel' image node"
CONSOLE = [PROMPT, AUTOBOOT, HELP_OUT, UNKNOWN_CMD]
REFUSED = [KERNEL_START, BOOTED, ENV_MARK, *CONSOLE]
ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|[78])")


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


def clean(text: str) -> str:
    """Console text as matched: ANSI escape sequences and carriage returns removed."""
    return ANSI.sub("", text).replace("\r", "")


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
    reboot: bool = False

    def argv(self, dumpdtb: Path | None = None) -> list[str]:
        machine = "virt,gic-version=3" + (f",dumpdtb={dumpdtb}" if dumpdtb else "")
        argv = [
            "qemu-system-aarch64", "-machine", machine, "-cpu", "cortex-a57", "-smp", "1", "-m", "2G",
            "-display", "none", "-serial", "stdio", "-monitor", "none", "-nic", "none",
            "-bios", str(self.bios),
            "-chardev", f"socket,id=chrtpm,path={self.tpm_sock}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis-device,tpmdev=tpm0",
            "-drive", f"if=none,id=slot,file={self.slot},format=raw,readonly=on",
            "-device", "virtio-blk-device,drive=slot",
            "-drive", f"if=pflash,unit=1,file={self.flash1},format=raw,readonly=on",
        ]
        if not self.reboot:
            argv.append("-no-reboot")   # a guest reset ends the run
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


@dataclasses.dataclass
class BootResult:
    text: str        # raw console output
    reason: str      # exited | stopped | timeout
    seconds: float
    keys_sent: int


def keystroke(tick: int) -> bytes:
    """What an attacker at the serial console types: a command every fifth tick, spaces between."""
    return b"help\r" if tick % 5 == 0 else b" "


def boot(machine: Machine, timeout: int, keys_from: str | None = None, stop: str | None = None,
         stop_count: int = 1) -> BootResult:
    """Run QEMU until it exits, `stop` has appeared `stop_count` times, or timeout.

    With `keys_from` set, keystrokes are typed at the serial console every
    KEY_TICK seconds from the moment that pattern appears until the run ends.
    Typing starts at a console line, not at power-on: in QEMU, keystrokes sent
    before U-Boot's console is up never stopped stock autoboot in our runs,
    while keystrokes sent after it did.
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
    reason, ticks, typing = "exited", 0, False
    while proc.poll() is None:
        if time.monotonic() - start > timeout:
            reason = "timeout"
            break
        text = clean(b"".join(chunks).decode("utf-8", "replace"))
        if stop and len(re.findall(stop, text)) >= stop_count:
            reason = "stopped"
            break
        typing = typing or bool(keys_from and re.search(keys_from, text))
        if typing:
            try:
                proc.stdin.write(keystroke(ticks))
                proc.stdin.flush()
                ticks += 1
            except (BrokenPipeError, OSError):
                pass
        time.sleep(KEY_TICK)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
    thread.join(5)
    return BootResult(b"".join(chunks).decode("utf-8", "replace"), reason, time.monotonic() - start, ticks)


# --- artifacts ---------------------------------------------------------------

class Artifacts:
    """Keys, devicetrees, FIT variants, slot disks and flash images for one run."""

    def __init__(self, build: Path, work: Path, short: Path) -> None:
        self.build, self.work, self.short = build, work, short
        self.mkimage, self.mkenvimage = build / "mkimage", build / "mkenvimage"
        self.uboot = {v: build / f"u-boot-{v}.bin" for v in UBOOT_VARIANTS}
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
        its = FIT_SOURCE.read_text()
        unsigned, n = re.subn(r"\n\t+signature \{.*?\n\t+\};", "", its, flags=re.S)
        if n != 1:
            raise ValueError(f"{FIT_SOURCE.name}: expected one signature node, found {n}")
        (self.work / "fit.its").write_text(its)
        (self.work / "fit-unsigned.its").write_text(unsigned)

        # Signed FIT; the public key goes into the control DT as a required key.
        self.make_image("-f", "fit.its", "-K", "ctrl.dtb", "-k", str(self.short / "keys"), "-r", "good.itb")
        good = self.work / "good.itb"
        self.disk("good", good.read_bytes())
        self.notes["key_required"] = run(["fdtget", str(self.work / "ctrl.dtb"),
                                          f"/signature/key-{KEY_NAME}", "required"]).stdout.strip()

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
        names = ["fit.its", "ctrl.dtb", "kernel.dtb", "good.itb", "unsigned.itb", "rogue.itb", "added-config.itb",
                 "tamper-kernel.itb", "tamper-ramdisk.itb", "tamper-fdt.itb", "legacy.uimg", "env.bin"]
        out = {n: sha256(self.work / n) for n in names}
        built = [f"u-boot-{v}.{ext}" for v in UBOOT_VARIANTS for ext in ("bin", "config")]
        for n in built + ["Image.gz", "initramfs.cpio.gz", "mkimage", "mkenvimage"]:
            out[n] = sha256(self.build / n)
        return out


# --- cases -------------------------------------------------------------------

Expect = str | tuple[str, int]   # a pattern, or (pattern, minimum number of matches)


@dataclasses.dataclass
class Case:
    id: str
    tc: str
    role: str            # positive | test | control
    title: str
    uboot: str = "hardened"
    slot: str = "good"
    flash: str = "blank"
    keys_from: str | None = None
    reboot: bool = False
    expect: list[Expect] = dataclasses.field(default_factory=list)
    forbid: list[str] = dataclasses.field(default_factory=list)
    stop: str | None = None
    stop_count: int = 1
    control_for: str | None = None


CASES = [
    Case("TC-01", "TC-01", "positive", "Signed chain boots to the initramfs",
         expect=[VERIFIED, KERNEL_START, BOOTED], forbid=[ENV_MARK, *CONSOLE]),
    # TC-03: the configuration signature still verifies (the signed hash values are
    # untouched); the per-image hash check catches the changed byte.
    Case("TC-03a", "TC-03", "test", "Kernel changed after signing", slot="tamper-kernel",
         expect=[VERIFIED, BAD_KERNEL, RESET], forbid=REFUSED),
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
         forbid=[*REFUSED, VERIFIED]),
    Case("TC-04d", "TC-04", "test", "FIT signed by a rogue key with the same key name", slot="rogue",
         expect=[rf"sha256,rsa3072:{KEY_NAME}-\s+error!", r"Verification failed for 'conf' config node",
                 REQUIRED_FAIL, RESET],
         forbid=[*REFUSED, VERIFIED]),
    Case("TC-04e", "TC-04", "test", "Legacy uImage in the boot slot", slot="legacy",
         expect=[r"Wrong Image Type for bootm command", RESET], forbid=[*REFUSED, LINUX]),
    Case("TC-04e-control", "TC-04", "control", "Stock U-Boot boots the same legacy uImage (via injected environment)",
         uboot="stock", slot="legacy", flash="env", control_for="TC-04e",
         expect=[ENV_MARK, r"Booting kernel from Legacy Image", KERNEL_START, LINUX]),
    Case("TC-04f", "TC-04", "test", "Environment injected into flash is ignored", flash="env",
         expect=[VERIFIED, BOOTED], forbid=[ENV_MARK, *CONSOLE]),
    Case("TC-04f-control", "TC-04", "control", "Stock U-Boot runs the injected environment",
         uboot="stock", flash="env", control_for="TC-04f", expect=[ENV_MARK]),
    Case("TC-04g", "TC-04", "test", "Keystrokes from console start to the end of a good boot reach no prompt",
         keys_from=CONSOLE_UP, expect=[VERIFIED, BOOTED, ECHOED_IN_LINUX], forbid=CONSOLE),
    Case("TC-04g-control", "TC-04", "control", "The same keystrokes stop autoboot when only the delay is restored",
         uboot="ctl-bootdelay", keys_from=CONSOLE_UP, control_for="TC-04g", stop=HELP_OUT,
         expect=[AUTOBOOT, PROMPT, HELP_OUT], forbid=[BOOTFLOW_SCAN, VERIFIED, KERNEL_START]),
    Case("TC-04h", "TC-04", "test", "Keystrokes after a refused boot reach no prompt; the board resets and refuses again",
         slot="tamper-kernel", reboot=True, keys_from=BAD_KERNEL, stop=BAD_KERNEL, stop_count=5,
         expect=[(BANNER, 5), (BAD_KERNEL, 5), RESET], forbid=[KERNEL_START, BOOTED, *CONSOLE]),
    Case("TC-04h-control", "TC-04", "control", "The same keystrokes reach a prompt when only the reset is removed",
         uboot="ctl-noreset", slot="tamper-kernel", keys_from=BAD_KERNEL, control_for="TC-04h", stop=HELP_OUT,
         expect=[BAD_KERNEL, PROMPT, HELP_OUT], forbid=[KERNEL_START, RESET]),
]


def check_configs(build: Path) -> list[dict]:
    """TC-04a: the hardened .config holds every P2 setting, and each control
    build differs from it in exactly the one setting its fragment changes."""
    checks = check_config.check(build / "u-boot-hardened.config", FRAGMENTS)
    for variant, frag in CONTROL_FRAGMENTS.items():
        want = sorted(check_config.expected([frag]).values())
        got = check_config.diff(build / f"u-boot-{variant}.config", build / "u-boot-hardened.config")
        checks.append({"kind": "control-diff", "pattern": f"{variant} differs from hardened only by {want}",
                       "ok": got == want, "observed": got})
    return checks


def evaluate(case: Case, text: str, reason: str, keys_sent: int = 0) -> list[dict]:
    text = clean(text)
    checks = []
    for e in case.expect:
        pattern, need = (e, 1) if isinstance(e, str) else e
        found = len(re.findall(pattern, text))
        label = pattern if need == 1 else f"{pattern} (at least {need}x)"
        checks.append({"kind": "expect", "pattern": label, "ok": found >= need})
    checks += [{"kind": "forbid", "pattern": p, "ok": not re.search(p, text)} for p in case.forbid]
    if case.keys_from and case.role != "control":   # a control's expected console output shows typing
        checks.append({"kind": "keys", "pattern": f"at least {MIN_KEYS} keystrokes typed (typed {keys_sent})",
                       "ok": keys_sent >= MIN_KEYS})
    ended_ok = reason == ("stopped" if case.stop else "exited")
    checks.append({"kind": "end", "pattern": f"run ended: {reason}", "ok": ended_ok})
    return checks


# --- provenance --------------------------------------------------------------

def environment() -> dict[str, str]:
    """Where this run happened. Only a GitHub Actions run counts as CI evidence."""
    env = os.environ
    if env.get("GITHUB_ACTIONS") != "true":
        return {"kind": "local"}
    server, repo, run_id = env.get("GITHUB_SERVER_URL", ""), env.get("GITHUB_REPOSITORY", ""), env.get("GITHUB_RUN_ID", "")
    return {
        "kind": "ci",
        "run_id": run_id,
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
        "run_url": f"{server}/{repo}/actions/runs/{run_id}",
        "workflow": env.get("GITHUB_WORKFLOW", ""),
        "event": env.get("GITHUB_EVENT_NAME", ""),
        "ref": env.get("GITHUB_REF", ""),
        "sha": env.get("GITHUB_SHA", ""),
        "runner_image": f"{env.get('ImageOS', '')} {env.get('ImageVersion', '')}".strip(),
    }


def host_packages(path: Path = ROOT / "cc/emu/host-packages.txt") -> dict:
    """Installed versions of the pinned host packages, compared with the pins."""
    snapshot, packages = "", []
    for line in path.read_text().splitlines():
        if line.startswith("snapshot:"):
            snapshot = line.split(":", 1)[1].strip()
        elif line.strip() and not line.startswith("#"):
            name, want = line.split()
            try:
                got = run(["dpkg-query", "-W", "-f=${Version}", name]).stdout.strip()
            except (OSError, subprocess.CalledProcessError):
                got = "missing"
            packages.append({"name": name, "pinned": want, "installed": got, "ok": got == want})
    return {"snapshot": snapshot, "all_match": all(p["ok"] for p in packages), "packages": packages}


def git_state() -> dict[str, str]:
    try:
        commit = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.strip()
        dirty = bool(run(["git", "-C", str(ROOT), "status", "--porcelain", "--", "cc", "tests"]).stdout.strip())
        return {"commit": commit, "cc_or_tests_modified": str(dirty).lower()}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "unknown", "cc_or_tests_modified": "unknown"}


def write_markdown(out: Path, summary: dict) -> None:
    env = summary["environment"]
    where = f"GitHub Actions run [{env['run_id']}]({env['run_url']}) ({env['runner_image']})" \
        if env["kind"] == "ci" else "local run (not CI evidence)"
    lines = [
        "# VE-07 emulated run: verified boot (TC-01, TC-03, TC-04)", "",
        f"- Date (UTC): {summary['date_utc']}",
        f"- Where: {where}",
        f"- Code commit: `{summary['git']['commit']}` (cc/ or tests/ modified: {summary['git']['cc_or_tests_modified']})",
        f"- Host packages match the pins (snapshot {summary['host_packages']['snapshot']}): "
        f"{'yes' if summary['host_packages']['all_match'] else '**no**'}",
        f"- Result: **{'PASS' if summary['passed'] else 'FAIL'}**",
        "", "| Test case | Result |", "|---|---|",
    ]
    lines += [f"| {tc} | {res} |" for tc, res in summary["test_cases"].items()]
    lines += ["", "| Run | Role | What | Result | Seconds | Log |", "|---|---|---|---|---|---|"]
    for r in summary["runs"]:
        log = f"[{r['log']}]({r['log']})" if r.get("log") else "–"
        role = r["role"] + (f" for {r['control_for']}" if r.get("control_for") else "")
        lines.append(f"| {r['id']} | {role} | {r['title']} | {'pass' if r['ok'] else '**FAIL**'} | "
                     f"{r.get('seconds', 0):.0f} | {log} |")
    lines += ["", "Every check behind each result is in `summary.json`. Logs are the raw console output; "
              "patterns are matched with ANSI escape sequences removed.", ""]
    (out / "summary.md").write_text("\n".join(lines))


# --- main --------------------------------------------------------------------

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
        cfg_checks = check_configs(build)
        cfg_checks.append({"kind": "required-key", "pattern": f"control DT marks key-{KEY_NAME} required",
                           "ok": art.notes["key_required"] in ("conf", "image"),
                           "observed": art.notes["key_required"]})
        runs.append({"id": "TC-04a", "tc": "TC-04", "role": "test",
                     "title": "Built .config holds every P2 setting; each control build changes exactly one",
                     "ok": all(c["ok"] for c in cfg_checks), "checks": cfg_checks, "log": None})

        selected = [c for c in CASES if not args.only or c.id in args.only or c.id == "TC-01"]
        for case in selected:
            tpm = Swtpm(short / f"tpm-{case.id}")
            try:
                m = Machine(art.uboot[case.uboot], art.slots[case.slot], art.flash[case.flash],
                            work / "ctrl.dtb", tpm.sock, reboot=case.reboot)
                res = boot(m, CASE_TIMEOUT, keys_from=case.keys_from, stop=case.stop, stop_count=case.stop_count)
            finally:
                tpm.stop()
            log = f"{case.id}.log"
            (out / log).write_text(res.text)
            checks = evaluate(case, res.text, res.reason, res.keys_sent)
            ok = all(c["ok"] for c in checks)
            runs.append({"id": case.id, "tc": case.tc, "role": case.role, "title": case.title,
                         "control_for": case.control_for, "uboot": case.uboot, "slot": case.slot,
                         "flash": case.flash, "keys_from": case.keys_from, "keys_sent": res.keys_sent,
                         "reboot": case.reboot, "ok": ok, "checks": checks, "end": res.reason,
                         "seconds": round(res.seconds, 1), "log": log, "log_sha256": sha256(out / log)})
            print(f"{'PASS' if ok else 'FAIL'}  {case.id:15} {case.title} ({res.seconds:.0f}s, {res.reason})",
                  flush=True)

        positive = next(r for r in runs if r["role"] == "positive")
        test_cases = {}
        for r in runs:
            tc = r["tc"]
            if not positive["ok"] and r is not positive:
                r["ok"] = False
                r["note"] = "not counted: the positive control (TC-01) failed in this run"
            test_cases[tc] = "passed" if test_cases.get(tc, "passed") == "passed" and r["ok"] else "failed"

        env = environment()
        pkgs = host_packages()
        toolchain = build / "toolchain.txt"
        summary = {
            "event": "VE-07", "harness": "tests/ve07/boot_cases.py",
            "environment": env,
            "date_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "git": git_state(),
            # CI evidence also needs every host package at its pinned version.
            "passed": all(r["ok"] for r in runs) and (pkgs["all_match"] or env["kind"] != "ci"),
            "test_cases": dict(sorted(test_cases.items())),
            "host": {
                "os": platform.platform(), "python": platform.python_version(),
                "qemu": first_line(["qemu-system-aarch64", "--version"]),
                "swtpm": first_line(["swtpm", "--version"]),
                "openssl": first_line(["openssl", "version"]),
                "dtc": first_line(["dtc", "--version"]),
                "mkimage": first_line([str(art.mkimage), "-V"]),
            },
            "host_packages": pkgs,
            "toolchain": toolchain.read_text().splitlines() if toolchain.exists() else [],
            "pins": {
                "u-boot": (ROOT / "cc/uboot/pin.txt").read_text(),
                "guest": (ROOT / "cc/emu/guest.lock").read_text(),
            },
            "public_keys_sha256_der": art.public_keys,
            "artifacts_sha256": art.hashes(),
            "notes": art.notes,
            "runs": runs,
        }
        if env["kind"] == "ci" and not pkgs["all_match"]:
            for tc in summary["test_cases"]:
                summary["test_cases"][tc] = "failed"
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        write_markdown(out, summary)
        print(f"{'PASS' if summary['passed'] else 'FAIL'}: {sum(r['ok'] for r in runs)}/{len(runs)} runs; "
              + ", ".join(f"{k} {v}" for k, v in sorted(summary["test_cases"].items())))
        return 0 if summary["passed"] else 1
    finally:
        shutil.rmtree(short, ignore_errors=True)   # removes the per-run private keys
        if not args.work:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
