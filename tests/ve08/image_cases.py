#!/usr/bin/env python3
"""VE-08, on the host: FC images signed and checked with PX4's own verification code (TC-11).

fc/build.sh builds px4_fmu-v6x_bootloader_secureboot with a per-run key
(K-FC-FW dev) in key slot 0 and px4_fmu-v6x_secureboot signed with it, at the
pinned PX4 commit, in the pinned PX4 container. This harness then:

  - checks that the boot loader holds the run key and not PX4's public test
    key, and that the .px4 upload envelope carries the signed image;
  - builds tests/ve08/host/check_image.c with PX4's find_toc(), verify_app(),
    stub keystore and monocypher for a 32-bit host, once with the run key in
    slot 0 as the boot loader has it, and once with PX4's test key;
  - asks it whether the boot loader would start each image:

  TC-11a  the image the build signed with the run key        starts (positive)
  TC-11b  the image as built, unsigned                        stays in the boot loader
  TC-11c  the signed image with one byte changed after signing  stays
  TC-11d  the image signed with PX4's public test key          stays
          control: the same image starts under a checker holding the test key,
          so TC-11d fails on the key alone

A negative case counts only if TC-11a passed in the same run. Writes one log per
case and summary.json/summary.md to --out; exit status 0 only if every case passes.

Usage:
    python3 tests/ve08/image_cases.py --px4 <checkout> --fc <fc/build.sh output> --out <evidence>

Standard library only. Needs gcc with -m32 support (fc/host-packages.txt).
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "ve07"))
import boot_cases  # noqa: E402  (provenance helpers shared with VE-07)

HOST = Path(__file__).resolve().parent / "host"
APP_LOAD_ADDRESS = 0x08020000
TOC_OFFSET = 0x800
SIGNATURE_SIZE = 64
STARTS = r"(?m)^P2-FC result: starts the application at 0x08020000$"
STAYS = r"(?m)^P2-FC result: stays in the boot loader: "
BOOT_ENTRY = re.compile(r"(?m)^P2-FC toc 0: BOOT 0x([0-9a-f]{8})-0x([0-9a-f]{8}) signature=(\d+) key=(\d+) flags=0x([0-9a-f]{2})$")


def public_key(c_array: Path) -> bytes:
    """The 32 key bytes of a PX4 .pub file (a C array body, as generate_signing_keys.py writes it)."""
    values = re.findall(r"0x([0-9a-fA-F]{1,2})", re.sub(r"//.*", "", c_array.read_text()))
    if len(values) != 32:
        raise ValueError(f"{c_array}: expected 32 bytes, found {len(values)}")
    return bytes(int(v, 16) for v in values)


def px4_image(envelope: Path) -> tuple[bytes, dict]:
    """The firmware image inside a .px4 file, and the envelope's other fields."""
    desc = json.loads(envelope.read_text())
    image = zlib.decompress(base64.b64decode(desc.pop("image")))
    for field in ("parameter_xml", "airframe_xml"):
        desc.pop(field, None)
    return image, desc


def flip_in_app(signed: bytes) -> tuple[bytes, int]:
    """The signed image with one byte inverted in the signed range, past the TOC."""
    at = TOC_OFFSET + (len(signed) - SIGNATURE_SIZE - TOC_OFFSET) // 2
    out = bytearray(signed)
    out[at] ^= 0xFF
    return bytes(out), at


def build_checker(px4: Path, key: Path, out: Path) -> list[str]:
    common = px4 / "platforms/nuttx/src/bootloader/common"
    mono = px4 / "src/lib/crypto/monocypher/src"
    cmd = ["gcc", "-m32", "-O2", "-Wall", "-fPIE", "-pie",
           # PX4's headers lean on NuttX for these; on Linux they must be named.
           "-include", "stdint.h", "-include", "stddef.h",
           f"-I{HOST}", f"-I{px4 / 'src/include'}", f"-I{common}", f"-I{px4 / 'platforms/common/include'}",
           f"-I{px4 / 'src/drivers/sw_crypto'}", f"-I{px4 / 'src/drivers/stub_keystore'}", f"-I{px4 / 'src'}",
           f"-I{mono}", f"-DPUBLIC_KEY0={key}",
           str(HOST / "check_image.c"), str(HOST / "sw_crypto_ed25519.c"),
           str(common / "image_toc.c"), str(common / "crypto.c"),
           str(px4 / "src/drivers/stub_keystore/stub_keystore.c"),
           str(mono / "monocypher.c"), str(mono / "optional/monocypher-ed25519.c"),
           "-o", str(out)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return cmd


@dataclasses.dataclass
class Case:
    id: str
    tc: str
    role: str        # positive | test | control
    title: str
    image: str
    checker: str     # run-key | test-key
    starts: bool
    control_for: str | None = None


CASES = [
    Case("TC-11a", "TC-11", "positive", "Image signed by the build with the run key", "signed", "run-key", True),
    Case("TC-11b", "TC-11", "test", "Image as built, unsigned", "unsigned", "run-key", False),
    Case("TC-11c", "TC-11", "test", "Signed image with one byte changed after signing", "modified", "run-key", False),
    Case("TC-11d", "TC-11", "test", "Image signed with PX4's public test key", "test-key", "run-key", False),
    Case("TC-11d-control", "TC-11", "control", "The same image starts when the test key is in slot 0", "test-key",
         "test-key", True, control_for="TC-11d"),
]


def evaluate(case: Case, text: str, code: int, signed_len: int) -> list[dict]:
    checks = [{"kind": "result", "pattern": STARTS if case.starts else STAYS, "ok": bool(re.search(
        STARTS if case.starts else STAYS, text)) and code == (0 if case.starts else 1), "observed": code}]
    # Every image carries the same TOC; only the bytes after it, and the signature, differ.
    m = BOOT_ENTRY.search(text)
    ok = bool(m) and int(m.group(1), 16) == APP_LOAD_ADDRESS and m.group(4) == "0" \
        and int(m.group(2), 16) == APP_LOAD_ADDRESS + signed_len - SIGNATURE_SIZE
    checks.append({"kind": "toc", "pattern": "TOC entry 0 is BOOT, checked with key slot 0, and ends where the "
                   "build put the signature", "ok": ok, "observed": m.group(0) if m else None})
    return checks


def static_checks(fc: Path, run_key: bytes, test_key: bytes) -> list[dict]:
    bootloader = (fc / "bootloader.bin").read_bytes()
    built, signed = (fc / "firmware.bin").read_bytes(), (fc / "firmware-signed.bin").read_bytes()
    padded = built + b"\xff" * (-len(built) % 4)
    image, desc = px4_image(fc / "firmware.px4")
    return [
        {"kind": "static", "pattern": "the boot loader holds the run key once", "ok": bootloader.count(run_key) == 1,
         "observed": bootloader.count(run_key)},
        {"kind": "static", "pattern": "the boot loader does not hold PX4's public test key",
         "ok": test_key not in bootloader},
        {"kind": "static", "pattern": "the signed image is the built image, padded to 4 bytes, plus a 64-byte signature",
         "ok": signed[:len(padded)] == padded and len(signed) == len(padded) + SIGNATURE_SIZE,
         "observed": {"built": len(built), "signed": len(signed)}},
        {"kind": "static", "pattern": "the .px4 envelope carries the signed image and marks it signed",
         "ok": image == signed and desc.get("image_signed") is True,
         "observed": {"image_sha256": hashlib.sha256(image).hexdigest(), "image_signed": desc.get("image_signed")}},
    ]


def host_packages() -> dict:
    return boot_cases.host_packages(ROOT / "fc/host-packages.txt")


def git_state() -> dict[str, str]:
    try:
        run = lambda *a: subprocess.run(["git", "-C", str(ROOT), *a], check=True, capture_output=True,  # noqa: E731
                                        text=True).stdout.strip()
        return {"commit": run("rev-parse", "HEAD"),
                "fc_or_tests_modified": str(bool(run("status", "--porcelain", "--", "fc", "tests"))).lower()}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "unknown", "fc_or_tests_modified": "unknown"}


def write_markdown(out: Path, summary: dict) -> None:
    env = summary["environment"]
    where = f"GitHub Actions run [{env['run_id']}]({env['run_url']}) ({env['runner_image']})" \
        if env["kind"] == "ci" else "local run (not CI evidence)"
    lines = [
        "# VE-08 host run: FC images checked with PX4's verification code (TC-11)", "",
        f"- Date (UTC): {summary['date_utc']}",
        f"- Where: {where}",
        f"- Code commit: `{summary['git']['commit']}` (fc/ or tests/ modified: {summary['git']['fc_or_tests_modified']})",
        f"- PX4: `{summary['build_info'].get('px4_commit', '?')}` ({summary['build_info'].get('px4_describe', '?')}), "
        f"built in `{summary['pins']['container']}`",
        f"- Host packages match the pins (snapshot {summary['host_packages']['snapshot']}): "
        f"{'yes' if summary['host_packages']['all_match'] else '**no**'}",
        f"- Result: **{'PASS' if summary['passed'] else 'FAIL'}**", "",
        "| Check | Result |", "|---|---|",
    ]
    lines += [f"| {c['pattern']} | {'pass' if c['ok'] else '**FAIL**'} |" for c in summary["static"]]
    lines += ["", "| Run | Role | Image | Checker key in slot 0 | Expected | Result | Log |", "|---|---|---|---|---|---|---|"]
    for r in summary["runs"]:
        role = r["role"] + (f" for {r['control_for']}" if r.get("control_for") else "")
        lines.append(f"| {r['id']} | {role} | {r['title']} | {r['checker']} | "
                     f"{'starts' if r['starts'] else 'stays in boot loader'} | {'pass' if r['ok'] else '**FAIL**'} | "
                     f"[{r['log']}]({r['log']}) |")
    lines += ["", "Every check is in `summary.json`. Each log is the checker's output for that image.", ""]
    (out / "summary.md").write_text("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--px4", type=Path, required=True, help="PX4 checkout the images were built from")
    parser.add_argument("--fc", type=Path, required=True, help="fc/build.sh output folder")
    parser.add_argument("--out", type=Path, required=True, help="evidence folder to create")
    args = parser.parse_args(argv)
    px4, fc, out = args.px4.resolve(), args.fc.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    run_key_file, test_key_file = fc / "k-fc-fw-dev.pub", px4 / "Tools/test_keys/key0.pub"
    run_key, test_key = public_key(run_key_file), public_key(test_key_file)
    signed = (fc / "firmware-signed.bin").read_bytes()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        modified, at = flip_in_app(signed)
        (work / "modified.bin").write_bytes(modified)
        images = {"signed": fc / "firmware-signed.bin", "unsigned": fc / "firmware.bin",
                  "modified": work / "modified.bin", "test-key": fc / "firmware-test-key.bin"}
        checkers = {"run-key": work / "check-run-key", "test-key": work / "check-test-key"}
        build_cmd = build_checker(px4, run_key_file, checkers["run-key"])
        build_checker(px4, test_key_file, checkers["test-key"])

        runs = []
        for case in CASES:
            res = subprocess.run([str(checkers[case.checker]), str(images[case.image])], capture_output=True, text=True)
            log = f"{case.id}.log"
            (out / log).write_text(res.stdout + res.stderr)
            checks = evaluate(case, res.stdout, res.returncode, len(signed))
            ok = all(c["ok"] for c in checks)
            runs.append({"id": case.id, "tc": case.tc, "role": case.role, "title": case.title, "image": case.image,
                         "checker": case.checker, "starts": case.starts, "control_for": case.control_for,
                         "ok": ok, "checks": checks, "log": log, "log_sha256": boot_cases.sha256(out / log)})
            print(f"{'PASS' if ok else 'FAIL'}  {case.id:15} {case.title}", flush=True)
        hashes = {f"{name}.bin": boot_cases.sha256(path) for name, path in images.items()}

    static = static_checks(fc, run_key, test_key)
    positive = next(r for r in runs if r["role"] == "positive")
    for r in runs:
        if not positive["ok"] and r is not positive:
            r["ok"] = False
            r["note"] = "not counted: the positive control (TC-11a) failed in this run"
    env, pkgs = boot_cases.environment(), host_packages()
    passed = all(r["ok"] for r in runs) and all(c["ok"] for c in static) and (pkgs["all_match"] or env["kind"] != "ci")
    pin = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in
           (ROOT / "fc/px4/pin.txt").read_text().splitlines() if line and not line.startswith("#")}
    build_info = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in
                  (fc / "build-info.txt").read_text().splitlines() if ":" in line}
    summary = {
        "event": "VE-08", "harness": "tests/ve08/image_cases.py", "environment": env,
        "date_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git": git_state(), "passed": passed,
        "test_cases": {"TC-11": "passed" if passed else "failed"},
        "pins": pin, "build_info": build_info,
        "build_info_matches_pin": build_info.get("px4_commit") == pin.get("commit"),
        "host": {"os": platform.platform(), "python": platform.python_version(),
                 "gcc": boot_cases.first_line(["gcc", "--version"])},
        "host_packages": pkgs,
        "checker_build": build_cmd,
        "public_keys_sha256": {"K-FC-FW dev (run key)": hashlib.sha256(run_key).hexdigest(),
                               "PX4 public test key": hashlib.sha256(test_key).hexdigest()},
        "modified_byte_offset": at,
        "artifacts_sha256": {**{f.name: boot_cases.sha256(f) for f in sorted(fc.iterdir()) if f.is_file()}, **hashes},
        "static": static, "runs": runs,
    }
    if not summary["build_info_matches_pin"]:
        summary["passed"] = False
        summary["test_cases"]["TC-11"] = "failed"
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    write_markdown(out, summary)
    print(f"{'PASS' if summary['passed'] else 'FAIL'}: {sum(r['ok'] for r in runs)}/{len(runs)} runs, "
          f"{sum(c['ok'] for c in static)}/{len(static)} static checks")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
