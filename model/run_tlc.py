#!/usr/bin/env python3
"""Usage: python3 model/run_tlc.py SPEC CFG TRACE    (e.g. model/Epoch.tla model/Epoch.cfg out/Epoch.json)

Runs TLC from tla2tools.jar, fetched to .cache/tla/ and refused unless its SHA-256 matches model/tla2tools.pin.
Prints "pass" or the violated name; writes a counterexample to TRACE as JSON and TLC's output to its .log.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VIOLATED = re.compile(r"^Error: (?:Invariant|Action property) (\w+) is violated\.$", re.M)
PASSED = "Model checking completed. No error has been found."


def read_pin(path: Path = ROOT / "model" / "tla2tools.pin") -> tuple[str, str]:
    """The jar's URL and SHA-256 from the pin's "key: value" lines (ValueError if malformed)."""
    lines = [line.split(":", 1) for line in path.read_text().splitlines() if line.strip() and line[0] != "#"]
    fields = {key.strip(): value.strip() for key, value in lines}
    url, sha = fields.get("url", ""), fields.get("sha256", "")
    if not re.fullmatch(r"https://\S+/tla2tools\.jar", url) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ValueError(f"{path}: needs an https url of tla2tools.jar and a lowercase hex sha256")
    return url, sha


def jar(url: str, sha: str, cache: Path = ROOT / ".cache" / "tla") -> Path:
    """The jar in `cache`, downloaded if absent. On a SHA-256 mismatch it is deleted and SystemExit raised."""
    path = cache / f"tla2tools-{sha[:16]}.jar"
    if not path.exists():
        cache.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=120) as response:
            path.with_suffix(".part").write_bytes(response.read())
        path.with_suffix(".part").replace(path)
    with path.open("rb") as f:
        got = hashlib.file_digest(f, "sha256").hexdigest()
    if got != sha:
        path.unlink()
        raise SystemExit(f"refusing {url}: SHA-256 {got} is not the pinned {sha} (re-pin: model/README.md)")
    return path


def outcome(stdout: str, returncode: int) -> str:
    """"pass", or the one invariant or action property TLC reports violated; RuntimeError otherwise."""
    violated = VIOLATED.findall(stdout)
    if returncode == 0 and PASSED in stdout and not violated:
        return "pass"
    if returncode != 0 and len(violated) == 1:
        return violated[0]
    raise RuntimeError(f"TLC exited {returncode} without passing or naming one violation")


def run(tla2tools: Path, spec: Path, cfg: Path, trace: Path) -> str:
    """outcome() of TLC with one worker and no deadlock check; also writes `trace` and its .log."""
    trace.parent.mkdir(parents=True, exist_ok=True)
    trace.unlink(missing_ok=True)
    java = str(Path(os.environ["JAVA_HOME"]) / "bin" / "java") if os.environ.get("JAVA_HOME") else "java"
    with tempfile.TemporaryDirectory() as meta:   # TLC's state files, kept out of the tree
        proc = subprocess.run([java, "-XX:+UseParallelGC", "-cp", str(tla2tools), "tlc2.TLC", "-workers", "1",
                               "-deadlock", "-noGenerateSpecTE", "-metadir", meta, "-config", str(cfg.resolve()),
                               "-dumpTrace", "json", str(trace.resolve()), str(spec.resolve())],
                              capture_output=True, text=True)
    trace.with_suffix(".log").write_text(proc.stdout + proc.stderr)
    result = outcome(proc.stdout, proc.returncode)
    if result != "pass" and not trace.is_file():
        raise RuntimeError(f"TLC reported {result} violated but wrote no trace")
    return result


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    result = run(jar(*read_pin()), *map(Path, sys.argv[1:]))
    print(result if result == "pass" else f"violated: {result}")
    sys.exit(result != "pass")
