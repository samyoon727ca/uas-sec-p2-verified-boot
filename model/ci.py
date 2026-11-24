#!/usr/bin/env python3
"""Usage: python3 model/ci.py [--out DIR]    (DIR defaults to build/model)

Runs TLC on each entry of model/configs.json, failing unless the outcome is its "expect" ("pass" or the violated
name); writes <cfg>.log and <cfg>.json to DIR. Then runs tests/model, if it has tests, with P2_MODEL_TRACES=DIR."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_tlc  # noqa: E402

CONFIGS = run_tlc.ROOT / "model" / "configs.json"


def load_configs(path: Path = CONFIGS) -> list[dict]:
    """The entries, checked: string fields naming files in path's directory, and each cfg only once."""
    entries, seen = json.loads(path.read_text()), set()
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: expected a non-empty list")
    for e in entries:
        if not isinstance(e, dict) or set(e) != {"spec", "cfg", "expect"} or not (isinstance(e["expect"], str)
                and re.fullmatch(r"\w+\.tla", str(e["spec"]), re.A) and (path.parent / e["spec"]).is_file()
                and re.fullmatch(r"\w+\.cfg", str(e["cfg"]), re.A) and (path.parent / e["cfg"]).is_file()
                ) or e["cfg"] in seen:
            raise ValueError(f"{path}: not a {{spec, cfg, expect}} entry for files in its directory: {e!r}")
        seen.add(e["cfg"])
    return entries


def main() -> int:
    p = argparse.ArgumentParser(description="Run TLC on every entry of model/configs.json.")
    p.add_argument("--out", type=Path, default=run_tlc.ROOT / "build" / "model")
    out = p.parse_args().out.resolve()
    entries, tla2tools, failed = load_configs(), run_tlc.jar(*run_tlc.read_pin()), 0
    for e in entries:
        trace = out / (e["cfg"][:-4] + ".json")
        try:
            got = run_tlc.run(tla2tools, CONFIGS.parent / e["spec"], CONFIGS.parent / e["cfg"], trace)
        except RuntimeError as err:
            got = f"error: {err}, see {trace.with_suffix('.log')}"
        failed += got != e["expect"]
        print(f"{'OK  ' if got == e['expect'] else 'DIFF'}  {e['cfg']}: expected {e['expect']}, got {got}")
        if got != e["expect"]:   # TLC's last lines and an annotation, so the step log shows why
            print(*trace.with_suffix(".log").read_text().splitlines()[-30:], sep="\n")
            print(f"::error title=model/{e['cfg']}::expected {e['expect']}, got {got}")
    if any((run_tlc.ROOT / "tests" / "model").glob("test*.py")):
        failed += subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests/model", "-t", "."],
                                 cwd=run_tlc.ROOT, env=dict(os.environ, P2_MODEL_TRACES=str(out))).returncode != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
