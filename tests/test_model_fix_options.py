"""The results table of docs/model-fix-options.md matches model/configs.json, so the two cannot drift. No Java: the
expected cells come from each entry's "expect", which model/ci.py checks against TLC, and its cfg's checked names."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "model"))
import ci as model_ci  # noqa: E402

DOC = ROOT / "docs" / "model-fix-options.md"
COLUMNS = ("NoOldReleaseUnseals", "EpochMonotonic", "OnlyInitramfsObtainsKeys")


def checked(cfg: Path) -> set[str]:
    """The names a TLC cfg lists under INVARIANT or PROPERTY (each keyword's line holds its names)."""
    names = set()
    for line in cfg.read_text().splitlines():
        words = line.split()
        if words and words[0] in ("INVARIANT", "PROPERTY"):
            names.update(words[1:])
    return names


def expected() -> dict[str, list[str]]:
    """cfg -> one cell per column: pass, fail, or — if the run does not check it; cfgs checking no column omitted."""
    rows = {}
    for e in model_ci.load_configs():
        names = checked(model_ci.CONFIGS.parent / e["cfg"])
        if names & set(COLUMNS):
            rows[e["cfg"]] = ["fail" if e["expect"] == c else "pass" if e["expect"] == "pass" and c in names
                              else "—" for c in COLUMNS]
    return rows


def documented(text: str) -> dict[str, list[str]]:
    """cfg -> its cells, from the table under "## Results" whose header names the columns."""
    lines = text.split("\n## Results\n", 1)[1].splitlines()
    header = "| Option | Config | Attacker | " + " | ".join(COLUMNS) + " |"
    start = lines.index(header)
    rows = {}
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 3 + len(COLUMNS) or cells[1] in rows:
            raise ValueError(f"malformed or repeated row: {line!r}")
        rows[cells[1]] = cells[3:]
    return rows


class FixOptionsTableTest(unittest.TestCase):
    def test_table_matches_configs(self):
        self.assertEqual(documented(DOC.read_text()), expected())

    def test_every_option_is_in_configs_and_pending(self):
        text = DOC.read_text()
        for n in range(1, 5):
            section = re.search(rf"^## Option {n}: .*?(?=^## )", text, re.M | re.S)
            self.assertIsNotNone(section, n)
            self.assertIn("**Owner decision: pending.**", section.group())
            self.assertIn("**Closes, in this model:**", section.group())
            cfgs = set(re.findall(r"`(\w+\.cfg)`", section.group()))
            self.assertTrue(cfgs and cfgs <= {e["cfg"] for e in model_ci.load_configs()}, (n, cfgs))

    def test_parsers(self):
        self.assertEqual(expected()["Epoch.cfg"], ["fail", "—", "—"])
        self.assertEqual(expected()["BootRoot.cfg"], ["pass", "pass", "pass"])
        self.assertNotIn("BootRootWitness.cfg", expected())
        row = "| x | A.cfg | y | pass | fail | — |"
        table = f"\n## Results\n\n| Option | Config | Attacker | {' | '.join(COLUMNS)} |\n|---|\n{row}\n"
        self.assertEqual(documented(table), {"A.cfg": ["pass", "fail", "—"]})
        for bad in (table + row + "\n", table.replace("| — |", "|")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                documented(bad)


if __name__ == "__main__":
    unittest.main()
