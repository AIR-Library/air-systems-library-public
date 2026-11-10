#!/usr/bin/env python3
"""Regression tests for the library's own tools (tools/run_suites.py and tools/readme_status.py).

LIFESPAN: permanent -- CI runs it in the `readme` job (.github/workflows/ci.yml): `python -m unittest tools/test_tools.py`.

What it checks, on a throwaway copy of the folder layout (no language toolchain needed, nothing is run):
  * a system declared in docs/specs/README.md whose files are gone from a language is still a suite there, so the
    runner reports it MISSING (never excused) instead of skipping it;
  * the README table keeps a declared system with no files, shown failing in every language.
Why     CodeRabbit's review of PR 19 asked for a regression check for a suite with both files absent. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP.
Touches a temporary directory only.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import readme_status  # noqa: E402
import run_suites  # noqa: E402

SPEC_INDEX = """# System specs

| system | spec | required tests |
|---|---|---|
| alpha | [alpha.md](alpha.md) | 1 |
| beta | [beta.md](beta.md) | 1 |
"""


class LayoutTest(unittest.TestCase):
    """Builds a small library layout in a temp folder and points both tools at it."""

    def setUp(self) -> None:
        """Creates docs/specs (alpha and beta declared), ci/baseline.json, and alpha's python files only."""
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "docs" / "specs").mkdir(parents=True)
        (root / "docs" / "specs" / "README.md").write_text(SPEC_INDEX)
        (root / "ci").mkdir()
        (root / "ci" / "baseline.json").write_text(json.dumps({"known_failing": []}))
        py = root / "saas_templates" / "python"
        py.mkdir(parents=True)
        (py / "alpha_python.py").write_text("x = 1\n")
        (py / "alpha_python_tests.py").write_text("def test_x():  # ALPHA-01\n    pass\n")
        for lang in run_suites.EXT:
            (root / "saas_templates" / lang).mkdir(parents=True, exist_ok=True)
        self.saved = (run_suites.TEMPLATES, readme_status.ROOT)
        run_suites.TEMPLATES = root / "saas_templates"
        readme_status.ROOT = root

    def tearDown(self) -> None:
        """Restores the tools' real paths and removes the temp folder."""
        run_suites.TEMPLATES, readme_status.ROOT = self.saved
        self.tmp.cleanup()

    def test_declared_system_without_files_is_still_a_suite(self) -> None:
        """beta has no files in any language, yet the runner lists it, so it is reported MISSING."""
        self.assertEqual(run_suites.systems_for("python"), ["alpha", "beta"])
        self.assertEqual(run_suites.systems_for("rust"), ["alpha", "beta"])

    def test_readme_table_keeps_declared_system_as_failing(self) -> None:
        """The table has a beta row, failing in every language, and the total counts 16 suites."""
        table = readme_status.table()
        beta = next(line for line in table.splitlines() if line.startswith("| beta |"))
        self.assertNotIn("✅", beta)
        self.assertEqual(beta.count("❌"), len(readme_status.LANGS))
        self.assertTrue(table.startswith("1 of 16 suites pass."))


if __name__ == "__main__":
    unittest.main()
