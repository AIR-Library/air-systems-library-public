#!/usr/bin/env python3
"""Write (or check) the README's status table from ci/baseline.json, so the table can never lag behind CI.

LIFESPAN: permanent -- CI runs `--check` (.github/workflows/ci.yml, job "readme").

What it does
  The README table between the markers <!-- status:start --> and <!-- status:end --> says, for every system and
  language, whether the suite passes. CI already guarantees that every suite NOT listed in ci/baseline.json passes
  (tools/run_suites.py fails the run on any other result), so the baseline is the source of truth: a suite is
  marked passing exactly when it is absent from the baseline and both of its files exist. tools/run_suites.py also
  fails a run in which a suite on the baseline passes, so a stale baseline entry cannot leave a passing suite shown
  as failing here (CodeRabbit, PR 19). The systems come from docs/specs/README.md, so a system that loses its files
  stays in the table as failing.

Inputs   ci/baseline.json; the files under saas_templates/<lang>/; README.md.
Outputs  `--write` rewrites the table in README.md; `--check` (the default) exits 1 and prints the expected table
         when README.md is out of date, 0 when it matches.
Why      Owner, 2026-11-10: the prebuilds must be "fully working and not missing anything". Before this the README
         table was refreshed by hand: on 2026-11-10 it still showed 79 of 144 passing while CI passed 92.
Written  2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
Touches  files only (reads the baseline and templates; --write rewrites README.md). No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LANGS = ["csharp", "go", "java", "javascript", "php", "python", "rust", "typescript"]
EXT = {"python": "py", "javascript": "js", "typescript": "ts", "go": "go", "php": "php",
       "java": "java", "csharp": "cs", "rust": "rs"}
START, END = "<!-- status:start -->", "<!-- status:end -->"


def systems() -> list[str]:
    """Every system the library declares, plus any that has a file. Out: sorted names.

    The declared set is docs/specs/README.md's table (one row per system spec), so a system whose files vanished from
    every language still gets a row, shown failing, instead of silently dropping out of the total (CodeRabbit, PR 19,
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: reads docs/specs/README.md and the template folders."""
    names: set[str] = set()
    spec_index = ROOT / "docs" / "specs" / "README.md"
    if spec_index.is_file():
        names |= set(re.findall(r"^\|\s*([a-z0-9_]+)\s*\|\s*\[[a-z0-9_]+\.md\]", spec_index.read_text(encoding="utf-8"), re.M))
    for lang in LANGS:
        for p in (ROOT / "saas_templates" / lang).glob(f"*_{lang}.{EXT[lang]}"):
            names.add(p.name[: -len(f"_{lang}.{EXT[lang]}")])
    return sorted(names)


def passes(system: str, lang: str, failing: set[str]) -> bool:
    """True when both files of a suite exist and it is not on the known-failing list. Touches: file existence."""
    folder = ROOT / "saas_templates" / lang
    both = (folder / f"{system}_{lang}.{EXT[lang]}").is_file() and (folder / f"{system}_{lang}_tests.{EXT[lang]}").is_file()
    return both and f"{system}/{lang}" not in failing


def table() -> str:
    """The status table as Markdown, with a passing count per language. Touches: reads the baseline and templates."""
    failing = set(json.loads((ROOT / "ci" / "baseline.json").read_text())["known_failing"])
    names = systems()
    rows = ["| system | " + " | ".join(LANGS) + " |", "|---|" + "---|" * len(LANGS)]
    totals = {lang: 0 for lang in LANGS}
    for s in names:
        cells = []
        for lang in LANGS:
            ok = passes(s, lang, failing)
            totals[lang] += ok
            cells.append("✅" if ok else "❌")
        rows.append(f"| {s} | " + " | ".join(cells) + " |")
    rows.append("| **passing** | " + " | ".join(f"**{totals[lang]}/{len(names)}**" for lang in LANGS) + " |")
    total = sum(totals.values())
    return f"{total} of {len(names) * len(LANGS)} suites pass.\n\n" + "\n".join(rows)


def main() -> int:
    """Check (default) or rewrite the README table. Exit 0 when it matches, 1 when it does not, 2 on a usage error."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="rewrite the table in README.md")
    a = ap.parse_args()
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    m = re.search(re.escape(START) + r"\n(.*?)\n" + re.escape(END), text, re.S)
    if not m:
        print(f"README.md has no {START} ... {END} block", file=sys.stderr)
        return 2
    want = table()
    if a.write:
        readme.write_text(text[: m.start(1)] + want + text[m.end(1):], encoding="utf-8")
        print("README.md status table written")
        return 0
    if m.group(1).strip() == want.strip():
        print("README.md status table matches ci/baseline.json")
        return 0
    print("README.md status table is out of date; run: python tools/readme_status.py --write\n\nExpected:\n" + want)
    return 1


if __name__ == "__main__":
    sys.exit(main())
