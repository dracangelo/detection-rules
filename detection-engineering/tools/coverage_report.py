#!/usr/bin/env python3
"""Print an ATT&CK coverage table (markdown) and optionally an ATT&CK Navigator layer."""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import sigma_eval  # noqa: E402

TECH = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--navigator", type=Path, help="write a Navigator v4.5 layer JSON here")
    args = ap.parse_args()

    by_tech = defaultdict(list)
    rows = []
    for path in sigma_eval.rule_files(ROOT / "rules"):
        rule = sigma_eval.load_rule(path)
        techs = [m.group(1).upper() for t in rule["tags"] if (m := TECH.match(t))]
        tactics = [t[7:] for t in rule["tags"] if t.startswith("attack.") and not TECH.match(t)]
        for t in techs:
            by_tech[t].append(rule["title"])
        rows.append((", ".join(techs), ", ".join(tactics), rule["level"], rule["title"], path.stem))

    print("| Technique | Tactic(s) | Level | Rule |\n|---|---|---|---|")
    for techs, tactics, level, title, stem in sorted(rows):
        print(f"| {techs} | {tactics} | {level} | {title} (`{stem}`) |")
    print(f"\n{len(rows)} rules covering {len(by_tech)} distinct techniques.")

    if args.navigator:
        layer = {
            "name": "detection-engineering coverage", "versions": {"layer": "4.5"}, "domain": "enterprise-attack",
            "techniques": [{"techniqueID": t, "score": len(v), "comment": "; ".join(v)} for t, v in sorted(by_tech.items())],
            "gradient": {"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 3},
        }
        args.navigator.write_text(json.dumps(layer, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
