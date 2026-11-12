#!/usr/bin/env python3
"""Score lab telemetry against the Sigma rules.

Input: events.jsonl produced by lab/Run-AtomicValidation.ps1 (one JSON event per line, each
tagged with _test_guid). For every (rule, atomic test) pair in lab/atomic_map.json the
expected rule must match at least one event captured in that test's window.

Exit code 0 = every expected detection fired, 1 = at least one miss (a detection gap).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import sigma_eval  # noqa: E402


def load_events(path: Path) -> list[dict]:
    events = []
    # PowerShell's Add-Content -Encoding UTF8 may add a BOM on Windows PowerShell 5.1.
    for n, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = line.strip().lstrip("\ufeff")
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{n}: invalid JSON ({exc})")
    return events


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("events", type=Path, help="events.jsonl from the lab run")
    ap.add_argument("--rules", type=Path, default=ROOT / "rules")
    ap.add_argument("--map", type=Path, default=ROOT / "lab" / "atomic_map.json")
    ap.add_argument("--json", type=Path, help="also write machine-readable results here")
    args = ap.parse_args()

    events = load_events(args.events)
    atomic_map = json.loads(args.map.read_text())["rules"]
    rules = {p.stem: sigma_eval.load_rule(p) for p in sigma_eval.rule_files(args.rules)}
    compiled = {name: sigma_eval.compile_rule(r) for name, r in rules.items()}

    results, misses = [], 0
    for name, entry in atomic_map.items():
        if name not in compiled:
            print(f"warning: {name} is in atomic_map.json but has no rule file", file=sys.stderr)
            continue
        for test in entry["tests"]:
            window = [e for e in events if e.get("_test_guid") == test["guid"]]
            hits = [e for e in window if compiled[name](e)]
            others = sorted({n for n, fn in compiled.items() if n != name and any(fn(e) for e in window)})
            status = "DETECTED" if hits else ("NO-TELEMETRY" if not window else "MISSED")
            misses += status != "DETECTED"
            results.append({
                "rule": name, "attack_id": entry["attack_id"], "atomic_id": entry["atomic_id"],
                "test": test["name"], "guid": test["guid"], "events_in_window": len(window),
                "matching_events": len(hits), "status": status, "other_rules_fired": others,
                "sample_match": (hits[0].get("CommandLine") or hits[0].get("ScriptBlockText", ""))[:200] if hits else None,
            })

    width = max(len(r["rule"]) for r in results)
    print(f"{'RULE':<{width}}  {'ATT&CK':<10} {'STATUS':<13} EVENTS  TEST")
    for r in results:
        print(f"{r['rule']:<{width}}  {r['attack_id']:<10} {r['status']:<13} {r['events_in_window']:>6}  {r['test']}")
        if r["status"] == "MISSED":
            print(f"{'':<{width}}  -> telemetry exists but the rule did not match; inspect the window and tune the rule")
        if r["status"] == "NO-TELEMETRY":
            print(f"{'':<{width}}  -> no events captured; check Sysmon config / script block logging / AV blocked the test")
    detected = sum(r["status"] == "DETECTED" for r in results)
    print(f"\n{detected}/{len(results)} atomic tests detected by their mapped rule")
    if args.json:
        args.json.write_text(json.dumps(results, indent=2))
    return 1 if misses else 0


if __name__ == "__main__":
    raise SystemExit(main())
