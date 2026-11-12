"""Unit tests: metadata hygiene, sample-log detection tests and atomic-map coverage."""
import json
import re
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import sigma_eval  # noqa: E402

RULES = sigma_eval.rule_files(ROOT / "rules")
LOGS = ROOT / "tests" / "logs"
ATOMIC_MAP = json.loads((ROOT / "lab" / "atomic_map.json").read_text())["rules"]
ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TACTICS = {  # tactic names as published in the ATT&CK version sigma-cli validates against
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "stealth", "defense-impairment", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
}
REQUIRED = ["title", "id", "status", "description", "references", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"]


def stem(path: Path) -> str:
    return path.stem


def load_cases(path: Path) -> dict:
    return json.loads((LOGS / f"{path.stem}.json").read_text())


def ids():
    return [stem(p) for p in RULES]


def event_params(key: str):
    out = []
    for path in RULES:
        f = LOGS / f"{path.stem}.json"
        if f.exists():
            for i, ev in enumerate(json.loads(f.read_text()).get(key, [])):
                out.append(pytest.param(path, ev, id=f"{path.stem}[{i}]"))
    return out


def test_rules_exist():
    assert RULES, "no rules found under rules/"


@pytest.mark.parametrize("path", RULES, ids=ids())
def test_metadata(path):
    rule = sigma_eval.load_rule(path)
    for key in REQUIRED:
        assert rule.get(key), f"{path.name}: missing '{key}'"
    uuid.UUID(rule["id"])
    tags = rule["tags"]
    techniques = [t for t in tags if ATTACK_TECHNIQUE.match(t)]
    tactics = [t for t in tags if t.startswith("attack.") and t[7:] in TACTICS]
    assert techniques, f"{path.name}: no ATT&CK technique tag (attack.tNNNN[.NNN])"
    assert tactics, f"{path.name}: no ATT&CK tactic tag (e.g. attack.execution)"
    assert rule["level"] in {"informational", "low", "medium", "high", "critical"}
    assert path.name.startswith(("proc_creation_win_", "ps_script_")), "follow the file naming convention"


def test_rule_ids_unique():
    found = [sigma_eval.load_rule(p)["id"] for p in RULES]
    assert len(found) == len(set(found)), "duplicate rule ids"


@pytest.mark.parametrize("path", RULES, ids=ids())
def test_sample_logs_present(path):
    f = LOGS / f"{path.stem}.json"
    assert f.exists(), f"missing tests/logs/{path.stem}.json"
    cases = json.loads(f.read_text())
    assert len(cases.get("should_match", [])) >= 2, "need >= 2 true-positive sample events"
    assert len(cases.get("should_not_match", [])) >= 2, "need >= 2 benign/near-miss sample events"


@pytest.mark.parametrize("path,event", event_params("should_match"))
def test_detects_true_positive(path, event):
    rule = sigma_eval.load_rule(path)
    assert sigma_eval.matches(rule, event), f"expected a match: {event}"


@pytest.mark.parametrize("path,event", event_params("should_not_match"))
def test_ignores_benign(path, event):
    rule = sigma_eval.load_rule(path)
    assert not sigma_eval.matches(rule, event), f"unexpected match: {event}"


@pytest.mark.parametrize("path", RULES, ids=ids())
def test_atomic_mapping(path):
    """Every rule must name the Atomic Red Team test(s) used to validate it in the lab."""
    rule = sigma_eval.load_rule(path)
    entry = ATOMIC_MAP.get(path.stem)
    assert entry, f"{path.stem} is missing from lab/atomic_map.json"
    assert entry["tests"], "at least one atomic test required"
    for t in entry["tests"]:
        uuid.UUID(t["guid"])
    tag_ids = {t[7:].upper() for t in rule["tags"] if ATTACK_TECHNIQUE.match(t)}
    assert entry["attack_id"] in tag_ids, "attack_id in atomic_map.json must match the rule's ATT&CK tag"


def test_atomic_map_has_no_orphans():
    assert set(ATOMIC_MAP) <= set(ids()), "atomic_map.json references rules that do not exist"
