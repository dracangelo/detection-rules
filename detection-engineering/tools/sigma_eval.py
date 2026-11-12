"""Minimal Sigma rule evaluator used by the unit tests and lab validation.

It deliberately supports only the subset of Sigma this repo uses and raises
UnsupportedSigma for anything else, so a rule can never silently "pass" a test
because of a feature the evaluator ignores. `sigma check` / `sigma convert` in CI
remain the authority on rule syntax; this file answers one question:
"does this rule match this event?".

Supported: field modifiers contains, startswith, endswith, all, re; wildcards (* ?)
with \\* and \\? escapes; list-of-maps (OR) selections; conditions with and / or / not,
parentheses, "1 of X*", "all of X*", "1 of them", "all of them". Matching is
case-insensitive (as in Sigma) except for `re`, which follows the regex flags.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

import yaml

Event = dict[str, Any]


class UnsupportedSigma(Exception):
    pass


SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re"}
LOGSOURCE_EVENT_ID = {"process_creation": 1, "ps_script": 4104}


def load_rule(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def event_matches_logsource(rule: dict, event: Event) -> bool:
    """Events carry EventID (Sysmon 1 = process creation, 4104 = script block)."""
    wanted = LOGSOURCE_EVENT_ID.get(rule["logsource"].get("category"))
    return wanted is None or int(event.get("EventID", wanted)) == wanted


def _wildcard_regex(value: str, mode: str) -> re.Pattern:
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    body = "".join(out)
    if mode == "contains":
        body = ".*" + body + ".*"
    elif mode == "startswith":
        body += ".*"
    elif mode == "endswith":
        body = ".*" + body
    return re.compile(body, re.IGNORECASE | re.DOTALL)


def _value_matcher(value: Any, mods: list[str]) -> Callable[[Any], bool]:
    if value is None:
        return lambda actual: actual is None
    text = str(value)
    if "re" in mods:
        pattern = re.compile(text)
        return lambda actual: actual is not None and pattern.search(str(actual)) is not None
    mode = next((m for m in mods if m in ("contains", "startswith", "endswith")), "exact")
    pattern = _wildcard_regex(text, mode)
    return lambda actual: actual is not None and pattern.fullmatch(str(actual)) is not None


def _compile_item(key: str, expected: Any) -> Callable[[Event], bool]:
    field, *mods = key.split("|")
    unknown = set(mods) - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedSigma(f"modifier(s) not supported by evaluator: {sorted(unknown)}")
    values = expected if isinstance(expected, list) else [expected]
    matchers = [_value_matcher(v, mods) for v in values]
    combine = all if "all" in mods else any
    return lambda event: combine(m(event.get(field)) for m in matchers)


def _compile_selection(sel: Any) -> Callable[[Event], bool]:
    if isinstance(sel, dict):
        items = [_compile_item(k, v) for k, v in sel.items()]
        return lambda event: all(i(event) for i in items)
    if isinstance(sel, list) and all(isinstance(x, dict) for x in sel):
        subs = [_compile_selection(x) for x in sel]
        return lambda event: any(s(event) for s in subs)
    if isinstance(sel, list):  # keyword search across all values
        pats = [_wildcard_regex(str(k), "contains") for k in sel]
        return lambda event: any(p.fullmatch(str(v)) for p in pats for v in event.values())
    raise UnsupportedSigma(f"unsupported selection shape: {type(sel).__name__}")


class _Condition:
    def __init__(self, text: str, selections: dict[str, Callable[[Event], bool]]):
        self.tokens = re.findall(r"\(|\)|[^\s()]+", text)
        self.pos = 0
        self.sel = selections
        self.tree = self._or()
        if self.pos != len(self.tokens):
            raise UnsupportedSigma(f"trailing tokens in condition: {text!r}")

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self):
        tok = self._peek()
        self.pos += 1
        return tok

    def _or(self):
        node = self._and()
        while (self._peek() or "").lower() == "or":
            self._next()
            node = (lambda a, b: lambda e: a(e) or b(e))(node, self._and())
        return node

    def _and(self):
        node = self._not()
        while (self._peek() or "").lower() == "and":
            self._next()
            node = (lambda a, b: lambda e: a(e) and b(e))(node, self._not())
        return node

    def _not(self):
        if (self._peek() or "").lower() == "not":
            self._next()
            inner = self._not()
            return lambda e: not inner(e)
        return self._atom()

    def _atom(self):
        tok = self._next()
        if tok == "(":
            node = self._or()
            if self._next() != ")":
                raise UnsupportedSigma("unbalanced parentheses")
            return node
        if tok is None:
            raise UnsupportedSigma("unexpected end of condition")
        if (self._peek() or "").lower() == "of" and tok.lower() in ("1", "all"):
            self._next()
            names = self._resolve(self._next())
            fns = [self.sel[n] for n in names]
            if tok == "1":
                return lambda e: any(f(e) for f in fns)
            return lambda e: all(f(e) for f in fns)
        if tok not in self.sel:
            raise UnsupportedSigma(f"condition references unknown selection {tok!r}")
        return self.sel[tok]

    def _resolve(self, pattern: str) -> list[str]:
        if pattern == "them":
            names = list(self.sel)
        else:
            rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            names = [n for n in self.sel if rx.match(n)]
        if not names:
            raise UnsupportedSigma(f"'of {pattern}' matches no selections")
        return names


def compile_rule(rule: dict) -> Callable[[Event], bool]:
    det = dict(rule["detection"])
    condition = det.pop("condition")
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    selections = {name: _compile_selection(body) for name, body in det.items()}
    tree = _Condition(condition, selections).tree
    return lambda event: event_matches_logsource(rule, event) and tree(event)


def matches(rule: dict, event: Event) -> bool:
    return compile_rule(rule)(event)


def rule_files(root: str | Path = "rules") -> list[Path]:
    return sorted(Path(root).rglob("*.yml"))
