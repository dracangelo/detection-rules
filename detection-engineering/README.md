# detection-engineering

Detection-as-code for Windows: **Sigma rules mapped to MITRE ATT&CK**, each with **sample logs and
tests**, linted by **sigma-cli on every push**, and validated against real attack simulations
(**Atomic Red Team**) in an isolated lab.

```
rules/windows/
  process_creation/   9 rules (Sysmon EID 1 / 4688 style fields)
  powershell/         1 rule  (Script Block Logging, EID 4104)
tests/
  logs/<rule>.json    true-positive and benign/near-miss events per rule
  test_rules.py       metadata hygiene + per-event detection tests (pytest)
tools/
  sigma_eval.py       tiny Sigma evaluator used by tests and lab validation
  validate_lab.py     scores real lab telemetry against rule<->atomic-test mapping
  coverage_report.py  ATT&CK coverage table (+ Navigator layer)
lab/
  atomic_map.json     which Atomic Red Team test(s) validate which rule (by GUID)
  Run-AtomicValidation.ps1   runs the atomics in the lab VM and exports events
  README.md           lab setup
.github/workflows/validate.yml
```

## Rules

| Rule | ATT&CK | Level | Atomic test(s) |
|---|---|---|---|
| PowerShell Encoded Command Execution | T1059.001 | medium | T1059.001 #15 |
| LSASS Memory Dump via comsvcs.dll MiniDump | T1003.001 | high | T1003.001 #2 |
| Scheduled Task Created Running Script Host or User-Writable Path | T1053.005 | medium | T1053.005 #2 |
| Registry Run Key Added via reg.exe | T1547.001 | medium | T1547.001 #1 |
| Windows Event Log Cleared via wevtutil | T1685.005 (was T1070.001) | high | T1685.005 #1 |
| Mshta Executing Inline Script or Remote Content | T1218.005 | medium | T1218.005 #2, #10 |
| Defender Service Stopped or Disabled via sc.exe | T1685 (was T1562.001) | high | T1685 #20 |
| Defender Protections Disabled via Set-MpPreference | T1685 (was T1562.001) | high | T1685 #19, #34 |
| Local User Account Created via net.exe | T1136.001 | medium | T1136.001 #4 |
| Volume Shadow Copies Deleted via vssadmin | T1490 | high | T1490 #1 |

> **ATT&CK versions.** Current ATT&CK data (what sigma-cli validates against, and what Atomic Red
> Team's folders now use) renumbered a few techniques and tactics: T1562.001 → **T1685**,
> T1070.001 → **T1685.005**, and Defense Evasion → **Stealth** / **Defense Impairment**. Tags in this
> repo use the current IDs so `sigma check` passes; the old IDs are noted in rule descriptions for
> people who still search by them. If you pin an older sigma-cli, you may need to switch tags back.

## Workflow

```bash
make install     # sigma-cli + pytest
make check       # sigma check (same as CI)
make convert     # compile every rule to Splunk SPL
make test        # sample-log tests
make coverage    # ATT&CK coverage table + attack-layer.json for ATT&CK Navigator
```

CI (`.github/workflows/validate.yml`) runs `sigma check --fail-on-issues`, a Splunk conversion
(proves rules compile for a real backend), the pytest suite, and posts an ATT&CK coverage table to
the job summary, on every push and pull request.

## Adding a rule (definition of done)

1. `rules/windows/<category>/<name>.yml` with `title, id (new UUID), status, description, references,
   author, date, tags (tactic + technique), logsource, detection, falsepositives, level`.
2. `tests/logs/<name>.json` with ≥ 2 `should_match` events and ≥ 2 `should_not_match` near-misses
   (include a realistic false positive, not just obviously-benign noise).
3. An entry in `lab/atomic_map.json` pointing at the Atomic test GUID(s) that exercise it
   (`Invoke-AtomicTest <id> -ShowDetailsBrief` lists them).
4. `make check test` is green, then run the lab validation (below) before promoting `status`
   from `experimental` to `test`/`stable`.

`tests/test_rules.py` enforces 1–3 automatically.

## Lab validation (Atomic Red Team)

Unit tests prove a rule matches *the logs you wrote*. Lab validation proves it matches *what the
attack actually produces on a real Windows host*. See [`lab/README.md`](lab/README.md) for the
isolated-VM setup; in short:

```powershell
# in the lab VM (elevated) – runs real attack simulations, VM only!
.\lab\Run-AtomicValidation.ps1 -IUnderstandThisRunsAttackSimulations
```
```bash
# on your dev machine, after copying lab/results/<run>/events.jsonl out of the VM
make lab-validate EVENTS=lab/results/<run>/events.jsonl
```

Each atomic test gets its own time window; the mapped rule must match at least one event in it.
Result states: `DETECTED`, `MISSED` (telemetry exists, rule didn't match → tune the rule) and
`NO-TELEMETRY` (nothing logged → fix your logging, or AV blocked the test). A miss exits non-zero.

## Limits worth knowing

- `tools/sigma_eval.py` implements the Sigma subset these rules use and **raises** on anything else
  rather than silently passing. `sigma check`/`sigma convert` in CI remain the syntax authority.
- Rules are written against Sysmon-style field names (`Image`, `CommandLine`, `ParentImage`,
  `OriginalFileName`). For other telemetry (4688, EDR, ECS) convert with the matching pipeline.
- Rules are `experimental` until they have survived the lab run **and** a baseline against your
  own production-like logs for false positives.
