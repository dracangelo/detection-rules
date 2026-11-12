# Lab setup for Atomic Red Team validation

**These tests execute real attack techniques** (credential dumping, log clearing, shadow-copy
deletion, Defender tampering, account creation). Use a **disposable Windows VM that you own**, on a
**host-only / isolated network**, with a **clean snapshot** to revert to. Never run on a
production, work or domain-joined machine. `Run-AtomicValidation.ps1` refuses to run without an
explicit acknowledgement switch and aborts on domain-joined hosts.

## 1. VM

- Windows 10/11 or Server 2019/2022 VM, standalone (not domain-joined), host-only networking
  (the mshta atomics are local; if you later add atomics that download payloads, use a controlled
  egress path instead of full internet).
- Take a snapshot after setup; revert between runs.

## 2. Telemetry the rules need

| Source | Why | How |
|---|---|---|
| Sysmon (EID 1) | all `proc_creation_*` rules | Install Sysmon with a process-creation-capable config, e.g. SwiftOnSecurity/sysmon-config or olafhartong/sysmon-modular: `sysmon64 -accepteula -i sysmonconfig.xml` |
| PowerShell Script Block Logging (EID 4104) | `ps_script_*` rule | `New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force; Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging EnableScriptBlockLogging 1 -Type DWord` |

Why two sources: Atomic Red Team's PowerShell-executor tests (e.g. `Set-MpPreference ...`) run
inside a PowerShell session, so Sysmon EID 1 only shows `powershell.exe`, never the cmdlet. That
gap is exactly what lab validation is for, and why that technique has a script-block rule.

## 3. Install Invoke-AtomicRedTeam

Follow the current instructions at <https://github.com/redcanaryco/invoke-atomicredteam/wiki>
(typically `Install-AtomicRedTeam -getAtomics`, which creates `C:\AtomicRedTeam`). Windows Defender
will quarantine many atomics; for a lab VM Red Canary documents excluding `C:\AtomicRedTeam`
(`Add-MpPreference -ExclusionPath C:\AtomicRedTeam`). Tamper Protection will block the Defender
tamper tests; the process-creation rule still fires on the attempt, but the Set-MpPreference
change itself may not apply, which is fine for validating detection.

## 4. Run

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\lab\Run-AtomicValidation.ps1 -IUnderstandThisRunsAttackSimulations            # all rules
.\lab\Run-AtomicValidation.ps1 -IUnderstandThisRunsAttackSimulations -OnlyRule proc_creation_win_net_user_add
```

Output: `lab\results\<timestamp>\events.jsonl`. Copy it out of the VM and run
`make lab-validate EVENTS=<path>` (or `python tools/validate_lab.py <path>`).

## Notes on specific tests

- `wevtutil cl System` really clears the System log. Don't add the "Clear-EventLog" atomic
  (T1685.005 #2) to the map: it clears **every** log, including the Sysmon log you collect from.
- LSASS dump (`comsvcs.dll`) writes `lsass-comsvcs.dmp` to `%TEMP%`; delete it and revert the
  snapshot afterwards, as it contains credential material.
- Tests are pinned by **GUID**, not test number, because upstream test numbering shifts.
- Treat `lab/results/` as sensitive (hostnames, usernames, command lines); it is git-ignored.
