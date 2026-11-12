#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Runs the Atomic Red Team tests listed in atomic_map.json inside YOUR ISOLATED LAB VM and
  exports the resulting Sysmon (EID 1) and PowerShell script block (EID 4104) events so that
  tools/validate_lab.py can check which Sigma rules fired.

.DESCRIPTION
  Each test runs in its own time window; events from that window are tagged with the rule
  expected to detect it. Tests are cleaned up afterwards.

  THIS EXECUTES REAL ATTACK TECHNIQUES (LSASS dump, log clearing, shadow-copy deletion,
  Defender tampering, account creation). Run it ONLY on a disposable, network-isolated VM
  that you own, with a clean snapshot to revert to.

.EXAMPLE
  .\Run-AtomicValidation.ps1 -IUnderstandThisRunsAttackSimulations
  .\Run-AtomicValidation.ps1 -IUnderstandThisRunsAttackSimulations -OnlyRule proc_creation_win_net_user_add
#>
[CmdletBinding()]
param(
    [switch]$IUnderstandThisRunsAttackSimulations,
    [switch]$AllowDomainJoined,
    [switch]$SkipPrereqs,
    [string]$OnlyRule,
    [string]$MapPath = (Join-Path $PSScriptRoot 'atomic_map.json'),
    [string]$OutDir  = (Join-Path $PSScriptRoot ("results\" + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [int]$SettleSeconds = 5
)

$ErrorActionPreference = 'Stop'

# ---- safety gates -------------------------------------------------------------------------
if (-not $IUnderstandThisRunsAttackSimulations) {
    throw "Refusing to run: pass -IUnderstandThisRunsAttackSimulations to confirm this is an isolated lab VM."
}
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain -and -not $AllowDomainJoined) {
    throw "This machine is domain-joined. Lab VMs should be standalone. Override with -AllowDomainJoined only if you are certain."
}
if (-not (Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')) {
    throw "Sysmon is not running. Install it first (see lab/README.md)."
}
if (-not (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
    throw "Invoke-AtomicRedTeam module not found (see lab/README.md)."
}
Import-Module Invoke-AtomicRedTeam -Force

$sbl = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
if (-not $sbl -or $sbl.EnableScriptBlockLogging -ne 1) {
    Write-Warning "PowerShell Script Block Logging is not enabled; the ps_script rule cannot be validated."
}

# ---- helpers ------------------------------------------------------------------------------
function Get-LabEvents([datetime]$Start, [datetime]$End) {
    $filters = @(
        @{ LogName = 'Microsoft-Windows-Sysmon/Operational';        Id = 1;    StartTime = $Start; EndTime = $End },
        @{ LogName = 'Microsoft-Windows-PowerShell/Operational';    Id = 4104; StartTime = $Start; EndTime = $End }
    )
    foreach ($f in $filters) {
        Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $o = [ordered]@{
                EventID = $_.Id
                UtcTime = $_.TimeCreated.ToUniversalTime().ToString('o')
                Channel = $_.LogName
            }
            foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $o[$d.Name] = $d.'#text' } }
            [pscustomobject]$o
        }
    }
}

# ---- run ----------------------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$eventsFile = Join-Path $OutDir 'events.jsonl'
$map = (Get-Content $MapPath -Raw | ConvertFrom-Json).rules

foreach ($ruleName in $map.PSObject.Properties.Name) {
    if ($OnlyRule -and $ruleName -ne $OnlyRule) { continue }
    $entry = $map.$ruleName
    foreach ($t in $entry.tests) {
        Write-Host "`n=== $ruleName :: $($entry.atomic_id) :: $($t.name)" -ForegroundColor Cyan
        if (-not $SkipPrereqs) {
            Invoke-AtomicTest $entry.atomic_id -TestGuids $t.guid -GetPrereqs
        }
        Start-Sleep -Seconds 2
        $start = (Get-Date).AddSeconds(-1)
        try {
            Invoke-AtomicTest $entry.atomic_id -TestGuids $t.guid -TimeoutSeconds 120
        } catch {
            Write-Warning "Test failed to execute: $_"
        }
        Start-Sleep -Seconds $SettleSeconds   # let Sysmon / ETW flush
        $end = (Get-Date).AddSeconds(1)

        $events = @(Get-LabEvents -Start $start -End $end)
        foreach ($e in $events) {
            $e | Add-Member -NotePropertyName _test_guid -NotePropertyValue $t.guid
            $e | Add-Member -NotePropertyName _atomic_id -NotePropertyValue $entry.atomic_id
            $e | ConvertTo-Json -Compress -Depth 4 | Add-Content -Path $eventsFile -Encoding UTF8
        }
        Write-Host ("Collected {0} events" -f $events.Count)

        Invoke-AtomicTest $entry.atomic_id -TestGuids $t.guid -Cleanup
        Start-Sleep -Seconds 2
    }
}

Write-Host "`nDone. Events: $eventsFile" -ForegroundColor Green
Write-Host "Copy that file to your dev machine and run:  python tools/validate_lab.py <path>\events.jsonl"
