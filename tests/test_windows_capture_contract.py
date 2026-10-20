from __future__ import annotations

import os
import ast
import base64
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HELPER = ROOT / "platforms" / "windows_capture_helpers.ps1"
INSPECT = ROOT / "platforms" / "inspect.ps1"
CAPTURE_CMD = ROOT / "platforms" / "windows_capture.cmd"
POWERSHELL = shutil.which("powershell.exe")

from analyzers.evidence_analyzer import analyze_evidence  # noqa: E402
from evidence.bundle import (  # noqa: E402
    _read_exit_sidecar,
    import_bundle,
    validate_bundle,
    write_manifest,
)
from collectors import services as services_collector  # noqa: E402
from collectors import scheduled_tasks as scheduled_collector  # noqa: E402
from collectors import security_vendors as security_vendors_collector  # noqa: E402
from collectors import startup_items as startup_collector  # noqa: E402
from analyzers.risk_analyzer import analyze as analyze_risk  # noqa: E402
from analyzers.windows_security_rules import (  # noqa: E402
    analyze_windows_service_facts,
    analyze_windows_startup_facts,
)
from rules.loader import load_rules  # noqa: E402


def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _run_ps(script: str, *, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    assert POWERSHELL, "Windows PowerShell is required for capture contract tests."
    with tempfile.TemporaryDirectory(prefix="pcit-contract-") as temporary:
        script_path = Path(temporary) / "contract.ps1"
        script_path.write_text(script, encoding="utf-8-sig")
        return subprocess.run(
            [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )


def test_native_entrypoint_and_row_cap_cross_start_job_boundary() -> None:
    cmd = CAPTURE_CMD.read_text(encoding="utf-8").casefold()
    inspect = INSPECT.read_bytes().decode("ascii")
    assert "inspect.ps1" in cmd
    assert "bounded_windows_capture.vbs" not in cmd
    assert "wmic.exe" not in cmd + inspect.casefold()
    assert "param($CollectorName, $PolicyTempDirectory, $HelperPath, [int]$MaxRows)" in inspect
    assert "$script:MaxRows = $MaxRows" in inspect
    assert "$script:MaxRows)" in inspect
    assert "Select-PciRows -Rows $allProcesses -Limit $script:MaxRows" in inspect
    assert "Select-PciRows -Rows $allServices -Limit $script:MaxRows" in inspect
    assert "if (@('processes','services','accounts','startup_items','security_status') -contains $Name)" in inspect
    assert "ASSOCIATORS OF {" in inspect and "AdministratorMemberCount" in inspect
    assert "ImagePath=" in inspect and "ScriptPath=" in inspect
    assert "ArgumentsAndUserNames=OMITTED_FOR_PRIVACY" in inspect
    assert r"Access is denied|\u62d2\u7edd\u8bbf\u95ee|Permission denied" in inspect

    parse_result = _run_ps(
        f"""
$denialPattern = 'Access is denied|\\u62d2\\u7edd\\u8bbf\\u95ee|Permission denied'
if ('拒绝访问' -notmatch $denialPattern) {{ throw 'DENIAL_REGEX_MISMATCH' }}
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile({_ps_literal(INSPECT)}, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {{ $errors | ForEach-Object {{ Write-Error $_.Message }}; exit 1 }}
'DENIAL_REGEX_MATCH_OK'
'INSPECT_PARSE_OK'
"""
    )
    assert parse_result.returncode == 0, parse_result.stderr or parse_result.stdout
    assert "DENIAL_REGEX_MATCH_OK" in parse_result.stdout
    assert "INSPECT_PARSE_OK" in parse_result.stdout

    script = f"""
. {_ps_literal(HELPER)}
$worker = {{
    param([int]$RowLimit, [string]$HelperPath)
    $script:MaxRows = $RowLimit
    . $HelperPath
    $connections = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 3000; $i++) {{
        [void]$connections.Add('TCP 10.0.0.1:' + (10000 + $i) + ' 10.0.0.2:443 ESTABLISHED 77')
    }}
    [void]$connections.Add('TCP [::]:5985 [::]:0 LISTENING 1234')
    [void]$connections.Add('UDP [::]:5353 *:* 5678')
    $listeners = Select-PciNetstatListeners -Lines ([string[]]$connections.ToArray()) -Limit $script:MaxRows
    $rows = @(
        [pscustomobject]@{{ Name='one' }},
        [pscustomobject]@{{ Name='two' }},
        [pscustomobject]@{{ Name='three' }}
    )
    $processes = Select-PciRows -Rows $rows -Limit $script:MaxRows
    $services = Select-PciRows -Rows $rows -Limit $script:MaxRows
    [pscustomobject]@{{
        RowLimit=$script:MaxRows
        ListenerCount=$listeners.Count
        ListenerTruncated=$listeners.Truncated
        ListenerLines=@($listeners.Lines | ForEach-Object {{ $_.Line }})
        ProcessCount=$processes.Count
        ProcessTruncated=$processes.Truncated
        ServiceCount=$services.Count
        ServiceTruncated=$services.Truncated
    }}
}}
$job = Start-Job -ScriptBlock $worker -ArgumentList @(2, {_ps_literal(HELPER)})
$completed = Wait-Job -Job $job -Timeout 30
if ($null -eq $completed) {{ Stop-Job -Job $job; throw 'SYNTHETIC_START_JOB_TIMEOUT' }}
$value = Receive-Job -Job $job -ErrorAction Stop | Select-Object -Last 1
Remove-Job -Job $job -Force
$value | ConvertTo-Json -Depth 5 -Compress
"""
    result = _run_ps(script)
    assert result.returncode == 0, result.stderr or result.stdout
    import json

    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value["RowLimit"] == 2
    assert value["ListenerCount"] == 2
    assert value["ListenerTruncated"] is False
    assert any("[::]:5985" in line for line in value["ListenerLines"])
    assert any("[::]:5353" in line for line in value["ListenerLines"])
    assert value["ProcessCount"] == 2 and value["ProcessTruncated"] is True
    assert value["ServiceCount"] == 2 and value["ServiceTruncated"] is True

    capped = _run_ps(
        f"""
. {_ps_literal(HELPER)}
$lines = @('TCP [::]:5985 [::]:0 LISTENING 1234', 'UDP [::]:5353 *:* 5678')
$value = Select-PciNetstatListeners -Lines $lines -Limit 1
[pscustomobject]@{{ Count=$value.Count; Truncated=$value.Truncated }} | ConvertTo-Json -Compress
"""
    )
    assert capped.returncode == 0, capped.stderr or capped.stdout
    capped_value = json.loads(capped.stdout.strip().splitlines()[-1])
    assert capped_value == {"Count": 1, "Truncated": True}


def test_secedit_parser_handles_real_fields_missing_fields_and_denial() -> None:
    script = f"""
. {_ps_literal(HELPER)}
$complete = @('[Unicode]', '[System Access]', 'MinimumPasswordLength = 12', 'PasswordComplexity = 1', 'LockoutBadCount = 5', 'MaximumPasswordAge = 90')
$parsed = Resolve-PciSecurityPolicyExport -ExitCode 0 -FileExists $true -Lines $complete
$missing = Resolve-PciSecurityPolicyExport -ExitCode 0 -FileExists $true -Lines @('[System Access]', 'OtherSetting = 1')
$denied = Resolve-PciSecurityPolicyExport -ExitCode 5 -FileExists $false -Lines @()
$conflict = Resolve-PciSecurityPolicyExport -ExitCode 0 -FileExists $true -Lines @('[System Access]', 'MinimumPasswordLength=8', 'PasswordComplexity=1', 'LockoutBadCount=5', 'PasswordComplexity=0')
[pscustomobject]@{{
    ParsedStatus=$parsed.Status
    ParsedValues=$parsed.Values
    MissingStatus=$missing.Status
    MissingFields=$missing.MissingFields
    DeniedStatus=$denied.Status
    ConflictStatus=$conflict.Status
}} | ConvertTo-Json -Depth 5 -Compress
"""
    result = _run_ps(script)
    assert result.returncode == 0, result.stderr or result.stdout
    import json

    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value["ParsedStatus"] == "collected"
    assert value["ParsedValues"]["MinimumPasswordLength"] == 12
    assert value["ParsedValues"]["PasswordComplexity"] == 1
    assert value["ParsedValues"]["LockoutBadCount"] == 5
    assert value["MissingStatus"] == "missing"
    assert set(value["MissingFields"]) == {"MinimumPasswordLength", "PasswordComplexity", "LockoutBadCount"}
    assert value["DeniedStatus"] == "permission_denied_or_unavailable"
    assert value["ConflictStatus"] == "parse_failed"


def test_native_sidecar_writer_round_trips_collected_partial_and_failed_evidence() -> None:
    assert POWERSHELL, "Windows PowerShell is required for native sidecar contract tests."
    work_root = ROOT / "work"
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pcit-sidecar-pipeline-", dir=work_root) as temporary:
        base = Path(temporary)
        source = base / "native"
        source.mkdir()
        (source / "cpu.txt").write_text("Name=Synthetic CPU\nRecordCount=1\n", encoding="utf-8")
        (source / "disks.txt").write_text(
            "COLLECTOR_STATUS=PARTIAL\nRecordCount=1\nDrive=C:\\\\;FreePercent=42\n",
            encoding="utf-8",
        )
        (source / "accounts.txt").write_text(
            "COLLECTOR_STATUS=FAILED\nCOLLECTOR_ERROR=FIXTURE\n", encoding="utf-8"
        )
        script = f"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile({_ps_literal(INSPECT)}, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {{ throw 'INSPECT_PARSE_FAILED' }}
$writer = $ast.Find({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-Sidecar' }}, $true)
if ($null -eq $writer) {{ throw 'SIDECAR_WRITER_NOT_FOUND' }}
$metadataAssignment = $ast.Find({{ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$metadata' }}, $true)
if ($null -eq $metadataAssignment) {{ throw 'METADATA_ASSIGNMENT_NOT_FOUND' }}
$startedAt = '2026-10-11T12:00:00Z'
$finishedAt = '2026-10-11T12:01:00Z'
$privilege = 'ordinary'
$script:CollectorVersion = 'fixture'
$script:CommandCatalog = 'cpu,disks,accounts'
Invoke-Expression ('$metadata = ' + $metadataAssignment.Right.Extent.Text)
if ($metadata.Count -ne 7 -or @($metadata | Where-Object {{ $_ -notmatch '^[a-z_]+=.+' }}).Count -ne 0) {{ throw 'METADATA_LINE_CONTRACT_FAILED' }}
Write-Output ('METADATA_COUNT=' + $metadata.Count)
Invoke-Expression $writer.Extent.Text
$OutputDirectory = {_ps_literal(source)}
Write-Sidecar 'cpu.txt' 0 'COLLECTED'
Write-Sidecar 'disks.txt' 0 'COLLECTED'
Write-Sidecar 'accounts.txt' 4 'FAILED'
"SIDECAR_WRITE_OK"
"""
        ps_result = _run_ps(script)
        assert ps_result.returncode == 0, ps_result.stderr or ps_result.stdout
        assert "METADATA_COUNT=7" in ps_result.stdout
        assert "SIDECAR_WRITE_OK" in ps_result.stdout

        expected_sidecars = {
            "cpu.exit-code.txt": (0, "COLLECTED"),
            "disks.exit-code.txt": (0, "COLLECTED"),
            "accounts.exit-code.txt": (4, "FAILED"),
        }
        for name, expected in expected_sidecars.items():
            path = source / name
            assert len(path.read_text(encoding="ascii").splitlines()) == 2
            assert _read_exit_sidecar(path) == expected

        target = {
            "os_family": "windows", "product": "Windows fixture", "version": "fixture",
            "architecture": "x64", "use_case": "unknown", "scope": "basic",
        }
        collection = {
            "started_at": "2026-10-11T12:00:00Z", "finished_at": "2026-10-11T12:01:00Z",
            "timezone": "UTC", "privilege": "ordinary", "collector_version": "fixture",
            "command_catalog": "cpu,disks,accounts",
        }
        write_manifest(source, project_alias="fixture", asset_alias="synthetic", target=target, collection=collection)
        source_manifest = validate_bundle(source)
        source_items = {item["path"]: item for item in source_manifest["items"]}
        assert source_items["cpu.txt"]["status"] == "collected"
        assert source_items["disks.txt"]["status"] == "collected"
        assert "partial facts" in source_items["disks.txt"]["reason"]
        assert source_items["accounts.txt"]["status"] == "failed"

        imported = import_bundle(source, base / "cases")
        imported_manifest = validate_bundle(imported)
        result = analyze_evidence(imported, imported_manifest)
        assert result.status == "PARTIAL"


def test_python_collector_json_boundaries_omit_command_arguments_and_user_names() -> None:
    assert POWERSHELL, "Windows PowerShell is required for collector privacy contract tests."
    service_source = services_collector._powershell_script()
    service_query = "Get-CimInstance Win32_Service -ErrorAction Stop"
    assert service_query in service_source
    service_fixture = r"""
$ErrorActionPreference = 'Stop'
$fixtureServices = @(
 [pscustomobject]@{
  Name='AcmeFixtureService'
  DisplayName='Acme Fixture Service'
  State='Running'
  StartMode='Auto'
  StartName='ACCOUNT_SENTINEL'
  PathName='"C:\Users\Alice\AppData\Local\Acme\agent.exe" -Token=PCIT_SECRET_SENTINEL'
 },
 [pscustomobject]@{
  Name='WrappedFixtureService'
  DisplayName='Wrapped Fixture Service'
  State='Running'
  StartMode='Auto'
  StartName='ACCOUNT_SENTINEL'
  PathName='"C:\Windows\System32\Acme\agent.exe -Token PCIT_SECRET_SENTINEL"'
 }
)
"""
    service_script = service_fixture + service_source.replace(service_query, "$fixtureServices", 1)
    service_result = _run_ps(service_script)
    assert service_result.returncode == 0, "Synthetic service projection failed."
    assert not service_result.stderr.strip(), "Synthetic service projection emitted a PowerShell error."
    assert "PCIT_SECRET_SENTINEL" not in service_result.stdout
    assert "ACCOUNT_SENTINEL" not in service_result.stdout
    assert "Alice" not in service_result.stdout
    service_data = json.loads(service_result.stdout.strip())
    service_rows = service_data if isinstance(service_data, list) else [service_data]
    service_row = service_rows[0]
    assert service_row["PathName"] == r"C:\Users\<redacted>\AppData\Local\Acme\agent.exe"
    assert service_row["ArgumentsOmitted"] is True
    assert "StartName" not in service_row
    assert service_rows[1]["PathName"] == "UNKNOWN"
    assert "StartName" not in service_rows[1]

    registry = load_rules(str(ROOT / "rules" / "windows_risk_rules.example.json"))
    service_findings = analyze_windows_service_facts(service_rows, registry)
    assert any(item["finding_id"] == "WIN_SERVICE_SUSPICIOUS_PATH" for item in service_findings)
    original_service_runner = services_collector.powershell_json
    try:
        services_collector.powershell_json = lambda _script, timeout: service_data
        service_collection = services_collector.collect()
    finally:
        services_collector.powershell_json = original_service_runner
    assert service_collection["status"] == "partial"

    startup_source = startup_collector._powershell_script()
    encoded_source = base64.b64encode(startup_source.encode("utf-16le")).decode("ascii")
    startup_script = fr"""
$ErrorActionPreference = 'Stop'
$source = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{encoded_source}'))
$tokens = $null
$parseErrors = $null
$sourceAst = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {{ throw 'STARTUP_SOURCE_PARSE_FAILED' }}
$functions = $sourceAst.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }}, $true)
foreach ($function in $functions) {{ Invoke-Expression $function.Extent.Text }}
$script:items = @()
$script:errors = @()
Add-StartupItem -Name 'FixtureStartup' -Command 'powershell.exe -NoProfile -File "C:\Users\Alice\AppData\Roaming\agent.ps1" -Token=PCIT_SECRET_SENTINEL' -Location 'C:\Users\Alice\Startup' -Scope 'CurrentUser' -SourceType 'RegistryRun'
Add-StartupItem -Name 'BareSwitchFixture' -Command 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Token PCIT_SECRET_SENTINEL -File C:\Tools\agent.ps1' -Location 'C:\ProgramData\Startup' -Scope 'Public' -SourceType 'RegistryRun'
Add-StartupItem -Name 'WrappedCommandFixture' -Command '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Token PCIT_SECRET_SENTINEL -File C:\Tools\agent.ps1"' -Location 'C:\ProgramData\Startup' -Scope 'Public' -SourceType 'RegistryRun'
[pscustomobject]@{{ Items=$script:items; Errors=$script:errors; ArgumentsAndUserNames='OMITTED_FOR_PRIVACY' }} | ConvertTo-Json -Depth 6 -Compress
"""
    startup_result = _run_ps(startup_script)
    assert startup_result.returncode == 0, "Synthetic startup projection failed."
    assert not startup_result.stderr.strip(), "Synthetic startup projection emitted a PowerShell error."
    startup_data = json.loads(startup_result.stdout.strip())
    def find_fixture_fields(value: object, prefix: str = "") -> list[str]:
        if isinstance(value, dict):
            return [
                path
                for key, nested in value.items()
                for path in find_fixture_fields(nested, f"{prefix}.{key}" if prefix else str(key))
            ]
        if isinstance(value, list):
            return [
                path
                for index, nested in enumerate(value)
                for path in find_fixture_fields(nested, f"{prefix}[{index}]")
            ]
        if isinstance(value, str) and (
            "PCIT_SECRET_SENTINEL" in value or "-Token" in value or "Alice" in value
        ):
            return [prefix]
        return []
    leaked_fields = find_fixture_fields(startup_data)
    assert not leaked_fields, f"Synthetic sensitive data leaked into startup JSON fields: {leaked_fields}"
    assert "PCIT_SECRET_SENTINEL" not in startup_result.stdout
    startup_item = startup_data["Items"][0]
    assert startup_item["Command"] == "powershell.exe"
    assert startup_item["ImagePath"] == "powershell.exe"
    assert startup_item["ScriptPath"] == r"C:\Users\<redacted>\AppData\Roaming\agent.ps1"
    assert startup_item["ScriptExtension"] == ".ps1", f"Safe extension was {startup_item['ScriptExtension']!r}."
    assert startup_item["ArgumentsOmitted"] is True
    bare_item = startup_data["Items"][1]
    assert bare_item["ImagePath"].endswith("powershell.exe")
    assert bare_item["ScriptPath"] == r"C:\Tools\agent.ps1"
    wrapped_item = startup_data["Items"][2]
    assert wrapped_item["ImagePath"] == "UNKNOWN"
    assert wrapped_item["ScriptPath"] is None
    assert startup_data["Errors"] == [
        "A startup image path could not be safely resolved; command arguments were omitted.",
        "A startup script path could not be safely resolved; command arguments were omitted.",
    ]
    startup_findings = analyze_windows_startup_facts(startup_data["Items"], registry)
    assert any(item["finding_id"] == "WIN_STARTUP_SUSPICIOUS_PATH" for item in startup_findings)
    startup_evidence = json.dumps(startup_findings, ensure_ascii=False)
    assert "PCIT_SECRET_SENTINEL" not in startup_evidence and "Alice" not in startup_evidence
    original_startup_runner = startup_collector.powershell_json
    try:
        startup_collector.powershell_json = lambda _script, timeout: startup_data
        startup_collection = startup_collector.collect()
    finally:
        startup_collector.powershell_json = original_startup_runner
    assert startup_collection["status"] == "partial"


def test_native_command_path_helpers_drop_ambiguous_arguments() -> None:
    assert POWERSHELL, "Windows PowerShell is required for native command privacy contract tests."
    script = fr"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile({_ps_literal(INSPECT)}, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {{ throw 'INSPECT_PARSE_FAILED' }}
$serviceFunction = $ast.Find({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ServiceExecutablePath' }}, $true)
$startupFunction = $ast.Find({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-StartupCommandFacts' }}, $true)
if ($null -eq $serviceFunction -or $null -eq $startupFunction) {{ throw 'SAFE_PATH_HELPER_NOT_FOUND' }}
Invoke-Expression $serviceFunction.Extent.Text
Invoke-Expression $startupFunction.Extent.Text
$servicePlain = Get-ServiceExecutablePath '"C:\Users\Alice\AppData\Local\Acme\agent.exe" -Token=PCIT_SECRET_SENTINEL'
$serviceWrapped = Get-ServiceExecutablePath '"C:\Windows\System32\Acme\agent.exe -Token PCIT_SECRET_SENTINEL"'
$startupPlain = Get-StartupCommandFacts 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Token PCIT_SECRET_SENTINEL -File C:\Tools\agent.ps1'
$startupWrapped = Get-StartupCommandFacts '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Token PCIT_SECRET_SENTINEL -File C:\Tools\agent.ps1"'
[pscustomobject]@{{
  ServicePlain=$servicePlain
  ServiceWrapped=$serviceWrapped
  StartupPlain=$startupPlain
  StartupWrapped=$startupWrapped
}} | ConvertTo-Json -Depth 5 -Compress
"""
    result = _run_ps(script)
    assert result.returncode == 0, "Native safe path helpers failed on synthetic inputs."
    assert not result.stderr.strip(), "Native safe path helpers emitted a PowerShell error."
    assert "PCIT_SECRET_SENTINEL" not in result.stdout
    assert "Alice" not in result.stdout
    facts = json.loads(result.stdout.strip())
    assert facts["ServicePlain"] == r"C:\Users\<redacted>\AppData\Local\Acme\agent.exe"
    assert facts["ServiceWrapped"] == "UNKNOWN"
    assert facts["StartupPlain"]["ImagePath"].endswith("powershell.exe")
    assert facts["StartupPlain"]["ScriptPath"] == r"C:\Tools\agent.ps1"
    assert facts["StartupWrapped"]["ImagePath"] == "UNKNOWN"
    assert facts["StartupWrapped"]["ScriptPath"] == "UNKNOWN"


def test_scheduled_task_json_boundary_omits_arguments_and_author() -> None:
    assert POWERSHELL, "Windows PowerShell is required for scheduled task privacy contract tests."
    encoded_source = base64.b64encode(
        scheduled_collector._powershell_script().encode("utf-16le")
    ).decode("ascii")
    script = fr"""
$ErrorActionPreference = 'Stop'
$source = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{encoded_source}'))
$tokens = $null
$parseErrors = $null
$sourceAst = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {{ throw 'TASK_SOURCE_PARSE_FAILED' }}
$functions = $sourceAst.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }}, $true)
foreach ($function in $functions) {{ Invoke-Expression $function.Extent.Text }}
$task = [pscustomobject]@{{
  TaskName='FixtureTask'
  TaskPath='\Fixture\'
  State='Ready'
  Author='TASK_AUTHOR_SENTINEL'
  Actions=@(
    [pscustomobject]@{{ Execute='powershell.exe'; Arguments='-NoProfile -File "C:\Users\Alice\AppData\Roaming\agent.ps1" -Token=TASK_SECRET_SENTINEL' }},
    [pscustomobject]@{{ Execute='"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Token TASK_SECRET_SENTINEL -File C:\Tools\agent.ps1"'; Arguments='' }}
  )
}}
ConvertTo-PciSafeScheduledTask $task | ConvertTo-Json -Depth 5 -Compress
"""
    result = _run_ps(script)
    assert result.returncode == 0, "Synthetic scheduled task projection failed."
    assert not result.stderr.strip(), "Synthetic scheduled task projection emitted a PowerShell error."
    assert "TASK_SECRET_SENTINEL" not in result.stdout
    assert "TASK_AUTHOR_SENTINEL" not in result.stdout
    assert "-Token" not in result.stdout
    assert "Alice" not in result.stdout
    projected = json.loads(result.stdout.strip())
    assert projected["Actions"] == "powershell.exe | UNKNOWN"
    assert projected["ScriptPaths"] == [r"C:\Users\<redacted>\AppData\Roaming\agent.ps1"]
    assert projected["UnknownActionPathCount"] > 0
    assert "Author" not in projected
    assert projected["ArgumentsAndAuthor"] == "OMITTED_FOR_PRIVACY"

    original_runner = scheduled_collector.powershell_json
    try:
        scheduled_collector.powershell_json = lambda _script, timeout: [projected]
        collected = scheduled_collector.collect()
    finally:
        scheduled_collector.powershell_json = original_runner
    assert collected["status"] == "partial"
    assert collected["errors"]
    analysis = analyze_risk({"scheduled_tasks": collected}, load_rules(
        str(ROOT / "rules" / "windows_risk_rules.example.json")
    ))
    assert any(item["finding_id"] == "WIN_SCHEDULED_TASK_SUSPICIOUS_PATH" for item in analysis.findings)


def test_security_inventory_json_boundary_omits_uninstall_and_driver_arguments() -> None:
    assert POWERSHELL, "Windows PowerShell is required for security inventory privacy contract tests."
    installed_source = security_vendors_collector._installed_programs_script()
    driver_source = security_vendors_collector._drivers_script()
    installed_encoded = base64.b64encode(installed_source.encode("utf-16le")).decode("ascii")
    driver_encoded = base64.b64encode(driver_source.encode("utf-16le")).decode("ascii")
    script = fr"""
$ErrorActionPreference = 'Stop'
$sources = @(
  [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{installed_encoded}')),
  [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{driver_encoded}'))
)
foreach ($source in $sources) {{
  $tokens = $null
  $parseErrors = $null
  $sourceAst = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors.Count -gt 0) {{ throw 'SECURITY_SOURCE_PARSE_FAILED' }}
  $functions = $sourceAst.FindAll({{ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }}, $true)
  foreach ($function in $functions) {{ Invoke-Expression $function.Extent.Text }}
}}
$programInput = [pscustomobject]@{{
  DisplayName='360 Security Fixture'
  DisplayVersion='1.0'
  Publisher='360'
  InstallLocation='C:\Users\Alice\AppData\Local\360'
  UninstallString='msiexec /x FIXTURE -Password=INSTALL_SECRET_SENTINEL'
  QuietUninstallString='vendor-uninstall -Token=QUIET_SECRET_SENTINEL'
}}
$driverInput = [pscustomobject]@{{
  Name='360FixtureFilter'
  DisplayName='360 Fixture Filter'
  State='Running'
  StartMode='System'
  PathName='"C:\Users\Alice\AppData\Local\360\filter.sys" -Token=DRIVER_SECRET_SENTINEL'
  ServiceType='Kernel Driver'
}}
$program = ConvertTo-PciSafeInstalledProgram $programInput 'HKCU'
$driver = ConvertTo-PciSafeSystemDriver $driverInput
[pscustomobject]@{{ Program=$program; Driver=$driver }} | ConvertTo-Json -Depth 5 -Compress
"""
    result = _run_ps(script)
    assert result.returncode == 0, "Synthetic security inventory projection failed."
    assert not result.stderr.strip(), "Synthetic security inventory projection emitted a PowerShell error."
    for marker in (
        "INSTALL_SECRET_SENTINEL",
        "QUIET_SECRET_SENTINEL",
        "DRIVER_SECRET_SENTINEL",
        "-Password",
        "-Token",
        "Alice",
    ):
        assert marker not in result.stdout
    projected = json.loads(result.stdout.strip())
    assert projected["Program"]["InstallLocation"] == r"C:\Users\<redacted>\AppData\Local\360"
    assert "UninstallString" not in projected["Program"]
    assert "QuietUninstallString" not in projected["Program"]
    assert projected["Driver"]["PathName"] == r"C:\Users\<redacted>\AppData\Local\360\filter.sys"
    assert projected["Driver"]["ArgumentsOmitted"] is True

    registry = load_rules(str(ROOT / "rules" / "windows_risk_rules.example.json"))
    vendor_patterns = registry["vendor_patterns"]
    installed = security_vendors_collector.normalize_installed_programs(
        [projected["Program"]], vendor_patterns
    )
    drivers = security_vendors_collector.normalize_drivers(
        [projected["Driver"]], vendor_patterns
    )
    assert installed and installed[0]["matched_vendor"] == "360"
    assert installed[0]["uninstall_string"] is None
    assert installed[0]["quiet_uninstall_string"] is None
    assert drivers and drivers[0]["matched_vendor"] == "360"
    assert drivers[0]["path_name"] == r"C:\Users\<redacted>\AppData\Local\360\filter.sys"

    unknown_driver_result = security_vendors_collector.collect_drivers(
        vendor_patterns,
        powershell_runner=lambda _script, timeout: {
            "Items": [{"Name": "360FixtureFilter", "PathName": "UNKNOWN"}],
            "UnresolvedPathCount": 1,
        },
    )
    assert unknown_driver_result["status"] == "partial"
    assert unknown_driver_result["errors"]


def test_hotfix_dates_sort_chronologically_and_ambiguous_dates_stay_unknown() -> None:
    script = f"""
. {_ps_literal(HELPER)}
$ordered = Get-PciHotfixSummary -Hotfixes @(
  [pscustomobject]@{{ InstalledOn='2025-12-31' }},
  [pscustomobject]@{{ InstalledOn='2024-02-01' }}
)
$ambiguous = Get-PciHotfixSummary -Hotfixes @([pscustomobject]@{{ InstalledOn='2/1/2024' }})
$invalid = Get-PciHotfixSummary -Hotfixes @([pscustomobject]@{{ InstalledOn='not-a-date' }})
$missing = Get-PciHotfixSummary -Hotfixes @([pscustomobject]@{{ InstalledOn=$null }})
[pscustomobject]@{{
  OrderedStatus=$ordered.Status; OrderedLatest=$ordered.LatestInstalled
  AmbiguousStatus=$ambiguous.Status; AmbiguousLatest=$ambiguous.LatestInstalled
  InvalidStatus=$invalid.Status; MissingStatus=$missing.Status
}} | ConvertTo-Json -Compress
"""
    result = _run_ps(script)
    assert result.returncode == 0, result.stderr or result.stdout
    import json

    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value["OrderedStatus"] == "collected"
    assert value["OrderedLatest"] == "2025-12-31"
    assert value["AmbiguousStatus"] == "unknown" and value["AmbiguousLatest"] is None
    assert value["InvalidStatus"] == "unknown"
    assert value["MissingStatus"] == "unknown"
    inspect = INSPECT.read_text(encoding="utf-8")
    local_security = (ROOT / "collectors" / "windows_security.py").read_text(encoding="utf-8")
    assert "Get-PciHotfixSummary -Hotfixes $qfe" in inspect
    assert "Get-PciHotfixSummary -Hotfixes $hotfixes" in local_security
    assert "LatestHotfixDate=UNKNOWN" in inspect
    assert "Quick-fix engineering dates were missing, ambiguous, or invalid" in local_security


def test_local_security_powershell_script_parses_without_running_collectors() -> None:
    source = (ROOT / "collectors" / "windows_security.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    script_text = None
    for node in ast.walk(module):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "script" for target in node.targets
        ) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            if "__PCI_HELPER_PATH__" in node.value.value:
                script_text = node.value.value
                break
    assert script_text is not None
    script_text = script_text.replace("__PCI_HELPER_PATH__", _ps_literal(HELPER))
    with tempfile.TemporaryDirectory(prefix="pcit-ps-parse-") as temporary:
        path = Path(temporary) / "windows-security.ps1"
        path.write_text(script_text, encoding="utf-8-sig")
        result = _run_ps(
            f"""
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile({_ps_literal(path)}, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {{ $errors | ForEach-Object {{ Write-Error $_.Message }}; exit 1 }}
'POWERSHELL_PARSE_OK'
"""
        )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "POWERSHELL_PARSE_OK" in result.stdout


def test_capture_preflight_rejects_existing_file_and_reparse_parent() -> None:
    assert POWERSHELL, "Windows PowerShell is required for capture contract tests."
    with tempfile.TemporaryDirectory(prefix="pcit-preflight-") as temporary:
        root = Path(temporary)
        existing_file = root / "do-not-overwrite.txt"
        existing_file.write_text("preserve-me", encoding="ascii")
        result = subprocess.run(
            [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(INSPECT), "-OutputDirectory", str(existing_file)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )
        assert result.returncode == 2
        assert existing_file.read_text(encoding="ascii") == "preserve-me"

        target = root / "real-target"
        target.mkdir()
        link = root / "junction-output"
        junction = _run_ps(
            f"New-Item -ItemType Junction -Path {_ps_literal(link)} -Target {_ps_literal(target)} | Out-Null"
        )
        assert junction.returncode == 0, junction.stderr or junction.stdout
        try:
            blocked = _run_ps(
                f"""
. {_ps_literal(HELPER)}
try {{ [void](Assert-PciNoReparsePath -Path {_ps_literal(link / 'not-created')}); 'NOT_BLOCKED' }}
catch {{ 'BLOCKED=' + $_.Exception.Message }}
"""
            )
            assert blocked.returncode == 0, blocked.stderr or blocked.stdout
            assert "BLOCKED=REPARSE_PATH_BLOCKED" in blocked.stdout
            output = link / "capture-output"
            blocked_capture = subprocess.run(
                [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", str(INSPECT), "-OutputDirectory", str(output)],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
            )
            assert blocked_capture.returncode == 2
            assert not (target / "capture-output").exists()
        finally:
            os.rmdir(link)


def test_temp_cleanup_is_contained_and_removes_only_owned_temp_files() -> None:
    external = Path(tempfile.mkdtemp(prefix="pcit-outside-")) / ("pcit-security-" + uuid.uuid4().hex)
    external.mkdir()
    sentinel = external / "preserve.txt"
    sentinel.write_text("do-not-delete", encoding="ascii")
    blocked = _run_ps(
        f"""
. {_ps_literal(HELPER)}
try {{ Remove-PciPrivateTempDirectory -Path {_ps_literal(external)} -Prefix 'pcit-security'; 'NOT_BLOCKED' }}
catch {{ 'BLOCKED=' + $_.Exception.Message }}
"""
    )
    assert blocked.returncode == 0, blocked.stderr or blocked.stdout
    assert "BLOCKED=TEMP_CLEANUP_TARGET_OUTSIDE_TEMP_ROOT" in blocked.stdout
    assert sentinel.read_text(encoding="ascii") == "do-not-delete"

    owned = Path(tempfile.gettempdir()) / ("pcit-security-" + uuid.uuid4().hex)
    owned.mkdir()
    owned_file = owned / "merged-policy.inf"
    owned_file.write_text("[System Access]\nPasswordComplexity=1\n", encoding="ascii")
    try:
        result = _run_ps(
            f". {_ps_literal(HELPER)}; Remove-PciPrivateTempDirectory -Path {_ps_literal(owned)} -Prefix 'pcit-security'"
        )
        assert result.returncode == 0, result.stderr or result.stdout
        assert not owned.exists()
    finally:
        if owned.exists():
            owned_file.unlink(missing_ok=True)
            owned.rmdir()
        if external.exists():
            sentinel.unlink(missing_ok=True)
            external.rmdir()
            external.parent.rmdir()


if __name__ == "__main__":
    if POWERSHELL:
        test_native_entrypoint_and_row_cap_cross_start_job_boundary()
        test_secedit_parser_handles_real_fields_missing_fields_and_denial()
        test_native_sidecar_writer_round_trips_collected_partial_and_failed_evidence()
        test_python_collector_json_boundaries_omit_command_arguments_and_user_names()
        test_native_command_path_helpers_drop_ambiguous_arguments()
        test_scheduled_task_json_boundary_omits_arguments_and_author()
        test_security_inventory_json_boundary_omits_uninstall_and_driver_arguments()
        test_local_security_powershell_script_parses_without_running_collectors()
        test_capture_preflight_rejects_existing_file_and_reparse_parent()
        test_temp_cleanup_is_contained_and_removes_only_owned_temp_files()
        print("Windows native capture contract tests passed.")
    else:
        print("Windows native capture contract tests skipped: powershell.exe is unavailable.")
