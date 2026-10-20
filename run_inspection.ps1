param(
    [string]$OutputDir = "reports/output",
    [string]$RawDir = "data/raw"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host "Windows Inspection MVP"
Write-Host "Project path: $ProjectRoot"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        & $py.Source -3 "$ProjectRoot\run_inspection.py" --output-dir $OutputDir --raw-dir $RawDir
        exit $LASTEXITCODE
    }
    Write-Host "ERROR: Python 3.10+ was not found. Please install or run with an available Python interpreter."
    Write-Host "See logs/execution if a previous run created logs."
    exit 1
}

& $python.Source "$ProjectRoot\run_inspection.py" --output-dir $OutputDir --raw-dir $RawDir
exit $LASTEXITCODE
