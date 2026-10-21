param(
    [string]$OutputDir = "reports/output",
    [string]$RawDir = "data/raw",
    [ValidateSet("zh-CN", "en-US", "zh", "en")]
    [string]$Language,
    [ValidateSet("zh-CN", "en-US", "zh", "en")]
    [string]$ReportLanguage
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host "Windows 本地巡检工具 / Windows local inspection tool"
Write-Host "项目目录 / Project directory: $ProjectRoot"

$RunArgs = @("--output-dir", $OutputDir, "--raw-dir", $RawDir)
if ($PSBoundParameters.ContainsKey("Language")) {
    $RunArgs += @("--lang", $Language)
}
if ($PSBoundParameters.ContainsKey("ReportLanguage")) {
    $RunArgs += @("--report-lang", $ReportLanguage)
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        & $py.Source -3 "$ProjectRoot\run_inspection.py" @RunArgs
        exit $LASTEXITCODE
    }
    Write-Host "错误 / ERROR: 未找到 Python 3.10 或更高版本。请安装 Python，或使用已有解释器运行。 / Python 3.10 or later was not found. Install Python or run with an available interpreter."
    Write-Host "如之前运行生成过日志，请查看 logs/execution。 / See logs/execution if a previous run created logs."
    exit 1
}

& $python.Source "$ProjectRoot\run_inspection.py" @RunArgs
exit $LASTEXITCODE
