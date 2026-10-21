# Synthetic bilingual report example

This is a fully synthetic, offline Windows evidence example. It contains no real device data, user names, external IP addresses, or live collection output. The Chinese CPU label is deliberately preserved as a raw evidence value in both languages. The administrator-member count and startup-item detail are intentionally unavailable, so the analysis is `PARTIAL` and the CLI exits with code 4.

## Reproduce

From the project root, import the already sealed source bundle and use the `CASE=` path printed by the command:

```powershell
$run = "work/bilingual-report-demo/replay-$(Get-Date -Format yyyyMMddHHmmss)"
$importOutput = python -X utf8 -B inspection_cli.py import docs/examples/bilingual/source_bundle --cases "$run/cases" --lang zh
$importExit = $LASTEXITCODE
$importOutput
if ($importExit -ne 0) { throw "Import failed with exit code $importExit" }
$casePath = ($importOutput | Where-Object { $_ -like 'CASE=*' } | Select-Object -First 1).Substring(5)

python -X utf8 -B inspection_cli.py analyze $casePath --output "$run/rendered/zh" --lang zh
$zhExit = $LASTEXITCODE
python -X utf8 -B inspection_cli.py analyze $casePath --output "$run/rendered/en" --lang en
$enExit = $LASTEXITCODE
"zh exit=$zhExit; en exit=$enExit (both expected 4 for PARTIAL)"
```

`source_bundle/` already contains its manifest, so import it directly; do not seal it again. The ignored `work/bilingual-report-demo/generate_bilingual_example.py` was used internally to create and verify this reviewed sample. It is not included in a public checkout and is not needed to reproduce the reports. The public steps above use the standard CLI and do not run collectors or request AI.

The import command should print a line beginning with `CASE=`. The commands above capture that value and pass the same imported case to both analyses. If running the commands separately, replace `<case-path>` below with the path after `CASE=`:

```powershell
python -X utf8 -B inspection_cli.py analyze <case-path> --output work/bilingual-report-demo/render/zh --lang zh
python -X utf8 -B inspection_cli.py analyze <case-path> --output work/bilingual-report-demo/render/en --lang en
```

Import is expected to return exit code `0`. Each analyze command is expected to return exit code `4` because the sample intentionally lacks evidence for the administrator-member count and startup-item detail. The machine status remains `ANALYSIS_STATUS=PARTIAL`; finding IDs, severity, evidence, and analysis JSON do not vary with display language. The generated files appear below `$run/rendered/zh/` and `$run/rendered/en/`.

## Generated results

- zh: `docs/examples/bilingual/reports/zh/0b979937-3954-450b-ae00-734e6c571f15/report.md`, `report.html`, `findings.csv`, `analysis.json` (exit 4)
- en: `docs/examples/bilingual/reports/en/0b979937-3954-450b-ae00-734e6c571f15/report.md`, `report.html`, `findings.csv`, `analysis.json` (exit 4)

The run produced 11 findings. Both analyses returned `PARTIAL`; the same administrator-count gap was retained. `analysis.json` SHA-256: `dd0a7eaba5d8401b84f658bd97201bfc938c8a3f3ed813984902221c9c2f4a0c`. Source/imported manifest SHA-256: `f4128b69b13e98dd30e5b06acb5a9deca2c02f86fcd9b8d5bdf6ada5e4389eb6`. Source evidence hash-map SHA-256: `6be8b1b094d1d9237b3b6ae7fc32aa4cef4f1ee16645e6abaefca4d66f5c2ab3`. Source and imported evidence file hashes and both manifest hashes were identical before and after analysis. See `execution-summary.json` for per-file SHA-256 values and finding keys.
