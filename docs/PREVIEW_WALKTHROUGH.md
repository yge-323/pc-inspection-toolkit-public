# Source preview walkthrough

This record is bound to public baseline commit `1231491cce01704d195960ba4f5be6185141c547` on `main`. A fresh local clone and GUI launch were performed on 2026-10-20. This is a source-preview walkthrough, not a clean-machine, collection, hardware, administrator, or broad platform acceptance.

## Environment

- Windows 11 desktop session.
- Python 3.12.10.
- Tk 8.6.15; Tcl 8.6.
- Screenshot capture session: display size 1707×1067, Win32 window DPI 96, Tk scaling 1.332282448377581.
- The application used a 1240×840 logical window geometry. The captured image surface was 1862×1308 pixels.

## Fresh clone and checks

The public `main` ref was read repeatedly through a session-scoped route helper. The repeated reads agreed on the expected `1231491cce01704d195960ba4f5be6185141c547` head, after which `git clone` ran on that same selected route. The clone was clean on `main` at the expected head. Local route details were not recorded.

Commands run from the fresh clone:

```powershell
python --version
# Python 3.12.10

python -c "import tkinter as tk; root=tk.Tk(); print('Tk', root.tk.call('info','patchlevel')); print('scaling', root.tk.call('tk','scaling')); root.withdraw(); root.destroy()"
# Tk 8.6.15
# scaling 1.332282448377581

python -X utf8 -B .\inspection_cli.py --help
# Exit code 0; printed the CLI usage and available commands.

python -X utf8 -B .\inspection_cli.py --version
# 0.3.0-landable

python -B .\desktop_launcher.py
# Opened a visible window titled "PC Inspection Toolkit · 现场巡检与证据分析".
# Closed the window with Alt+F4; process exit code 0.
```

The first GUI screen showed its authorization step waiting for confirmation. No local inspection, evidence import, UAC prompt, AI request, or collection command was started. The screenshots show page layouts; they are not evidence that those workflows were run.

## Screenshot source and capture record

The three PNGs in `docs/assets/` were captured from the actual Tk application window at baseline `1231491c`. A runtime-only screenshot harness overrode `desktop_ui.application_root` to return the synthetic path `C:/PCIT-Demo`; no application source was changed. The window was captured through `@oai/sky` `get_window_state` and its `Screenshot.url` data URL. That API returned JPEG data. The JPEG bytes were saved temporarily, then decoded and written as PNG with Windows `System.Drawing`; no crop, paint, retouch, or generated content was applied. The fresh-clone walkthrough separately used the standard `desktop_launcher.py` entry point without the path override.

Capture harness:

```powershell
python -B -c "import desktop_ui; from pathlib import Path; desktop_ui.application_root = lambda: Path('C:/PCIT-Demo'); from desktop_app import main; raise SystemExit(main())"
```

The in-memory capture and conversion steps were:

```javascript
const shot = state.screenshots[0];
const bytes = Buffer.from(shot.url.slice(shot.url.indexOf(",") + 1), "base64");
await writeFile(tempJpegPath, bytes, { flag: "wx" });
```

```powershell
$image = [System.Drawing.Image]::FromFile($tempJpegPath)
try { $image.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png) }
finally { $image.Dispose() }
```

All three captures used the same window geometry and screen session. Synthetic paths are visible only as `C:\PCIT-Demo\...`; no authorization box was selected, and the optional AI provider remained off.

| Screenshot | File | Dimensions | SHA-256 |
| --- | --- | ---: | --- |
| Overview | `docs/assets/preview-overview.png` | 1862×1308 | `f860a50e8d5882ef6b458c7dea9fc1a16ffe4c7a7f6fab29b0ade53ea363dcf6` |
| Local inspection | `docs/assets/preview-local-inspection.png` | 1862×1308 | `566891a8372d541591a7c5450ee70c1b09b4e13b0ba60cc12e5425fd20f52dd5` |
| Evidence import | `docs/assets/preview-evidence-import.png` | 1862×1308 | `1b8e38f0b8c07bc4463a0801bb813eaef1dfa212e4746c65664b6bab18ccc96c` |

## Scope limits

This walkthrough verifies the documented source launch, Python/Tk imports, CLI help/version output, and the presence of three real GUI screenshots. It does not verify collection behavior, real evidence analysis, exports, UAC or administrator behavior, clean-machine installation, other Python/Tk combinations, POSIX targets, or hardware-specific checks. The screenshots illustrate the interface, not a successful inspection result.

## Bilingual interface and report follow-up

This follow-up is for the public staging candidate based on `033a669bd0737bce6c32ae04876f908f7810d30f` on branch `codex/bilingual-ui-reports`. It records the bilingual source changes and synthetic checks; it is not a clean-machine, administrator, hardware, or production acceptance.

- The GUI now defaults to Simplified Chinese, remembers its selected language per Windows user, and accepts a command-line language override. English and Chinese built-in findings and owned desktop diagnostics are translated. User paths, raw evidence, custom rule content, and unknown diagnostics retain their source text. Missing owned GUI/report strings fail validation rather than silently mixing languages.
- The analysis page has an independent report-language selection that follows the interface by default or explicitly selects either language. Luna Builder's real GUI runs used the sealed synthetic bundle with English UI and automatic report language, then English UI with an explicit Chinese report language in separate output directories. Both runs retained the same `analysis.json` SHA-256 (`dd0a7eaba5d8401b84f658bd97201bfc938c8a3f3ed813984902221c9c2f4a0c`), 11 findings, `PARTIAL`, and no AI execution. Sol independently verified the CLI behavior and hashes, and later confirmed that a fresh source GUI could load the hash-matched synthetic analysis and preserve its state across language changes.
- The CLI defaults to Chinese independently of GUI preferences. `--lang` selects human-facing CLI messages; `--report-lang` independently selects report text and defaults to `--lang`. Ten focused CLI tests passed, and real-process tests verified both language directions, recursive import flow, exit code 4 for the incomplete synthetic case, byte-identical analysis JSON, and unchanged GUI preference bytes.
- Targeted GUI tests passed for language switching, preserving authorization and Finding selections, owned worker-status retranslation, and the findings severity column. The geometry regression test now waits for naturally delivered Configure/debounce events and checks the final allocated text width and height. An earlier assertion used a parent-container width that did not match the label's actual settled allocation; the test contract now measures the settled widget's inner width.
- The focused GUI/i18n check skipped two cases on this host: the POSIX FIFO case is unavailable on Windows, and symlink creation was unavailable in this environment. The final 27-file runner had four skip instances; the two additional cases were the POSIX paste exporter round-trip (Windows) and the POSIX capture runner symlink boundary (symlink creation unavailable). These skips are reported as skips, not passes.
- During a native file-picker exercise, a stale picker selection briefly referenced a private sibling checkout. The GUI process was stopped immediately; no file was modified or copied, and no screenshot was saved for public use from that selection. A tool state capture did contain the path, and the event was reported to the coordinator. Sol independently verified that a separate synthetic `analysis.json` previously written under `C:\PCIT-Demo` has the same SHA-256 as the public sample. The resumed GUI only reads that synthetic analysis; no further writes or cleanup were made under `C:\PCIT-Demo`.

No real local collection, UAC/admin action, AI request, or network evidence collection was run. The accompanying bilingual example is synthetic and offline. Screenshot evidence for the final source candidate is recorded alongside the six bilingual images; those images show interface layout and synthetic analysis only, not a successful inspection.

### Final bilingual GUI and offline regression (2026-10-21)

The final source GUI was opened on Windows and natively browsed at a maximized 2560×1529 capture size. Both locales were checked on all five pages: Overview, Local inspection, Import evidence, Analysis and reports, and Review and handoff. The English and Chinese import/review checks were navigation and rendering checks only; they did not invoke import, export, comparison, collection, UAC, AI, or network actions. The analysis page displayed the hash-verified synthetic `analysis.json` reused read-only from `C:\PCIT-Demo`; no new files were written there during this resumed GUI review. The saved interface preference was returned to Chinese before closing the GUI.

Luna Builder captured the following six images from the actual GUI window. All use the same dimensions and are unmodified full-window JPEG captures. Sol independently inspected the images, including the final Chinese report capture, for layout and visible personal data.

| Locale | Page | File | Dimensions | SHA-256 |
| --- | --- | --- | ---: | --- |
| English | Overview | `docs/assets/bilingual-en-overview.jpg` | 2560×1529 | `550e3cb75e836d694fbcf76db4bca1aae9644703405bf57873118b9e7b45dc96` |
| English | Local inspection | `docs/assets/bilingual-en-local.jpg` | 2560×1529 | `1511da877e3fcbf9c5c300a5142727ca402c3fd799ebdb8a47a2688b0cd00c20` |
| English | Analysis and reports | `docs/assets/bilingual-en-report.jpg` | 2560×1529 | `bd63b9a3790bd033d3714370c89c72ef37a6c63a9bc544bf2c7b0ccd3781c1ce` |
| Chinese | Overview | `docs/assets/bilingual-zh-overview.jpg` | 2560×1529 | `a26b9bdf7bd9c1aac18c6268cb163f9f43054e7535609e860282bb42e4f07413` |
| Chinese | Local inspection | `docs/assets/bilingual-zh-local.jpg` | 2560×1529 | `e92fd0511b7c2d635eec2ec6c701ba537780e0d19838ee84c86eb1ceb294ad28` |
| Chinese | Analysis and reports | `docs/assets/bilingual-zh-report.jpg` | 2560×1529 | `b6d0c22d710b39f11fec78e46ef8431f0aad389dc7c86b7c77c98586e9bce879` |

Final verification on this candidate:

```powershell
python -B tests/run_unit_tests.py
# Exit code 0; all 27 Python MVP core offline test files passed.
# Four tests were skipped for host/platform constraints:
# - POSIX paste exporter round-trip is unavailable on Windows.
# - POSIX FIFO special-file coverage is unsupported on Windows.
# - Symlink creation was unavailable for the GUI preference boundary test.
# - Symlink creation was unavailable for the POSIX capture runner boundary test.

python -B tests/test_restart_build.py
# Exit code 0; all 5 source-package/build-contract tests passed.
# The allowlisted source copy's real subprocess help was checked in default Chinese
# and explicit English, with strict UTF-8 decoding, plus the version command.
# This is a source/build contract check; it did not create an EXE or ZIP.
```

The first full-run attempt exposed an old test expecting English CSV headers; it now parses CSV and checks translated headers plus the stable Finding ID. A later attempt exposed a Tk timing assertion; it now waits up to three seconds for naturally delivered resize/debounce events and a stable window size, and test teardown cancels callbacks in its isolated Tk interpreter. The restart contract initially assumed English `usage:` output; it now verifies the Chinese default help, English `--lang en --help`, and version through the allowlisted source package with strict UTF-8 decoding. Empty references no longer leave trailing spaces in Markdown; regenerating both locale outputs from the real CLI matched all eight published example artifacts byte-for-byte. Earlier failed logs are retained at `work/bilingual-final-unit-tests.log` and `work/bilingual-final-unit-tests-repaired.log`; final successful logs are `work/bilingual-final-unit-tests-final-pass.log` and `work/bilingual-final-restart-contracts.log`.

These checks do not cover real local collection, administrator/UAC behavior, real evidence media, AI requests, cross-platform GUI behavior, clean-machine installation, or long-term production use. The bilingual bundle and screenshots remain synthetic offline examples.

### Indexed bilingual fixture integrity boundary (2026-10-21)

The source bundle and report fixtures are sealed byte-for-byte examples. The public staging index initially normalized their CRLF bytes under the local `core.autocrlf` setting, which changed hashes despite an unchanged working copy. `.gitattributes` now assigns `-text whitespace=cr-at-eol` only to `docs/examples/bilingual/source_bundle/**` and `docs/examples/bilingual/reports/**`. This preserves fixture bytes while keeping `git diff --check` able to distinguish CRLF from actual trailing spaces; no global Git whitespace or line-ending setting was changed.

Validation was performed against a fresh `git checkout-index` export under ignored `work/`, so the CLI used the exact staged files. All 14 manifest entries matched their declared byte sizes and SHA-256 values; all 28 source evidence files matched the recorded hash map (`6be8b1b094d1d9237b3b6ae7fc32aa4cef4f1ee16645e6abaefca4d66f5c2ab3`); the exported manifest hash was `f4128b69b13e98dd30e5b06acb5a9deca2c02f86fcd9b8d5bdf6ada5e4389eb6`. Both indexed locale `analysis.json` artifacts matched `dd0a7eaba5d8401b84f658bd97201bfc938c8a3f3ed813984902221c9c2f4a0c`.

From that index export, a real offline CLI import exited 0. English CLI text with an explicit Chinese report and English CLI text with automatic report language each analyzed the imported case as `PARTIAL`, exited 4, emitted `AI_NOT_RUN`, and produced the same canonical analysis JSON hash. The input bundle was read from the index export; generated cases and reports stayed under ignored `work/`. After the Markdown whitespace fix, `python -B tests/test_markdown_report.py` and `python -B tests/test_windows_security.py` both passed. The earlier full 27-file offline run and the five restart/build source contracts are recorded above; no packaging was run.
