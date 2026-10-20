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
