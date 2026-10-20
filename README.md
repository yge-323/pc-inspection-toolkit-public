# PC Inspection Toolkit

[简体中文](README.zh-CN.md)

**0.3.0 Preview · source checkout**

PC Inspection Toolkit is a read-only inspection and offline evidence-analysis tool for authorized maintenance work. It presents collected facts, deterministic findings, evidence gaps, and human review steps. It does not automatically remediate systems or elevate privileges.

## Current source capabilities

- A Chinese Windows desktop guide for explicitly authorized, current-PC read-only collection and evidence import. The desktop GUI is developed and validated on Windows; this is not a clean-machine or administrator acceptance claim.
- Import and offline analysis of validated Windows and POSIX evidence bundles, with explicit `OK`, `PARTIAL`, or `FAILED` status.
- POSIX shell collection and SecureCRT / 4A paste import for an already authorized session. The tool does not connect to those targets itself.
- HTML, Markdown, CSV, and JSON reports; analysis comparison and redacted Codex export.
- Manual web-AI v2 export and structured-response import. The user controls any upload; the toolkit does not send web-AI requests.
- Experimental, opt-in local Ollama advisory analysis. It is off by default. Suggestions are separate from deterministic findings and do not change findings, severity, or status; recommendation quality has not been accepted as reliable.

## Platform and verification limits

The current source GUI has been exercised on Windows 11 with synthetic or redacted evidence, and automated Windows collector contract tests are present. Real local collection, a clean Windows installation, ordinary-versus-administrator coverage, and broad hardware coverage have not been accepted. The CLI has Windows and POSIX collection branches; no claim is made for every Linux distribution, legacy server, or macOS version. POSIX collectors and paste workflows require an already authorized operator session. AIX, Windows Server 2008, RHEL 5/6, real 4A environments, SMART/RAID and vendor-specific hardware checks remain unverified. The tool cannot guarantee that every security or maintenance issue will be found.

`PARTIAL` and `FAILED` are not successful inspections. Missing or inaccessible evidence remains unknown or incomplete; it is not reported as healthy.

## Run from source

For the Windows desktop GUI, use Python 3.10 or later with Tkinter. Opening the GUI does not start collection:

```powershell
python -B .\desktop_launcher.py
```

The CLI is the advanced interface. Inspect available commands first:

```powershell
python -B .\inspection_cli.py --help
```

Only run a local inspection after obtaining authorization for that computer:

```powershell
python -B .\inspection_cli.py inspect-local `
  --project-alias demo --asset-alias pc1 --use-case office_pc
```

SecureCRT / 4A paste import is available through the CLI and the desktop evidence-import workflow. The POSIX capture scripts must be run only in an already authorized session:

```sh
sh platforms/posix_capture.sh /tmp/ev-host1
sh platforms/posix_paste_export.sh /tmp/ev-host1 > /tmp/paste.txt
```

Then import the reviewed paste text on the maintenance computer with `inspection_cli.py paste-import`. Do not execute commands copied from untrusted evidence.

Core offline tests:

```powershell
python -B tests\run_unit_tests.py
```

## AI-Built · Human-Directed

Most implementation code was produced with AI programming tools. A human directed the requirements, testing, review, and release decisions. This project is not represented as fully autonomous or as having been developed without human involvement.

## License

The project owner selected Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), and the [dependency license inventory](DEPENDENCIES.md). Third-party components retain their own licenses. This source preview does not include Python, optional WinRM packages, PyInstaller, or a built application.

## Data and security

Inspection evidence, analysis files, reports, and logs may contain sensitive information. Keep them local, review every export before sharing, and do not upload real inspection data by default. See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [DEPENDENCIES.md](DEPENDENCIES.md). The existing Git history is not suitable for public reuse as-is; the public source snapshot must use the reviewed allowlist without `.git` history.
