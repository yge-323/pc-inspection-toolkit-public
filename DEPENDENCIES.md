# Dependency and third-party license inventory

Reviewed against source commit `0f9e89ee863cde27b36575501ea056efe3f5c070` on 2026-10-18. The repository has no dependency lockfile or pinned dependency manifest. The entries below identify observed or declared dependency families; they do not identify exact versions installed on a user's machine.

| Component | Use in this project | License identified upstream | Included in source snapshot? |
| --- | --- | --- | --- |
| Python 3.10+ runtime and standard library | Runtime; includes the `tkinter` wrapper. Python software is generally under the PSF License Version 2, but the Python distribution includes components with separate licenses; exact contents depend on the supplied Python build. | PSF License Version 2 for Python software; component-specific licenses may also apply | No; user supplies Python |
| Tcl/Tk | GUI runtime used through `tkinter` | Tcl/Tk license terms (BSD-style) | No; comes from the user's Python distribution |
| `pywinrm` | Optional CLI WinRM transport; imported only for that command | MIT | No |
| `requests` | Required dependency of `pywinrm` | Apache-2.0 | No |
| `requests-ntlm` | Required dependency of `pywinrm` | ISC | No |
| `xmltodict` | Required dependency of `pywinrm` | MIT | No |
| PyInstaller | Optional Windows packaging/build tool invoked by `build_restart.py` | GPL-2.0-or-later WITH Bootloader-exception; some runtime hooks/modules use Apache-2.0 | No; this task does not build or redistribute binaries |
| PyInstaller declared build-tool dependencies | Current upstream metadata declares `altgraph`, `packaging`, `setuptools`, and `pyinstaller-hooks-contrib`, plus platform- or Python-version-conditional packages including `pefile`, `pywin32-ctypes`, `macholib`, and `importlib_metadata` | Each has its own upstream license; resolved versions and their complete license texts were not captured for this source-only review | No |
| PowerShell, CMD, `sh`, Perl and system utilities | OS-provided commands called by in-tree scripts | Governed by each installed operating system/tool distribution | No; the project includes scripts, not these runtimes |

The application source imports only the standard library plus optional `winrm`; no third-party package implementation is vendored. The cited upstream `pywinrm` metadata declares `requests`, `requests_ntlm`, and `xmltodict`. The cited PyInstaller metadata declares build-tool dependencies, some conditional on platform or Python version. These upstream branches can change, and no versions are pinned in this repository, so they describe dependency families rather than a resolved environment. A reproducible WinRM or PyInstaller environment cannot be claimed from this source tree alone.

The clean source snapshot contains no Python, Tcl/Tk, WinRM, PyInstaller, or operating-system binaries. Before distributing a Windows onedir/EXE, build from a locked environment and review the actual bundle's license files and notices, including Python/Tcl/Tk, OpenSSL, zlib, platform runtimes, and all resolved transitive packages. An earlier package inventory from another branch is not evidence for a build from this source revision. Binary redistribution has not been reviewed here.

Upstream references checked:

- Python license: <https://github.com/python/cpython/blob/main/LICENSE>
- `pywinrm` dependency metadata: <https://github.com/diyan/pywinrm/blob/master/pyproject.toml>
- `requests-ntlm` ISC license: <https://github.com/requests/requests-ntlm/blob/master/LICENSE>
- Requests license: <https://github.com/psf/requests/blob/main/LICENSE>
- `xmltodict` MIT license: <https://github.com/martinblech/xmltodict/blob/master/LICENSE>
- PyInstaller license and component distinctions: <https://github.com/pyinstaller/pyinstaller/blob/develop/COPYING.txt> and <https://github.com/pyinstaller/pyinstaller/blob/develop/pyproject.toml>
- Tcl/Tk license terms: <https://github.com/tcltk/tk/blob/main/license.terms>

The exact third-party dependency versions and all redistributed files must be resolved and recorded before a binary build is approved.
