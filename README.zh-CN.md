# PC Inspection Toolkit

[English](README.md)

**0.3.0 Preview · 源码预览版**

PC Inspection Toolkit 是供获授权维护工作使用的只读巡检与离线证据分析工具，用于展示采集事实、确定性发现、证据缺口和人工核查步骤。它不会自动整改系统或提权。

## 当前源码能力

- 中文 Windows 桌面向导：经明确授权后，对当前电脑进行只读采集或导入证据。桌面 GUI 已在 Windows 环境开发和验证；这不代表干净机器或管理员权限验收通过。
- 导入并离线分析通过校验的 Windows 和 POSIX 证据包，明确显示 `OK`、`PARTIAL` 或 `FAILED`。
- POSIX Shell 采集及 SecureCRT / 4A 粘贴导入：仅用于已经授权的会话；工具本身不会连接这些目标。
- 生成 HTML、Markdown、CSV、JSON 报告；支持分析比较和 Codex 脱敏交付。
- 网页版 AI v2 分析包由用户手动导出，结构化回复由用户手动导入；工具不自动发送网页 AI 请求。
- 实验性、主动启用的本地 Ollama 辅助分析，默认关闭。建议与确定性 Findings 隔离，不改变 Finding、严重度或状态；建议质量尚未验收为可靠。

## 平台与验证限制

当前源码 GUI 已在 Windows 11 上使用合成或脱敏证据进行验证，并有 Windows 采集器契约测试。真实本机采集、干净 Windows 安装、普通用户与管理员权限矩阵或广泛硬件检查尚未验收。CLI 包含 Windows 与 POSIX 采集分支；不宣称支持所有 Linux 发行版、旧服务器或 macOS 版本。POSIX 采集及粘贴流程要求操作者已获得目标授权。AIX、Windows Server 2008、RHEL 5/6、真实 4A 环境、SMART/RAID 和厂商专用硬件检查仍未验证。工具不能保证发现所有安全或维护问题。

`PARTIAL` 和 `FAILED` 不代表巡检成功。缺失或无法读取的证据会保持未知或不完整，不会被报告为健康。

## 从源码运行

Windows 桌面 GUI 需要 Python 3.10 或更高版本及 Tkinter。打开 GUI 不会启动采集：

```powershell
python -B .\desktop_launcher.py
```

CLI 是高级入口。先查看可用命令：

```powershell
python -B .\inspection_cli.py --help
```

只有在取得该电脑巡检授权后才可执行本机巡检：

```powershell
python -B .\inspection_cli.py inspect-local `
  --project-alias demo --asset-alias pc1 --use-case office_pc
```

SecureCRT / 4A 粘贴导入可通过 CLI 和桌面证据导入流程使用。POSIX 采集脚本只能在已经授权的会话中运行：

```sh
sh platforms/posix_capture.sh /tmp/ev-host1
sh platforms/posix_paste_export.sh /tmp/ev-host1 > /tmp/paste.txt
```

随后在维护电脑上使用 `inspection_cli.py paste-import` 导入经审核的粘贴文本。不要执行来自不可信证据的命令。

核心离线测试：

```powershell
python -B tests\run_unit_tests.py
```

## AI-Built · Human-Directed

大部分实现代码由 AI 编程工具生成；人类负责需求指引、测试、审核和发布决策。本项目不宣称无人参与或 100% 自动开发。

## 许可证

项目所有者已选择 Apache-2.0。详见 [LICENSE](LICENSE)、[NOTICE](NOTICE) 和[依赖许可证清单](DEPENDENCIES.md)。第三方组件仍适用各自许可证。本源码预览不包含 Python、可选 WinRM 软件包、PyInstaller 或已构建应用。

## 数据与安全

巡检证据、分析文件、报告和日志可能包含敏感信息。请将其保留在本地，分享前逐项检查导出内容；默认不上传真实巡检数据。详见 [SECURITY.md](SECURITY.md)、[CONTRIBUTING.md](CONTRIBUTING.md) 和[依赖许可证清单](DEPENDENCIES.md)。现有 Git 历史不适合直接公开复用；公开源码快照必须按已审核白名单生成，且不带 `.git` 历史。
