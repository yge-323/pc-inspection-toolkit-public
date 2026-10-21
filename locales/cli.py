"""Translations for command-line help and human-facing status messages."""
from __future__ import annotations

import argparse
import re
import sys

from i18n import normalize_language


_EN = {
    "Offline evidence inspection and reporting tool": "Offline evidence inspection and reporting tool",
    "Create a manifest for a reviewed native evidence directory": "Create a manifest for a reviewed native evidence directory",
    "Validate and import a bundle into a new case directory": "Validate and import a bundle into a new case directory",
    "Analyze one validated, already imported bundle": "Analyze one validated, already imported bundle",
    "Use a validated listener knowledge JSON file (defaults to the bundled example).": "Use a validated listener knowledge JSON file (defaults to the bundled example).",
    "Assert Ollama cloud features were disabled before use": "Confirm Ollama cloud features were disabled before use",
    "Run authorized current-Windows collectors and render the same unified reports": "Run authorized current-Windows collectors and render the same unified reports",
    "Compare two analysis.json files": "Compare two analysis.json files",
    "Write a redacted summary for Codex conversation analysis": "Write a redacted summary for Codex conversation analysis",
    "Export selected allow-listed config facts after redaction": "Export selected allow-listed config facts after redaction",
    "Capture one explicitly authorized POSIX target using pinned OpenSSH host keys": "Capture one explicitly authorized POSIX target using pinned OpenSSH host keys",
    "Explicitly authorize using the already running SSH agent only; private-key files are never read": "Authorize the existing SSH agent for this capture; private-key files are never read",
    "Capture one explicitly authorized Windows target through HTTPS WinRM": "Capture one explicitly authorized Windows target through HTTPS WinRM",
    "Environment variable name containing the WinRM username": "Environment variable containing the WinRM username",
    "Environment variable name containing the WinRM password": "Environment variable containing the WinRM password",
    "Import bastion/SecureCRT paste block produced by platforms/posix_paste_export.sh": "Import a bastion/SecureCRT paste block produced by platforms/posix_paste_export.sh",
    "Text file containing the full BEGIN/END paste block": "Text file containing the complete BEGIN/END paste block",
    "Continue to analyze after import": "Analyze after import",
    "One-shot authorized local capture→seal→import→analyze (POSIX or Windows)": "One-shot authorized local capture, seal, import, and analysis (POSIX or Windows)",
    "Report output directory": "Report output directory",
    "Raw normalized data directory": "Raw normalized data directory",
    "Report files were created.": "Report files were created.",
    "The analysis is incomplete; review its evidence gaps.": "The analysis is incomplete; review its evidence gaps.",
    "Local AI was not requested; no AI request was sent.": "Local AI was not requested; no AI request was sent.",
    "The selected language preference was ignored; using Chinese.": "The saved language preference was ignored; using Chinese.",
    "Report": "Report",
    "Raw data": "Raw data",
    "Execution log": "Execution log",
    "Windows local inspection tool": "Windows local inspection tool",
    "Python 3.10 or later was not found. Install Python or run with an available interpreter.": "Python 3.10 or later was not found. Install Python or run with an available interpreter.",
    "See logs/execution if a previous run created logs.": "See logs/execution if a previous run created logs.",
    "Select the report and human message language": "Select the report and human message language",
    "The operation failed. Review the error details.": "The operation failed. Review the error details.",
}

_ZH = {
    "Offline evidence inspection and reporting tool": "离线证据巡检与报告工具",
    "Create a manifest for a reviewed native evidence directory": "为已复核的原生证据目录创建清单",
    "Validate and import a bundle into a new case directory": "校验证据包并导入新的案例目录",
    "Analyze one validated, already imported bundle": "分析已校验并导入的证据包",
    "Use a validated listener knowledge JSON file (defaults to the bundled example).": "使用已校验的监听端口知识库 JSON 文件（默认使用随附示例）。",
    "Assert Ollama cloud features were disabled before use": "确认使用前已关闭 Ollama cloud 功能",
    "Run authorized current-Windows collectors and render the same unified reports": "运行已授权的当前 Windows 采集器并生成统一报告",
    "Compare two analysis.json files": "比较两个 analysis.json 文件",
    "Write a redacted summary for Codex conversation analysis": "生成供 Codex 对话分析使用的脱敏摘要",
    "Export selected allow-listed config facts after redaction": "脱敏后导出白名单内的配置事实",
    "Capture one explicitly authorized POSIX target using pinned OpenSSH host keys": "使用固定的 OpenSSH 主机密钥采集一台已明确授权的 POSIX 目标",
    "Explicitly authorize using the already running SSH agent only; private-key files are never read": "仅明确授权使用当前运行的 SSH agent；不会读取私钥文件",
    "Capture one explicitly authorized Windows target through HTTPS WinRM": "通过 HTTPS WinRM 采集一台已明确授权的 Windows 目标",
    "Environment variable name containing the WinRM username": "包含 WinRM 用户名的环境变量名称",
    "Environment variable name containing the WinRM password": "包含 WinRM 密码的环境变量名称",
    "Import bastion/SecureCRT paste block produced by platforms/posix_paste_export.sh": "导入由 platforms/posix_paste_export.sh 生成的堡垒机/SecureCRT 粘贴块",
    "Text file containing the full BEGIN/END paste block": "包含完整 BEGIN/END 粘贴块的文本文件",
    "Continue to analyze after import": "导入后继续分析",
    "One-shot authorized local capture→seal→import→analyze (POSIX or Windows)": "一次性执行已授权的本机采集、封装、导入和分析（POSIX 或 Windows）",
    "Report output directory": "报告输出目录",
    "Raw normalized data directory": "归一化原始数据目录",
    "Report files were created.": "报告文件已生成。",
    "The analysis is incomplete; review its evidence gaps.": "分析未完整，请检查证据缺口。",
    "Local AI was not requested; no AI request was sent.": "未请求本地 AI；没有发送 AI 请求。",
    "The selected language preference was ignored; using Chinese.": "已忽略保存的语言偏好，当前使用简体中文。",
    "Report": "报告",
    "Raw data": "原始数据",
    "Execution log": "执行日志",
    "Windows local inspection tool": "Windows 本地巡检工具",
    "Python 3.10 or later was not found. Install Python or run with an available interpreter.": "未找到 Python 3.10 或更高版本。请安装 Python，或使用已有解释器运行。",
    "See logs/execution if a previous run created logs.": "如之前运行生成过日志，请查看 logs/execution。",
    "Select the report and human message language": "选择报告和人类可读提示的语言",
    "The operation failed. Review the error details.": "操作失败，请查看错误详情。",
    "JSON containing exactly: os_family, product, version, architecture, use_case, scope": "JSON 文件，字段必须严格为：os_family、product、version、architecture、use_case、scope",
    "JSON containing exactly: started_at, finished_at, timezone, privilege, collector_version, command_catalog": "JSON 文件，字段必须严格为：started_at、finished_at、timezone、privilege、collector_version、command_catalog",
    "Show program version and exit": "显示程序版本并退出",
    "Show this help message and exit": "显示此帮助信息并退出",
    "Argument error": "参数错误",
    "Invalid command-line arguments.": "命令行参数无效。请检查参数并查看帮助。",
    "Invalid choice": "无效选项值",
    "Available choices": "可选值",
    "Required arguments": "以下参数为必填项",
    "Unrecognized arguments": "无法识别的参数",
    "Expected one argument": "缺少参数值",
    "Invalid value type": "参数值类型无效",
    "Untranslated diagnostic": "未完整翻译的参数诊断（原始信息）",
}


def cli_text(text: str, language: str | None = None) -> str:
    locale = normalize_language(language)
    table = _EN if locale == "en-US" else _ZH
    return table.get(text, text)


class LocalizedArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with localized framework-owned labels and errors."""

    _default_language = "zh-CN"

    def __init__(self, *args, language: str | None = None, **kwargs):
        self.language = normalize_language(language or self._default_language)
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)
        self.add_argument("-h", "--help", action="help",
                          help=cli_text("Show this help message and exit", self.language))

    def format_usage(self) -> str:
        output = super().format_usage()
        if self.language == "zh-CN":
            output = output.replace("usage:", "用法：", 1)
        return output

    def format_help(self) -> str:
        output = super().format_help()
        if self.language == "zh-CN":
            for source, target in (
                ("usage:", "用法："),
                ("positional arguments:", "位置参数："),
                ("options:", "选项："),
                ("optional arguments:", "可选参数："),
            ):
                output = output.replace(source, target)
        return output

    def error(self, message: str) -> None:
        if self.language == "zh-CN":
            message = self._translate_error(message)
        self.print_usage(sys.stderr)
        separator = "：" if self.language == "zh-CN" else ": "
        self.exit(2, f"{cli_text('Argument error', self.language)}{separator}{message}\n")

    @staticmethod
    def _translate_error(message: str) -> str:
        expected = re.fullmatch(r"argument ([^:]+): expected one argument", message)
        if expected:
            return f"参数 {expected.group(1)}：{cli_text('Expected one argument')}"
        invalid_type = re.fullmatch(r"argument ([^:]+): invalid ([^ ]+) value: (.+)", message)
        if invalid_type:
            return (f"参数 {invalid_type.group(1)}：{cli_text('Invalid value type')} "
                    f"({invalid_type.group(2)})：{invalid_type.group(3)}")
        invalid = re.fullmatch(r"(?:argument [^:]+: )?invalid choice: (.+?) \(choose from (.+)\)", message)
        if invalid:
            return f"{cli_text('Invalid choice')}: {invalid.group(1)}；{cli_text('Available choices')}：{invalid.group(2)}"
        required = re.fullmatch(r"the following arguments are required: (.+)", message)
        if required:
            return f"{cli_text('Required arguments')}：{required.group(1)}"
        unrecognized = re.fullmatch(r"unrecognized arguments: (.+)", message)
        if unrecognized:
            return f"{cli_text('Unrecognized arguments')}：{unrecognized.group(1)}"
        return f"{cli_text('Untranslated diagnostic')}：{message}"


def argument_parser_class(language: str | None = None):
    locale = normalize_language(language)

    class Parser(LocalizedArgumentParser):
        _default_language = locale

    return Parser
