"""Controlled translations for application-authored desktop error diagnostics."""
from __future__ import annotations

import re

from i18n import normalize_language, tr


_EXACT_EN = {
    "便携目录缺少命令行程序 pc-inspection-toolkit.exe":
        "The portable folder is missing the command-line program pc-inspection-toolkit.exe.",
    "WMI 本地时间证据缺少有效 UTC 偏移":
        "The WMI local-time evidence does not contain a valid UTC offset.",
    "采集时间输出格式不受支持": "The collection-time output format is unsupported.",
    "请选择列表中的实际用途。": "Choose an actual use case from the list.",
    "证据未含可信格式的真实采集起止时间；不会使用文件时间代替，请用新版固定采集器重新采集。":
        "The evidence does not contain trusted, well-formed collection start and end times. File timestamps will not be substituted; recollect with the current fixed collector.",
    "采集时间缺少明确时区，证据不能被封装为可比较时间。":
        "The collection time has no explicit timezone, so the evidence cannot be sealed with a comparable timestamp.",
    "采集结束时间早于开始时间，证据元数据冲突，不能封装。":
        "The collection end time precedes the start time. The evidence metadata conflicts and cannot be sealed.",
    "采集器版本或固定命令目录元数据缺失/无效，不能封装。":
        "Collector version or fixed command-catalog metadata is missing or invalid; the evidence cannot be sealed.",
    "不能从固定证据识别 Windows/Linux/macOS；不会猜测目标平台。":
        "The target platform cannot be identified as Windows, Linux, or macOS from the fixed evidence. The platform will not be guessed.",
    "采集命令目录与已识别的平台采集器不匹配或未受支持。":
        "The collector command catalog does not match the identified platform or is unsupported.",
    "固定原生采集目录不得包含子目录。":
        "The fixed native collector folder must not contain subdirectories.",
    "analysis.json 不存在。": "analysis.json does not exist.",
    "analysis.json 超出 20 MiB 安全读取上限。":
        "analysis.json exceeds the 20 MiB safe-read limit.",
    "分析结果结构不正确。": "The analysis result has an invalid structure.",
    "所选证据目录不存在。": "The selected evidence folder does not exist.",
    "所选粘贴导出文件不存在。": "The selected paste-export file does not exist.",
    "现有 paste-import 命令未返回已导入案例路径。":
        "The existing paste-import command did not return the imported case path.",
    "子进程输出管道未能在期限内关闭；请检查本次操作是否已停止。":
        "The child-process output pipe did not close before the deadline. Check whether this operation has stopped.",
    "请求停止后，无法确认所有本程序启动的子进程均已退出。":
        "After cancellation was requested, the app could not confirm that all child processes it started had exited.",
    "用户取消": "The user cancelled the operation.",
    "操作超过时间上限": "The operation exceeded its time limit.",
}

_TEMPLATES = (
    (
        re.compile(r"^采集元数据字段重复：(.*)$"),
        "Duplicate collection metadata field: {suffix}",
    ),
    (
        re.compile(r"^固定采集命令目录与输出文件不一致：(.*)$"),
        "The fixed collector command catalog does not match the output files: {suffix}",
    ),
    (
        re.compile(r"^原生采集目录含固定目录之外的文件，不会封装：(.*)$"),
        "The native collector folder contains files outside the fixed allow-list and will not be sealed: {suffix}",
    ),
    (
        re.compile(r"^固定证据包含互相冲突的重复事实：(.*)$"),
        "The fixed evidence contains conflicting duplicate facts: {suffix}",
    ),
)

_EXCEPTION_PREFIX = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*): (.*)$", re.DOTALL)


def display_desktop_error(message: str, language: str = "zh-CN") -> str:
    """Translate known application diagnostics while preserving embedded data.

    Unknown diagnostics are never rewritten. English callers can distinguish
    retained source diagnostics by the explicit ``Original diagnostic:`` prefix.
    """
    locale = normalize_language(language)
    if not isinstance(message, str):
        message = str(message)

    exception_type = ""
    diagnostic = message
    match = _EXCEPTION_PREFIX.fullmatch(message)
    if match:
        exception_type, diagnostic = match.groups()

    translated = _EXACT_EN.get(diagnostic)
    if translated is None:
        for pattern, template in _TEMPLATES:
            match = pattern.fullmatch(diagnostic)
            if match:
                translated = template.format(suffix=match.group(1))
                break
    if translated is None and locale == "en-US":
        exact_translation = tr(diagnostic, locale)
        if exact_translation != diagnostic:
            translated = exact_translation

    if translated is not None:
        rendered = f"{exception_type}: {translated}" if exception_type else translated
        return message if locale == "zh-CN" else rendered

    if locale == "zh-CN":
        return message
    if message.startswith("Original diagnostic:"):
        return message
    return f"Original diagnostic: {message}"
