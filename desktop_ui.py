from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

from desktop_app import (
    MAX_CHILD_OUTPUT, MAX_CHILD_SECONDS, NATIVE_RAW_ALLOWED_NAMES, USE_CASES,
    _is_reparse, _read_process_output, application_root, cli_command, derive_native_metadata,
)
from evidence.bundle import BundleError, import_bundle, stage_native_evidence, write_manifest


COLORS = {
    "workspace": "#F4F6FA", "sidebar": "#EEF2F7", "white": "#FFFFFF",
    "border": "#DCE3ED", "text": "#26364E", "muted": "#74849B",
    "blue": "#2867C7", "blue_hover": "#1F57AD", "blue_soft": "#E5EEFC",
    "green": "#218F79", "green_soft": "#E6F4EF", "amber": "#B87818",
    "amber_soft": "#FFF3DE", "red": "#C34343", "red_soft": "#FBEAEA",
    "slate_soft": "#EDF1F5",
}
SPACING = {"page_x": 30, "page_y": 22, "card": 20, "section": 16, "field": 10, "small": 6}
FONT_SIZE = {"title": 21, "section": 12, "body": 10, "small": 9, "brand": 11, "hero": 17}
CONTROL = {"button_pad_x": 14, "button_pad_y": 8, "field_pad_x": 8, "field_pad_y": 6}
MAX_ANALYSIS_BYTES = 20 * 1024 * 1024
PAGE_TITLES = {
    "overview": ("巡检工作台", "从本机只读采集或导入现场证据开始"),
    "local": ("本机只读巡检", "仅检查当前 Windows 设备；需要你明确确认授权"),
    "import": ("现场证据导入", "校验原生采集目录、EvidenceBundle 或 SecureCRT / 4A 粘贴证据"),
    "report": ("分析与报告", "按真实 analysis.json 展示确定性发现、证据缺口与独立的 AI 辅助建议"),
    "review": ("复查与交付", "导出脱敏交付文件，或按现有规则比较整改前后分析"),
}
NAV_ITEMS = (
    ("overview", "⌂", "概览"),
    ("local", "▣", "本机巡检"),
    ("import", "▱", "证据导入"),
    ("report", "☷", "分析与报告"),
    ("review", "⇄", "复查与交付"),
)


class InspectionDesktop:
    """Responsive Tk desktop UI backed by the existing CLI and evidence contracts."""

    def __init__(self, root: Any) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk, self.root = tk, ttk, root
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.cancel_event = threading.Event()
        self.busy = False
        self.last_analysis: Path | None = None
        self.last_report_dir: Path | None = None
        self.analysis_value: dict[str, Any] | None = None
        self.analysis_metadata: dict[str, Any] = {}
        self.log_widgets: list[Any] = []
        self.progress_bars: list[Any] = []
        self.pages: dict[str, dict[str, Any]] = {}
        self.nav_buttons: dict[str, Any] = {}
        self._responsive_pairs: list[dict[str, Any]] = []
        app_root = application_root()
        self.cases_var = tk.StringVar(value=str(app_root / "data" / "raw" / "cases"))
        self.reports_var = tk.StringVar(value=str(app_root / "reports" / "output"))
        self.project_var = tk.StringVar()
        self.asset_var = tk.StringVar()
        self.use_case_var = tk.StringVar(value="未知/其他")
        self.local_consent_var = tk.BooleanVar(value=False)
        self.source_var = tk.StringVar(value="bundle")
        self.bundle_var = tk.StringVar()
        self.ai_enabled_var = tk.BooleanVar(value=False)
        self.ai_endpoint_var = tk.StringVar()
        self.ai_model_var = tk.StringVar()
        self.ai_ack_var = tk.BooleanVar(value=False)
        self.ai_timeout_var = tk.StringVar(value="180")
        self.status_var = tk.StringVar(value="就绪。未检查不代表安全；工具不会自动提权或修改目标配置。")
        self.activity_var = tk.StringVar(value="未开始")
        self.analysis_status_var = tk.StringVar(value="未加载")
        self.analysis_record_var = tk.StringVar(value="请选择已有 analysis.json，或完成一次分析。")
        self.finding_count_var = tk.StringVar(value="—")
        self.gap_count_var = tk.StringVar(value="—")
        self.compare_result_var = tk.StringVar(value="本会话尚无比较结果。")
        self._current_filter = "all"
        self._finding_by_iid: dict[str, dict[str, Any]] = {}
        self.compare_path: Path | None = None
        self._build()
        self.root.after(100, self._poll)

    def _font_family(self) -> str:
        import tkinter.font as tkfont
        try:
            available = set(tkfont.families(self.root))
        except Exception:
            available = set()
        for name in ("Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", "Arial"):
            if name in available:
                return name
        return "TkDefaultFont"

    def _setup_theme(self) -> None:
        import tkinter.font as tkfont
        tk, ttk = self.tk, self.ttk
        self.font_family = self._font_family()
        style = ttk.Style(self.root)
        try:
            if "clam" in style.theme_names():
                style.theme_use("clam")
        except tk.TclError:
            pass
        self.root.configure(background=COLORS["workspace"])
        default_font = (self.font_family, FONT_SIZE["body"])
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
            try:
                tkfont.nametofont(name).configure(family=self.font_family, size=FONT_SIZE["body"])
            except Exception:
                pass
        style.configure("TFrame", background=COLORS["workspace"])
        style.configure("Workspace.TFrame", background=COLORS["workspace"])
        style.configure("Topbar.TFrame", background=COLORS["white"])
        style.configure("Sidebar.TFrame", background=COLORS["sidebar"])
        style.configure("Card.TFrame", background=COLORS["white"], bordercolor=COLORS["border"],
                        lightcolor=COLORS["border"], darkcolor=COLORS["border"], borderwidth=1, relief="solid")
        style.configure("CardInner.TFrame", background=COLORS["white"], borderwidth=0, relief="flat", padding=0)
        style.configure("Page.TLabel", background=COLORS["workspace"], foreground=COLORS["text"], font=default_font)
        style.configure("PageTitle.TLabel", background=COLORS["workspace"], foreground=COLORS["text"],
                        font=(self.font_family, FONT_SIZE["title"], "bold"))
        style.configure("PageSubtitle.TLabel", background=COLORS["workspace"], foreground=COLORS["muted"],
                        font=(self.font_family, FONT_SIZE["body"]))
        style.configure("Card.TLabel", background=COLORS["white"], foreground=COLORS["text"], font=default_font)
        style.configure("CardTitle.TLabel", background=COLORS["white"], foreground=COLORS["text"],
                        font=(self.font_family, FONT_SIZE["section"], "bold"))
        style.configure("CardMuted.TLabel", background=COLORS["white"], foreground=COLORS["muted"],
                        font=(self.font_family, FONT_SIZE["small"]))
        style.configure("CardSmall.TLabel", background=COLORS["white"], foreground=COLORS["muted"],
                        font=(self.font_family, FONT_SIZE["body"]))
        style.configure("SidebarMuted.TLabel", background=COLORS["sidebar"], foreground=COLORS["muted"],
                        font=(self.font_family, FONT_SIZE["small"]))
        style.configure("HeroTitle.TLabel", background=COLORS["white"], foreground=COLORS["text"],
                        font=(self.font_family, FONT_SIZE["hero"], "bold"))
        style.configure("Brand.TLabel", background=COLORS["white"], foreground=COLORS["text"],
                        font=(self.font_family, FONT_SIZE["brand"], "bold"))
        style.configure("FieldLabel.TLabel", background=COLORS["white"], foreground=COLORS["muted"],
                        font=(self.font_family, FONT_SIZE["small"], "bold"))
        for name, background, foreground in (
            ("StatusOk.TLabel", COLORS["green_soft"], COLORS["green"]),
            ("StatusPartial.TLabel", COLORS["amber_soft"], COLORS["amber"]),
            ("StatusFailed.TLabel", COLORS["red_soft"], COLORS["red"]),
            ("StatusEmpty.TLabel", COLORS["slate_soft"], COLORS["muted"]),
        ):
            style.configure(name, background=background, foreground=foreground,
                            font=(self.font_family, FONT_SIZE["small"], "bold"), padding=(10, 5))
        style.configure("Nav.TButton", background=COLORS["sidebar"], foreground=COLORS["text"],
                        font=default_font, anchor="w", padding=(12, 10), borderwidth=0)
        style.map("Nav.TButton", background=[("active", "#E4EAF3")], foreground=[("active", COLORS["blue"])])
        style.configure("NavActive.TButton", background=COLORS["blue_soft"], foreground=COLORS["blue"],
                        font=(self.font_family, FONT_SIZE["body"], "bold"), anchor="w", padding=(12, 10), borderwidth=0)
        style.map("NavActive.TButton", background=[("active", COLORS["blue_soft"])])
        style.configure("Primary.TButton", background=COLORS["blue"], foreground=COLORS["white"],
                        font=(self.font_family, FONT_SIZE["body"], "bold"),
                        padding=(CONTROL["button_pad_x"], CONTROL["button_pad_y"]), borderwidth=0)
        style.map("Primary.TButton", background=[("disabled", "#B9C7DA"), ("pressed", COLORS["blue_hover"]),
                                                  ("active", COLORS["blue_hover"])],
                  foreground=[("disabled", "#F6F8FB")])
        style.configure("Secondary.TButton", background=COLORS["white"], foreground=COLORS["text"],
                        font=(self.font_family, FONT_SIZE["body"], "bold"),
                        padding=(CONTROL["button_pad_x"], CONTROL["button_pad_y"]),
                        bordercolor=COLORS["border"], borderwidth=1, relief="solid")
        style.map("Secondary.TButton", background=[("disabled", "#F4F6F8"), ("active", "#F6F8FC")],
                  foreground=[("disabled", "#A7B2C0")])
        style.configure("Link.TButton", background=COLORS["white"], foreground=COLORS["blue"],
                        font=(self.font_family, FONT_SIZE["body"], "bold"), padding=(6, 5), borderwidth=0)
        style.map("Link.TButton", foreground=[("active", COLORS["blue_hover"])])
        style.configure("Filter.TButton", background=COLORS["white"], foreground=COLORS["muted"],
                        font=(self.font_family, FONT_SIZE["small"]), padding=(8, 5), borderwidth=0)
        style.configure("FilterActive.TButton", background=COLORS["blue_soft"], foreground=COLORS["blue"],
                        font=(self.font_family, FONT_SIZE["small"], "bold"), padding=(8, 5), borderwidth=0)
        style.configure("Field.TEntry", fieldbackground=COLORS["white"], foreground=COLORS["text"],
                        insertcolor=COLORS["text"], padding=(CONTROL["field_pad_x"], CONTROL["field_pad_y"]),
                        bordercolor=COLORS["border"], lightcolor=COLORS["border"], darkcolor=COLORS["border"])
        style.configure("Field.TCombobox", fieldbackground=COLORS["white"], foreground=COLORS["text"],
                        padding=(CONTROL["field_pad_x"], CONTROL["field_pad_y"]))
        style.configure("TCheckbutton", background=COLORS["white"], foreground=COLORS["text"], font=default_font)
        style.map("TCheckbutton", background=[("active", COLORS["white"])])
        style.configure("TRadiobutton", background=COLORS["white"], foreground=COLORS["text"], font=default_font)
        style.map("TRadiobutton", background=[("active", COLORS["white"])])
        style.configure("Source.TRadiobutton", background=COLORS["white"], foreground=COLORS["text"],
                        font=default_font, padding=(10, 9), anchor="w")
        style.map("Source.TRadiobutton",
                  background=[("selected", COLORS["blue_soft"]), ("active", COLORS["white"])],
                  foreground=[("selected", COLORS["blue"])])
        style.configure("EmptyState.TLabel", background=COLORS["white"], foreground=COLORS["muted"],
                        font=(self.font_family, FONT_SIZE["body"]), padding=(20, 28))
        style.configure("TSeparator", background=COLORS["border"])
        style.configure("Treeview", background=COLORS["white"], fieldbackground=COLORS["white"],
                        foreground=COLORS["text"], rowheight=30, font=default_font,
                        bordercolor=COLORS["border"], borderwidth=1)
        style.configure("Treeview.Heading", background="#F6F8FB", foreground=COLORS["muted"],
                        font=(self.font_family, FONT_SIZE["small"], "bold"), padding=(8, 8))
        style.map("Treeview", background=[("selected", COLORS["blue_soft"])],
                  foreground=[("selected", COLORS["text"])])
        style.configure("TScrollbar", background="#E6EBF2", troughcolor=COLORS["workspace"],
                        bordercolor=COLORS["workspace"])

    def _build(self) -> None:
        tk, ttk = self.tk, self.ttk
        self._setup_theme()
        self.root.title("PC Inspection Toolkit · 现场巡检与证据分析")
        self.root.geometry("1240x840")
        self.root.minsize(980, 660)
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=0)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=0)

        topbar = ttk.Frame(self.root, style="Topbar.TFrame", padding=(20, 10))
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.columnconfigure(4, weight=1)
        mark = tk.Label(topbar, text="P", width=2, background=COLORS["blue"], foreground=COLORS["white"],
                        font=(self.font_family, 11, "bold"), padx=4, pady=3)
        mark.grid(row=0, column=0, sticky="w")
        ttk.Label(topbar, text="PC Inspection Toolkit", style="Brand.TLabel").grid(row=0, column=1, sticky="w", padx=(10, 14))
        ttk.Separator(topbar, orient="vertical").grid(row=0, column=2, sticky="ns", padx=(0, 12))
        ttk.Label(topbar, text="现场巡检与证据分析", style="CardMuted.TLabel").grid(row=0, column=3, sticky="w")
        ttk.Label(topbar, text="Windows 桌面工具", style="CardMuted.TLabel").grid(row=0, column=4, sticky="e", padx=(16, 0))

        body = ttk.Frame(self.root, style="Workspace.TFrame")
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)
        sidebar = ttk.Frame(body, style="Sidebar.TFrame", padding=(12, 18))
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.configure(width=218)
        sidebar.grid_propagate(False)
        ttk.Label(sidebar, text="工作空间", style="SidebarMuted.TLabel").pack(anchor="w", padx=10, pady=(4, 12))
        for key, icon, title in NAV_ITEMS:
            button = ttk.Button(sidebar, text=f"  {icon}    {title}", style="Nav.TButton",
                                command=lambda selected=key: self._navigate(selected))
            button.pack(fill="x", pady=2)
            self.nav_buttons[key] = button
        ttk.Separator(sidebar).pack(fill="x", pady=(18, 14))
        ttk.Label(sidebar, text="安全原则", style="SidebarMuted.TLabel").pack(anchor="w", padx=10, pady=(0, 8))
        for line in ("只读操作 · 不修改目标", "不会自动提权或执行修复", "未检查不代表安全"):
            ttk.Label(sidebar, text=line, style="SidebarMuted.TLabel", wraplength=182).pack(anchor="w", padx=10, pady=4)
        ttk.Label(sidebar, text="V3 桌面巡检", style="SidebarMuted.TLabel").pack(side="bottom", anchor="w", padx=10, pady=(12, 2))

        workspace = ttk.Frame(body, style="Workspace.TFrame")
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.rowconfigure(0, weight=1)
        workspace.columnconfigure(0, weight=1)
        self.page_host = ttk.Frame(workspace, style="Workspace.TFrame")
        self.page_host.grid(row=0, column=0, sticky="nsew")
        self.page_host.rowconfigure(0, weight=1)
        self.page_host.columnconfigure(0, weight=1)

        footer = ttk.Frame(self.root, style="Topbar.TFrame", padding=(18, 8))
        footer.grid(row=2, column=0, sticky="ew")
        footer.columnconfigure(1, weight=1)
        self.footer_progress = ttk.Progressbar(footer, mode="indeterminate", length=90)
        self.footer_progress.grid(row=0, column=0, sticky="w", padx=(0, 12))
        self.footer_progress.grid_remove()
        ttk.Label(footer, textvariable=self.status_var, style="CardMuted.TLabel", anchor="w").grid(row=0, column=1, sticky="ew")
        self.cancel_button = ttk.Button(footer, text="取消当前操作", style="Secondary.TButton",
                                        command=self._cancel, state="disabled", width=14)
        self.cancel_button.grid(row=0, column=2, sticky="e", padx=(12, 0))

        self._build_overview()
        self._build_local()
        self._build_import()
        self._build_report()
        self._build_review()
        self._register_page_wheel_bindings()
        self._navigate("overview")

    def _new_page(self, key: str) -> Any:
        tk, ttk = self.tk, self.ttk
        page = ttk.Frame(self.page_host, style="Workspace.TFrame")
        page.grid(row=0, column=0, sticky="nsew")
        page.rowconfigure(1, weight=1)
        page.columnconfigure(0, weight=1)
        page.columnconfigure(1, weight=0)
        title, subtitle = PAGE_TITLES[key]
        header_bottom = 6 if key == "review" else 10
        content_top = 4 if key == "review" else 8
        header = ttk.Frame(page, style="Workspace.TFrame",
                           padding=(SPACING["page_x"], 18, SPACING["page_x"], header_bottom))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=title, style="PageTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text=subtitle, style="PageSubtitle.TLabel", wraplength=780).grid(
            row=1, column=0, sticky="w", pady=(4, 0))
        canvas = tk.Canvas(page, background=COLORS["workspace"], highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(page, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=1, column=0, sticky="nsew")
        content = ttk.Frame(canvas, style="Workspace.TFrame",
                            padding=(SPACING["page_x"], content_top, SPACING["page_x"], SPACING["page_y"]))
        window = canvas.create_window((0, 0), window=content, anchor="nw")
        content.columnconfigure(0, weight=1)
        page_state = {
            "frame": page,
            "header": header,
            "content": content,
            "canvas": canvas,
            "scrollbar": scrollbar,
            "window": window,
            "scroll_update_pending": False,
            "wheel_tag": None,
            "wheel_delta": 0,
        }
        self.pages[key] = page_state
        content.bind("<Configure>", lambda _event, p=page_state: self._schedule_page_scroll_update(p))
        canvas.bind("<Configure>", lambda event, p=page_state: self._resize_page_content(event, p))
        return content

    def _schedule_page_scroll_update(self, page: dict[str, Any]) -> None:
        if page["scroll_update_pending"]:
            return
        page["scroll_update_pending"] = True
        try:
            page["canvas"].after_idle(lambda target=page: self._update_page_scrollbar(target))
        except self.tk.TclError:
            page["scroll_update_pending"] = False

    def _update_page_scrollbar(self, page: dict[str, Any]) -> None:
        page["scroll_update_pending"] = False
        canvas, scrollbar = page["canvas"], page["scrollbar"]
        try:
            bounds = canvas.bbox(page["window"])
            viewport_height = canvas.winfo_height()
            if bounds is None or viewport_height <= 1:
                return
            content_height = bounds[3] - bounds[1]
            needs_scrollbar = content_height > viewport_height
            scrollbar_visible = scrollbar.winfo_manager() == "grid"
            if needs_scrollbar:
                canvas.configure(scrollregion=bounds)
                if not scrollbar_visible:
                    scrollbar.grid(row=1, column=1, sticky="ns")
            else:
                canvas.configure(scrollregion=(
                    bounds[0], bounds[1],
                    max(bounds[2], bounds[0] + canvas.winfo_width()),
                    bounds[1] + viewport_height,
                ))
                if scrollbar_visible:
                    scrollbar.grid_remove()
                canvas.yview_moveto(0)
        except self.tk.TclError:
            return

    def _resize_page_content(self, event: Any, page: dict[str, Any]) -> None:
        try:
            page["canvas"].itemconfigure(page["window"], width=max(1, event.width))
            self._schedule_page_scroll_update(page)
        except self.tk.TclError:
            return

    def _register_page_wheel_bindings(self) -> None:
        for key, page in self.pages.items():
            tag = f"PageScroll_{key}_{id(page['canvas'])}"
            page["wheel_tag"] = tag
            self.root.bind_class(tag, "<MouseWheel>",
                                 lambda event, target=page: self._handle_page_mousewheel(event, target))
            self.root.bind_class(tag, "<Button-4>",
                                 lambda event, target=page: self._handle_page_buttonwheel(event, target, -1))
            self.root.bind_class(tag, "<Button-5>",
                                 lambda event, target=page: self._handle_page_buttonwheel(event, target, 1))
            self._add_page_wheel_tag(page["header"], tag)
            self._add_page_wheel_tag(page["canvas"], tag)
            self._add_page_wheel_tag(page["content"], tag)

    def _add_page_wheel_tag(self, widget: Any, tag: str) -> None:
        if isinstance(widget, (self.tk.Scrollbar, self.ttk.Scrollbar)):
            return
        tags = widget.bindtags()
        if tag not in tags:
            widget.bindtags((tags[0], tag, *tags[1:]))
        for child in widget.winfo_children():
            self._add_page_wheel_tag(child, tag)

    def _handle_page_mousewheel(self, event: Any, page: dict[str, Any]) -> str:
        delta = int(getattr(event, "delta", 0))
        if not delta:
            return "break"
        accumulated = page["wheel_delta"] + delta
        steps = abs(accumulated) // 120
        page["wheel_delta"] = accumulated
        if not steps:
            return "break"
        sign = 1 if accumulated > 0 else -1
        page["wheel_delta"] -= sign * steps * 120
        direction = -sign
        return self._scroll_page_or_inner(event.widget, page, direction, steps)

    def _handle_page_buttonwheel(self, event: Any, page: dict[str, Any], direction: int) -> str:
        return self._scroll_page_or_inner(event.widget, page, direction, 1)

    def _scroll_page_or_inner(self, widget: Any, page: dict[str, Any], direction: int, steps: int) -> str:
        if self._scroll_inner_widget(widget, direction, steps):
            return "break"
        try:
            page["canvas"].yview_scroll(direction * steps, "units")
        except self.tk.TclError:
            return "break"
        return "break"

    def _scroll_inner_widget(self, widget: Any, direction: int, steps: int) -> bool:
        if not isinstance(widget, (self.tk.Text, self.tk.Listbox, self.ttk.Treeview)):
            return False
        try:
            first, last = widget.yview()
            can_scroll = first > 0.0001 if direction < 0 else last < 0.9999
            if can_scroll:
                widget.yview_scroll(direction * steps, "units")
                return True
        except (self.tk.TclError, AttributeError, TypeError):
            return False
        return False

    def _card(self, parent: Any, *, padding: int | None = None) -> Any:
        return self.ttk.Frame(parent, style="Card.TFrame",
                              padding=SPACING["card"] if padding is None else padding)

    def _card_header(self, parent: Any, title: str, subtitle: str = "") -> Any:
        ttk = self.ttk
        header = ttk.Frame(parent, style="CardInner.TFrame", padding=(0, 0, 0, SPACING["field"]))
        header.grid_columnconfigure(0, weight=1)
        ttk.Label(header, text=title, style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        if subtitle:
            ttk.Label(header, text=subtitle, style="CardMuted.TLabel", wraplength=680).grid(
                row=1, column=0, sticky="w", pady=(4, 0))
        return header

    def _primary(self, parent: Any, text: str, command: Callable[[], Any], *, width: int = 16) -> Any:
        return self.ttk.Button(parent, text=text, command=command, style="Primary.TButton", width=width)

    def _secondary(self, parent: Any, text: str, command: Callable[[], Any], *, width: int = 14) -> Any:
        return self.ttk.Button(parent, text=text, command=command, style="Secondary.TButton", width=width)

    def _entry(self, parent: Any, variable: Any, *, width: int | None = None) -> Any:
        return self.ttk.Entry(parent, textvariable=variable, style="Field.TEntry", width=width)

    def _field_label(self, parent: Any, text: str, row: int, col: int, *, colspan: int = 1) -> None:
        self.ttk.Label(parent, text=text, style="FieldLabel.TLabel").grid(
            row=row, column=col, columnspan=colspan, sticky="w", pady=(SPACING["field"], 4))

    def _text_area(self, parent: Any, *, row: int, height: int, background: str,
                   highlight: bool = False) -> Any:
        tk, ttk = self.tk, self.ttk
        widget = tk.Text(parent, height=height, wrap="word", state="disabled", background=background,
                         foreground=COLORS["text"], font=(self.font_family, FONT_SIZE["body"]),
                         relief="flat", borderwidth=0, padx=8, pady=8,
                         highlightthickness=1 if highlight else 0,
                         highlightbackground=COLORS["border"], highlightcolor=COLORS["blue"])
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=widget.yview)
        widget.configure(yscrollcommand=lambda first, last, bar=scrollbar:
                         self._sync_text_scrollbar(bar, first, last))
        widget.grid(row=row, column=0, sticky="nsew")
        scrollbar.grid(row=row, column=1, sticky="ns")
        scrollbar.grid_remove()
        return widget

    def _sync_text_scrollbar(self, scrollbar: Any, first: str, last: str) -> None:
        scrollbar.set(first, last)
        if float(first) <= 0 and float(last) >= 1:
            scrollbar.grid_remove()
        else:
            scrollbar.grid()

    def _register_pair(self, parent: Any, first: Any, second: Any, *, threshold: int = 840,
                       weights: tuple[int, int] = (2, 1), stretch_second: bool = True) -> None:
        parent.columnconfigure(0, weight=weights[0], uniform="responsive")
        parent.columnconfigure(1, weight=weights[1], uniform="responsive")
        first.grid(row=0, column=0, sticky="nsew", padx=(0, SPACING["section"]))
        second.grid(row=0, column=1, sticky="nsew" if stretch_second else "new")
        pair = {"parent": parent, "first": first, "second": second, "threshold": threshold,
                "weights": weights, "stretch_second": stretch_second, "stacked": False}
        self._responsive_pairs.append(pair)
        parent.bind("<Configure>", lambda event, p=pair: self._reflow_pair(event, p))

    def _reflow_pair(self, event: Any, pair: dict[str, Any]) -> None:
        stacked = event.width < pair["threshold"]
        if stacked == pair["stacked"]:
            return
        pair["stacked"] = stacked
        if stacked:
            pair["first"].grid_configure(row=0, column=0, padx=0, pady=(0, SPACING["section"]))
            pair["second"].grid_configure(row=1, column=0, padx=0, pady=0)
            pair["parent"].columnconfigure(1, weight=0, uniform="")
        else:
            pair["first"].grid_configure(row=0, column=0, padx=(0, SPACING["section"]), pady=0)
            pair["second"].grid_configure(row=0, column=1, padx=0, pady=0)
            pair["parent"].columnconfigure(1, weight=pair["weights"][1], uniform="responsive")

    def _build_overview(self) -> None:
        ttk, tk = self.ttk, self.tk
        content = self._new_page("overview")
        hero = self._card(content, padding=18)
        hero.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        hero.columnconfigure(0, weight=1)
        ttk.Label(hero, text="从一次安全、可追溯的巡检开始", style="HeroTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(hero, text="在本机执行只读巡检，或把现场采集的证据带回工具分析。",
                  style="CardSmall.TLabel", wraplength=640).grid(row=1, column=0, sticky="w", pady=(8, 3))
        ttk.Label(hero, text="所有操作均需人工发起；不会自动提权、修改配置或执行修复。",
                  style="CardMuted.TLabel").grid(row=2, column=0, sticky="w")
        ttk.Label(hero, text="离线优先 · Windows 维护端", style="StatusEmpty.TLabel").grid(row=0, column=1, sticky="ne")
        actions = ttk.Frame(hero, style="CardInner.TFrame")
        actions.grid(row=3, column=0, sticky="w", pady=(16, 0))
        self._primary(actions, "开始本机巡检", lambda: self._navigate("local")).pack(side="left", padx=(0, 10))
        self._secondary(actions, "导入现场证据", lambda: self._navigate("import")).pack(side="left")

        flow = self._card(content, padding=18)
        flow.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        flow.columnconfigure(0, weight=1)
        self._card_header(flow, "作业流程", "各步骤只显示本会话实际状态").grid(row=0, column=0, sticky="ew")
        steps = ttk.Frame(flow, style="CardInner.TFrame")
        steps.grid(row=1, column=0, sticky="ew")
        for col in range(4):
            steps.columnconfigure(col, weight=1, uniform="steps")
        self.workflow_vars = [
            ("1", "确认授权", tk.StringVar(value="等待确认")),
            ("2", "采集或导入", tk.StringVar(value="尚未开始")),
            ("3", "规则分析", tk.StringVar(value="等待证据")),
            ("4", "报告与复查", tk.StringVar(value="等待分析")),
        ]
        for col, (number, title, variable) in enumerate(self.workflow_vars):
            item = ttk.Frame(steps, style="CardInner.TFrame", padding=(8, 6))
            item.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 8, 0))
            tk.Label(item, text=number, width=2, background=COLORS["blue_soft"], foreground=COLORS["blue"],
                     font=(self.font_family, FONT_SIZE["body"], "bold"), padx=4, pady=4).pack(side="left", padx=(0, 9))
            text = ttk.Frame(item, style="CardInner.TFrame")
            text.pack(side="left", fill="x", expand=True)
            ttk.Label(text, text=title, style="Card.TLabel").pack(anchor="w")
            ttk.Label(text, textvariable=variable, style="CardMuted.TLabel").pack(anchor="w", pady=(2, 0))

        pair = ttk.Frame(content, style="Workspace.TFrame")
        pair.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        tasks = self._card(pair, padding=16)
        capabilities = self._card(pair, padding=16)
        self._register_pair(pair, tasks, capabilities, threshold=900)
        tasks.columnconfigure(1, weight=1)
        self._card_header(tasks, "选择任务").grid(row=0, column=0, columnspan=3, sticky="ew")
        self._task_row(tasks, 1, "PC", "检查本机 Windows 设备",
                       "填写设备代号、选择目录并确认授权后启动只读采集。",
                       "打开巡检", lambda: self._navigate("local"))
        tasks.grid_rowconfigure(2, minsize=12)
        self._task_row(tasks, 3, "IN", "分析外部设备证据",
                       "导入 EvidenceBundle、固定采集器目录或 SecureCRT / 4A 粘贴结果。",
                       "打开导入", lambda: self._navigate("import"))
        capabilities.columnconfigure(1, weight=1)
        self._card_header(capabilities, "能力与边界").grid(row=0, column=0, columnspan=2, sticky="ew")
        for index, text in enumerate((
            "规则 Finding 与证据缺口展示", "Markdown / HTML / CSV / JSON 报告",
            "Codex 脱敏交付与前后复查", "Ollama 建议为可选功能，默认关闭",
        ), start=1):
            ttk.Label(capabilities, text="●", foreground=COLORS["green"], background=COLORS["white"]).grid(
                row=index, column=0, sticky="w", pady=4)
            ttk.Label(capabilities, text=text, style="CardSmall.TLabel", wraplength=300).grid(
                row=index, column=1, sticky="w", padx=(8, 0), pady=4)
        ttk.Label(capabilities, textvariable=self.analysis_record_var, style="CardMuted.TLabel",
                  wraplength=320).grid(row=5, column=0, columnspan=2, sticky="ew", pady=(10, 0))

    def _task_row(self, parent: Any, row: int, mark: str, title: str, description: str,
                  button_text: str, command: Callable[[], Any]) -> None:
        ttk, tk = self.ttk, self.tk
        tk.Label(parent, text=mark, width=4, background=COLORS["blue_soft"], foreground=COLORS["blue"],
                 font=(self.font_family, FONT_SIZE["small"], "bold"), padx=5, pady=8).grid(row=row, column=0, sticky="nw")
        text = ttk.Frame(parent, style="CardInner.TFrame")
        text.grid(row=row, column=1, sticky="ew", padx=(12, 8))
        ttk.Label(text, text=title, style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(text, text=description, style="CardMuted.TLabel", wraplength=440).pack(anchor="w", pady=(4, 0))
        ttk.Button(parent, text=button_text + "  ›", command=command, style="Link.TButton").grid(
            row=row, column=2, sticky="e")

    def _build_local(self) -> None:
        ttk = self.ttk
        content = self._new_page("local")
        pair = ttk.Frame(content, style="Workspace.TFrame")
        pair.grid(row=0, column=0, sticky="ew", pady=(0, SPACING["section"]))
        config, scope = self._card(pair), self._card(pair)
        self._register_pair(pair, config, scope, threshold=860, stretch_second=False)
        config.columnconfigure(0, weight=1)
        config.columnconfigure(1, weight=1)
        self._card_header(config, "任务配置", "只填写脱敏标识；证据由本机只读采集产生。").grid(
            row=0, column=0, columnspan=2, sticky="ew")
        self._field_label(config, "项目代号", 1, 0)
        self._field_label(config, "设备代号", 1, 1)
        self._entry(config, self.project_var).grid(row=2, column=0, sticky="ew", padx=(0, 8))
        self._entry(config, self.asset_var).grid(row=2, column=1, sticky="ew", padx=(8, 0))
        self._field_label(config, "检查场景", 3, 0, colspan=2)
        self.use_case_combo = ttk.Combobox(config, textvariable=self.use_case_var, values=list(USE_CASES),
                                           state="readonly", style="Field.TCombobox")
        self.use_case_combo.grid(row=4, column=0, columnspan=2, sticky="ew")
        self._field_label(config, "案例保存目录", 5, 0, colspan=2)
        self._directory_row(config, 6, self.cases_var)
        self._field_label(config, "报告输出目录", 7, 0, colspan=2)
        self._directory_row(config, 8, self.reports_var)
        ttk.Checkbutton(config, text="我已获得当前设备及当前权限范围内的只读巡检授权",
                        variable=self.local_consent_var, command=self._update_workflow,
                        ).grid(row=9, column=0, columnspan=2, sticky="w", pady=(16, 0))

        scope.columnconfigure(1, weight=1)
        self._card_header(scope, "采集范围", "具体可用性以现场运行结果及权限为准。").grid(
            row=0, column=0, columnspan=2, sticky="ew")
        for row, label in enumerate((
            "系统、CPU、内存与磁盘摘要", "监听端口、防火墙与共享线索",
            "服务、启动项与计划任务", "账户摘要及安全软件状态", "权限差异与采集缺口记录",
        ), start=1):
            ttk.Label(scope, text="●", foreground=COLORS["green"], background=COLORS["white"]).grid(
                row=row, column=0, sticky="w", pady=7)
            ttk.Label(scope, text=label, style="CardSmall.TLabel", wraplength=280).grid(
                row=row, column=1, sticky="w", padx=(8, 0), pady=7)
        ttk.Label(scope, text="缺少权限不会自动申请管理员权限，也不会把未检查项目标记为安全。",
                  style="StatusPartial.TLabel", wraplength=280).grid(
            row=7, column=0, columnspan=2, sticky="ew", pady=(12, 0))

        run = self._card(content)
        run.grid(row=1, column=0, sticky="ew", pady=(0, SPACING["section"]))
        run.columnconfigure(0, weight=1)
        header = ttk.Frame(run, style="CardInner.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="执行进度与日志", style="CardTitle.TLabel").pack(side="left")
        self.local_state_badge = ttk.Label(header, textvariable=self.activity_var, style="StatusEmpty.TLabel")
        self.local_state_badge.pack(side="right")
        run.grid_rowconfigure(1, minsize=SPACING["section"])
        ttk.Label(run, text="启动后显示真实采集日志、退出状态和分析输出。",
                  style="CardMuted.TLabel", wraplength=820).grid(row=2, column=0, sticky="w")
        progress = ttk.Progressbar(run, mode="indeterminate")
        progress.grid(row=3, column=0, sticky="ew", pady=(12, 14))
        progress.grid_remove()
        self.progress_bars.append(progress)
        controls = ttk.Frame(run, style="CardInner.TFrame")
        controls.grid(row=4, column=0, sticky="w")
        self._primary(controls, "开始只读巡检", self._start_local).pack(side="left", padx=(0, 10))
        self._secondary(controls, "取消当前操作", self._cancel).pack(side="left")
        ttk.Label(controls, text="必须先确认授权；运行中可取消。",
                  style="CardMuted.TLabel").pack(side="left", padx=(12, 0))
        self._log_panel(content, row=2)
        ttk.Label(content, text="巡检只读运行。权限不足或证据缺失会记录为缺口，PARTIAL 不代表检查通过。",
                  style="PageSubtitle.TLabel", wraplength=850).grid(row=3, column=0, sticky="ew", pady=(2, 0))

    def _directory_row(self, parent: Any, row: int, variable: Any, *, show_suffix: bool = False) -> None:
        frame = self.ttk.Frame(parent, style="CardInner.TFrame")
        frame.grid(row=row, column=0, columnspan=2, sticky="ew")
        frame.columnconfigure(0, weight=1)
        entry = self._entry(frame, variable)
        entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        if show_suffix:
            entry.icursor("end")
            entry.xview_moveto(1.0)
        self._secondary(frame, "浏览…", lambda v=variable: self._pick_directory(v), width=8).grid(row=0, column=1)

    def _log_panel(self, parent: Any, *, row: int) -> None:
        tk, ttk = self.tk, self.ttk
        card = self._card(parent, padding=16)
        card.grid(row=row, column=0, sticky="ew", pady=(0, SPACING["section"]))
        card.columnconfigure(0, weight=1)
        self._card_header(card, "执行日志", "显示本会话中的 CLI 输出；不会写入 Git 或自动上传。").grid(
            row=0, column=0, sticky="ew")
        text = tk.Text(card, height=6, wrap="word", state="disabled", background="#FBFCFE",
                       foreground=COLORS["text"], font=(self.font_family, FONT_SIZE["small"]),
                       relief="flat", borderwidth=0, padx=8, pady=8, highlightthickness=1,
                       highlightbackground=COLORS["border"], highlightcolor=COLORS["blue"])
        text.grid(row=1, column=0, sticky="ew")
        self.log_widgets.append(text)

    def _build_import(self) -> None:
        ttk, tk = self.ttk, self.tk
        content = self._new_page("import")
        pair = ttk.Frame(content, style="Workspace.TFrame")
        pair.grid(row=0, column=0, sticky="ew", pady=(0, SPACING["section"]))
        source, options = self._card(pair), self._card(pair)
        self._register_pair(pair, source, options, threshold=860, stretch_second=False)
        source.columnconfigure(0, weight=1)
        source.columnconfigure(1, weight=1)
        self._card_header(source, "选择证据来源", "导入前执行白名单、元数据、完整性和目标绑定检查。").grid(
            row=0, column=0, columnspan=2, sticky="ew")
        radio_frame = ttk.Frame(source, style="CardInner.TFrame")
        radio_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        radio_frame.columnconfigure(0, weight=1, uniform="source")
        radio_frame.columnconfigure(1, weight=1, uniform="source")
        ttk.Radiobutton(radio_frame, text="U 盘目录 / EvidenceBundle", variable=self.source_var,
                        value="bundle", style="Source.TRadiobutton", command=self._update_source_controls
                        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Radiobutton(radio_frame, text="SecureCRT / 4A 粘贴文件", variable=self.source_var,
                        value="paste", style="Source.TRadiobutton", command=self._update_source_controls
                        ).grid(row=0, column=1, sticky="ew", padx=(6, 0))
        self.source_hint_var = tk.StringVar(value="")
        ttk.Label(source, textvariable=self.source_hint_var, style="CardMuted.TLabel",
                  wraplength=560).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._field_label(source, "证据目录或粘贴文件", 3, 0, colspan=2)
        path_row = ttk.Frame(source, style="CardInner.TFrame")
        path_row.grid(row=4, column=0, columnspan=2, sticky="ew")
        path_row.columnconfigure(0, weight=1)
        self._entry(path_row, self.bundle_var).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.source_browse_button = self._secondary(path_row, "选择目录…", self._pick_source, width=10)
        self.source_browse_button.grid(row=0, column=1)
        self._field_label(source, "项目代号", 5, 0)
        self._field_label(source, "设备代号", 5, 1)
        self._entry(source, self.project_var).grid(row=6, column=0, sticky="ew", padx=(0, 8))
        self._entry(source, self.asset_var).grid(row=6, column=1, sticky="ew", padx=(8, 0))
        self._field_label(source, "用途（原生目录及粘贴证据必填）", 7, 0, colspan=2)
        ttk.Combobox(source, textvariable=self.use_case_var, values=list(USE_CASES),
                     state="readonly", style="Field.TCombobox").grid(row=8, column=0, columnspan=2, sticky="ew")
        self._field_label(source, "案例保存目录", 9, 0, colspan=2)
        self._directory_row(source, 10, self.cases_var, show_suffix=True)
        self._field_label(source, "报告输出目录", 11, 0, colspan=2)
        self._directory_row(source, 12, self.reports_var, show_suffix=True)

        self._card_header(options, "导入保护规则").grid(row=0, column=0, columnspan=2, sticky="ew")
        options.columnconfigure(1, weight=1)
        rules_frame = ttk.Frame(options, style="CardInner.TFrame")
        rules_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        rules_frame.columnconfigure(1, weight=1)
        rule_labels = []
        for row, text in enumerate((
            "固定文件与目录白名单", "真实采集时间及版本检查",
            "完整性校验与目标绑定", "缺失或冲突时保留缺口，不伪装完整",
        )):
            ttk.Label(rules_frame, text="●", foreground=COLORS["green"],
                      background=COLORS["white"]).grid(
                row=row, column=0, sticky="nw", pady=7)
            label = ttk.Label(rules_frame, text=text, style="CardSmall.TLabel", wraplength=280,
                              anchor="w", justify="left")
            label.grid(row=row, column=1, sticky="ew", padx=(8, 0), pady=7)
            rule_labels.append(label)

        def resize_rule_text(event: Any) -> None:
            wraplength = max(160, event.width - 32)
            for label in rule_labels:
                if int(label.cget("wraplength")) != wraplength:
                    label.configure(wraplength=wraplength)

        rules_frame.bind("<Configure>", resize_rule_text, add="+")
        options.grid_rowconfigure(5, minsize=SPACING["section"])
        ai_header = ttk.Frame(options, style="CardInner.TFrame")
        ai_header.grid(row=6, column=0, columnspan=2, sticky="ew")
        ai_header.columnconfigure(0, weight=1)
        ttk.Label(ai_header, text="本地 AI 辅助建议", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        self.ai_state_badge = ttk.Label(ai_header, text="默认关闭", style="StatusEmpty.TLabel")
        self.ai_state_badge.grid(row=0, column=1, sticky="e")
        ttk.Label(options, text="只提交 Finding 白名单摘要；建议不会改写规则结论或分析状态。",
                  style="CardMuted.TLabel", wraplength=320).grid(
            row=7, column=0, columnspan=2, sticky="ew", pady=(8, 8))
        ttk.Checkbutton(options, text="启用 Ollama 辅助建议", variable=self.ai_enabled_var,
                        command=self._update_ai_badge).grid(row=8, column=0, sticky="w")
        self._secondary(options, "AI 设置…", self._ai_settings_dialog, width=12).grid(row=8, column=1, sticky="e")
        ttk.Label(options, text="启用前需确认 Ollama cloud 功能关闭；AI 请求仅在明确启用后发出。",
                  style="CardMuted.TLabel", wraplength=320).grid(
            row=9, column=0, columnspan=2, sticky="ew", pady=(12, 0))

        progress_card = self._card(content)
        progress_card.grid(row=1, column=0, sticky="ew", pady=(0, SPACING["section"]))
        progress_card.columnconfigure(0, weight=1)
        self._card_header(progress_card, "导入状态", "只有证据导入成功后才会启动分析。").grid(row=0, column=0, sticky="ew")
        ttk.Label(progress_card, textvariable=self.activity_var, style="CardSmall.TLabel",
                  wraplength=800).grid(row=1, column=0, sticky="w")
        progress = ttk.Progressbar(progress_card, mode="indeterminate")
        progress.grid(row=2, column=0, sticky="ew", pady=(12, 14))
        progress.grid_remove()
        self.progress_bars.append(progress)
        controls = ttk.Frame(progress_card, style="CardInner.TFrame")
        controls.grid(row=3, column=0, sticky="w")
        self._primary(controls, "校验并安全导入", self._start_import).pack(side="left", padx=(0, 10))
        self._secondary(controls, "打开分析结果", lambda: self._navigate("report")).pack(side="left")
        self._log_panel(content, row=2)
        ttk.Label(content, text="源目录不会被修改；导入包中的内容按不可信数据解析，不执行脚本。",
                  style="PageSubtitle.TLabel", wraplength=850).grid(row=3, column=0, sticky="ew")
        self._update_source_controls()
        self._update_ai_badge()

    def _build_report(self) -> None:
        tk, ttk = self.tk, self.ttk
        content = self._new_page("report")
        current = self._card(content)
        current.grid(row=0, column=0, sticky="ew", pady=(0, SPACING["section"]))
        current.columnconfigure(0, weight=1)
        current.columnconfigure(1, weight=0)
        title_row = ttk.Frame(current, style="CardInner.TFrame")
        title_row.grid(row=0, column=0, sticky="ew")
        title_row.columnconfigure(0, weight=1)
        ttk.Label(title_row, text="当前分析案例", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        self.analysis_status_badge = ttk.Label(title_row, textvariable=self.analysis_status_var, style="StatusEmpty.TLabel")
        self.analysis_status_badge.grid(row=0, column=1, sticky="e")
        ttk.Label(current, textvariable=self.analysis_record_var, style="CardSmall.TLabel",
                  wraplength=800).grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 0))
        toolbar = ttk.Frame(current, style="CardInner.TFrame")
        toolbar.grid(row=0, column=1, sticky="e", padx=(14, 0))
        self._secondary(toolbar, "选择 analysis.json…", self._load_analysis_dialog, width=18).pack(side="left", padx=(0, 8))
        self._secondary(toolbar, "打开报告目录", self._open_last_report, width=14).pack(side="left")

        summaries = ttk.Frame(content, style="Workspace.TFrame")
        summaries.grid(row=1, column=0, sticky="ew", pady=(0, SPACING["section"]))
        for col in range(3):
            summaries.columnconfigure(col, weight=1, uniform="summary")
        self._summary_card(summaries, 0, "分析状态", self.analysis_status_var)
        self._summary_card(summaries, 1, "规则 Finding", self.finding_count_var)
        self._summary_card(summaries, 2, "证据缺口 / 错误", self.gap_count_var)

        findings_card = self._card(content, padding=0)
        findings_card.grid(row=2, column=0, sticky="nsew", pady=(0, SPACING["section"]))
        findings_card.columnconfigure(0, weight=1)
        findings_card.rowconfigure(2, weight=1)
        head = ttk.Frame(findings_card, style="CardInner.TFrame", padding=(18, 14, 18, 10))
        head.grid(row=0, column=0, sticky="ew")
        head.columnconfigure(0, weight=1)
        ttk.Label(head, text="检查结果明细", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        filters = ttk.Frame(head, style="CardInner.TFrame")
        filters.grid(row=0, column=1, sticky="e")
        for col in range(3):
            filters.columnconfigure(col, uniform="filter")
        self.filter_buttons = {}
        for col, (key, text) in enumerate((("all", "全部"), ("review", "待复核"), ("gaps", "证据缺口"))):
            button = ttk.Button(filters, text=text, style="Filter.TButton", width=8,
                                command=lambda selected=key: self._set_filter(selected))
            button.grid(row=0, column=col, sticky="ew", padx=(4, 0))
            self.filter_buttons[key] = button
        table_frame = ttk.Frame(findings_card, style="CardInner.TFrame", padding=(12, 6, 12, 12))
        table_frame.grid(row=2, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.finding_tree = ttk.Treeview(table_frame, columns=("severity", "title", "evidence"),
                                         show="headings", height=7, selectmode="browse")
        self.finding_tree.heading("severity", text="级别")
        self.finding_tree.heading("title", text="检查项目 / Finding")
        self.finding_tree.heading("evidence", text="证据摘要")
        self.finding_tree.column("severity", width=100, minwidth=82, stretch=False, anchor="center")
        self.finding_tree.column("title", width=420, minwidth=220, stretch=True)
        self.finding_tree.column("evidence", width=320, minwidth=170, stretch=True)
        self.finding_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.finding_tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.finding_scrollbar = tree_scroll
        self.finding_tree.configure(yscrollcommand=tree_scroll.set)
        self.finding_tree.bind("<<TreeviewSelect>>", self._on_finding_selected)
        for tag, color in (("Critical", COLORS["red"]), ("High", COLORS["red"]),
                           ("Warning", COLORS["amber"]), ("Info", COLORS["muted"])):
            self.finding_tree.tag_configure(tag, foreground=color)
        self.finding_empty_var = tk.StringVar(value="尚未加载分析。请选择真实 analysis.json；不会使用示例数据填充。")
        self.finding_empty_label = ttk.Label(table_frame, textvariable=self.finding_empty_var,
                                             style="EmptyState.TLabel", anchor="center", justify="center",
                                             wraplength=620)
        self.finding_empty_label.grid(row=0, column=0, columnspan=2, sticky="nsew")
        self.finding_tree.grid_remove()
        self.finding_scrollbar.grid_remove()

        detail = self._card(content)
        detail.grid(row=3, column=0, sticky="ew", pady=(0, SPACING["section"]))
        detail.columnconfigure(0, weight=1)
        self._card_header(detail, "Finding 详情", "展示分析文件中的原始字段，不重新推导风险。").grid(row=0, column=0, sticky="ew")
        self.finding_detail = self._text_area(detail, row=1, height=5, background="#FBFCFE", highlight=True)

        gaps = self._card(content)
        gaps.grid(row=4, column=0, sticky="ew", pady=(0, SPACING["section"]))
        gaps.columnconfigure(0, weight=1)
        self._card_header(gaps, "证据缺口与状态说明").grid(row=0, column=0, sticky="ew")
        self.gaps_text = self._text_area(gaps, row=1, height=4, background=COLORS["white"])

        advisory = self._card(content)
        advisory.grid(row=5, column=0, sticky="ew", pady=(0, SPACING["section"]))
        advisory.columnconfigure(0, weight=1)
        self._card_header(advisory, "AI 辅助建议（非正式结论）",
                          "与确定性 Finding 分区显示；不会改变 Finding、风险等级或分析状态。").grid(row=0, column=0, sticky="ew")
        self.ai_text = self._text_area(advisory, row=1, height=4, background=COLORS["white"])

        outputs = self._card(content)
        outputs.grid(row=6, column=0, sticky="ew")
        outputs.columnconfigure(0, weight=1)
        self._card_header(outputs, "报告文件").grid(row=0, column=0, sticky="ew")
        self.report_path_var = tk.StringVar(value="尚无本会话报告。")
        ttk.Label(outputs, textvariable=self.report_path_var, style="CardMuted.TLabel",
                  wraplength=800).grid(row=1, column=0, sticky="w", pady=(0, 10))
        buttons = ttk.Frame(outputs, style="CardInner.TFrame")
        buttons.grid(row=2, column=0, sticky="w")
        for name, button_text in (("report.md", "Markdown"), ("report.html", "HTML"),
                                  ("findings.csv", "CSV"), ("analysis.json", "JSON")):
            self._secondary(buttons, button_text, lambda file=name: self._open_report_file(file), width=11).pack(
                side="left", padx=(0, 8))

    def _summary_card(self, parent: Any, column: int, title: str, value: Any) -> None:
        card = self._card(parent, padding=16)
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
        self.ttk.Label(card, text=title, style="CardMuted.TLabel").pack(anchor="w")
        self.ttk.Label(card, textvariable=value, style="CardTitle.TLabel", wraplength=220).pack(anchor="w", pady=(6, 0))

    def _build_review(self) -> None:
        ttk = self.ttk
        content = self._new_page("review")
        current = self._card(content)
        current.grid(row=0, column=0, sticky="ew", pady=(0, SPACING["section"]))
        current.columnconfigure(0, weight=1)
        self._card_header(current, "当前报告", "复查要求目标身份与规则摘要符合比较契约；证据不足不会标记为已解除。").grid(
            row=0, column=0, sticky="ew")
        ttk.Label(current, textvariable=self.report_path_var, style="CardSmall.TLabel",
                  wraplength=820).grid(row=1, column=0, sticky="w")
        self._secondary(current, "打开最近报告目录", self._open_last_report, width=18).grid(
            row=1, column=1, sticky="e", padx=(12, 0))

        pair = ttk.Frame(content, style="Workspace.TFrame")
        pair.grid(row=1, column=0, sticky="ew", pady=(0, SPACING["section"]))
        deliver, compare = self._card(pair), self._card(pair)
        self._register_pair(pair, deliver, compare, threshold=860, weights=(1, 1))
        deliver.columnconfigure(0, weight=1)
        self._card_header(deliver, "Codex 脱敏交付", "由正式 CLI 生成；请在分享前复核脱敏结果。").grid(
            row=0, column=0, sticky="ew")
        ttk.Label(deliver, text="选择一份 analysis.json，导出仅含白名单摘要的交付文件。",
                  style="CardSmall.TLabel", wraplength=400).grid(row=1, column=0, sticky="w")
        self._primary(deliver, "导出脱敏交付文件…", self._start_codex, width=20).grid(
            row=2, column=0, sticky="w", pady=(14, 0))

        compare.columnconfigure(0, weight=1)
        self._card_header(compare, "整改前后比较", "同一项目资产与规则身份下比较；变化的规则不会当作已解决。").grid(
            row=0, column=0, sticky="ew")
        ttk.Label(compare, textvariable=self.compare_result_var, style="CardSmall.TLabel",
                  wraplength=400).grid(row=1, column=0, sticky="w")
        self._primary(compare, "比较 analysis.json…", self._start_compare, width=20).grid(
            row=2, column=0, sticky="w", pady=(14, 0))
        self._secondary(content, "返回分析与报告", lambda: self._navigate("report")).grid(row=2, column=0, sticky="w")
        self._update_empty_report()

    def _navigate(self, key: str) -> None:
        if key not in self.pages:
            return
        page = self.pages[key]
        page["frame"].tkraise()
        for name, button in self.nav_buttons.items():
            button.configure(style="NavActive.TButton" if name == key else "Nav.TButton")
        self.active_page = key
        self.root.update_idletasks()
        self._schedule_page_scroll_update(page)
        self.root.update_idletasks()
        page["canvas"].yview_moveto(0)

    def _update_source_controls(self) -> None:
        if self.source_var.get() == "paste":
            self.source_browse_button.configure(text="选择文件…", command=self._pick_paste_file)
            self.source_hint_var.set(
                "粘贴通道使用现有 paste-import 校验；选择完整的 SecureCRT / 4A 导出文本，不执行其中内容。")
        else:
            self.source_browse_button.configure(text="选择目录…", command=self._pick_bundle)
            self.source_hint_var.set("支持固定采集器输出目录及 EvidenceBundle；仅复制并解析允许的证据文件。")

    def _update_ai_badge(self) -> None:
        enabled = self.ai_enabled_var.get()
        self.ai_state_badge.configure(text="已启用" if enabled else "默认关闭",
                                      style="StatusPartial.TLabel" if enabled else "StatusEmpty.TLabel")

    def _update_workflow(self) -> None:
        self.workflow_vars[0][2].set("已确认只读授权" if self.local_consent_var.get() else "等待确认")

    def _pick_directory(self, variable: Any) -> None:
        from tkinter import filedialog
        value = filedialog.askdirectory(parent=self.root, mustexist=False)
        if value:
            variable.set(value)

    def _pick_bundle(self) -> None:
        from tkinter import filedialog
        value = filedialog.askdirectory(parent=self.root, mustexist=True)
        if value:
            self.bundle_var.set(value)

    def _pick_paste_file(self) -> None:
        from tkinter import filedialog
        value = filedialog.askopenfilename(parent=self.root, title="选择完整的 SecureCRT / 4A 粘贴导出文件",
                                           filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if value:
            self.bundle_var.set(value)

    def _pick_source(self) -> None:
        self._pick_paste_file() if self.source_var.get() == "paste" else self._pick_bundle()

    def _ai_settings_dialog(self) -> None:
        tk, ttk = self.tk, self.ttk
        dialog = tk.Toplevel(self.root)
        dialog.title("Ollama 辅助建议设置")
        dialog.transient(self.root)
        dialog.resizable(False, False)
        dialog.grab_set()
        frame = ttk.Frame(dialog, style="Workspace.TFrame", padding=22)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="本地模型设置", style="PageTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="仅在导入分析时启用；Ollama cloud 功能必须由你确认已关闭。",
                  style="PageSubtitle.TLabel", wraplength=480).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(6, 16))
        ttk.Label(frame, text="提供方", style="FieldLabel.TLabel").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Label(frame, text="Ollama（当前支持）", style="Page.TLabel").grid(row=2, column=1, sticky="w", padx=(10, 0))
        for row, label, variable, width in (
            (3, "本地服务 Endpoint", self.ai_endpoint_var, 42),
            (4, "模型名称", self.ai_model_var, 42),
            (5, "请求超时（秒）", self.ai_timeout_var, 10),
        ):
            ttk.Label(frame, text=label, style="FieldLabel.TLabel").grid(row=row, column=0, sticky="w", pady=(8, 0))
            self._entry(frame, variable, width=width).grid(row=row, column=1, sticky="ew" if width == 42 else "w",
                                                          padx=(10, 0), pady=(8, 0))
        ttk.Checkbutton(frame, text="我已确认 Ollama cloud 功能关闭",
                        variable=self.ai_ack_var).grid(row=6, column=0, columnspan=2, sticky="w", pady=(16, 10))
        ttk.Label(frame, text="服务身份与推理位置不能仅由回环地址证明。AI 建议与规则结论分开。",
                  style="PageSubtitle.TLabel", wraplength=480).grid(row=7, column=0, columnspan=2, sticky="w")
        buttons = ttk.Frame(frame, style="Workspace.TFrame")
        buttons.grid(row=8, column=0, columnspan=2, sticky="e", pady=(18, 0))
        self._secondary(buttons, "取消", dialog.destroy).pack(side="right", padx=(8, 0))
        self._primary(buttons, "保存本次设置", dialog.destroy, width=16).pack(side="right")
        dialog.update_idletasks()
        x = self.root.winfo_rootx() + max(0, (self.root.winfo_width() - dialog.winfo_reqwidth()) // 2)
        y = self.root.winfo_rooty() + max(0, (self.root.winfo_height() - dialog.winfo_reqheight()) // 2)
        dialog.geometry(f"+{x}+{y}")

    def _aliases(self) -> tuple[str, str] | None:
        project, asset = self.project_var.get().strip(), self.asset_var.get().strip()
        pattern = r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}"
        if not re.fullmatch(pattern, project) or not re.fullmatch(pattern, asset):
            self._message("项目代号和设备代号必须是 1–80 位 ASCII 字母、数字、点、下划线或连字符。")
            return None
        return project, asset

    def _ai_options(self) -> list[str] | None:
        if not self.ai_enabled_var.get():
            return []
        if not self.ai_ack_var.get():
            self._message("启用 AI 前必须确认 Ollama cloud 功能已关闭。")
            return None
        endpoint, model = self.ai_endpoint_var.get().strip(), self.ai_model_var.get().strip()
        try:
            timeout = int(self.ai_timeout_var.get())
        except ValueError:
            self._message("AI 超时必须是 1–1800 秒的整数。")
            return None
        if not endpoint or not model or not 1 <= timeout <= 1800:
            self._message("请填写本地服务 Endpoint、模型名称和 1–1800 秒的超时。")
            return None
        return ["--ai-provider", "ollama", "--ai-endpoint", endpoint, "--ai-model", model,
                "--ai-cloud-disabled-ack", "--ai-timeout", str(timeout)]

    def _start_local(self) -> None:
        if not self.local_consent_var.get():
            self._message("请先确认当前设备及当前权限范围内的只读巡检授权。工具不会自动提权。")
            return
        aliases = self._aliases()
        if not aliases:
            return
        use_case = USE_CASES.get(self.use_case_var.get())
        if not use_case:
            self._message("请选择巡检场景。")
            return
        command = cli_command([
            "inspect-local", "--project-alias", aliases[0], "--asset-alias", aliases[1],
            "--use-case", use_case, "--cases", str(Path(self.cases_var.get()).expanduser()),
            "--output", str(Path(self.reports_var.get()).expanduser()),
        ])
        self._start_worker("本机只读巡检", lambda: self._run_cli(command, allow_partial=True),
                           activity="正在进行本机只读巡检")

    def _start_import(self) -> None:
        selected_text = self.bundle_var.get().strip()
        if not selected_text:
            self._message("请选择证据目录或完整的粘贴导出文件。")
            return
        selected = Path(selected_text).expanduser()
        cases_dir = Path(self.cases_var.get()).expanduser()
        reports_dir = Path(self.reports_var.get()).expanduser()
        ai_options = self._ai_options()
        if ai_options is None:
            return
        if self.source_var.get() == "paste":
            aliases = self._aliases()
            if not aliases:
                return
            use_case = USE_CASES.get(self.use_case_var.get())
            if not use_case:
                self._message("请选择粘贴证据对应的实际用途。")
                return
            operation = lambda: self._paste_import_and_analyze(
                selected, cases_dir, reports_dir, aliases[0], aliases[1], use_case, ai_options)
        else:
            manifest = selected / "manifest.json"
            if not manifest.is_file():
                aliases = self._aliases()
                if not aliases:
                    return
                use_case = USE_CASES.get(self.use_case_var.get())
                if not use_case:
                    self._message("原生证据目录尚未封装；请选择实际用途。")
                    return
            else:
                aliases = (self.project_var.get().strip(), self.asset_var.get().strip())
                use_case = ""
            operation = lambda: self._import_and_analyze(
                selected, cases_dir, reports_dir, aliases[0], aliases[1], use_case, ai_options)
        self._start_worker("证据导入与分析", operation, activity="正在校验证据并进行规则分析")

    def _import_and_analyze(self, selected: Path, cases_dir: Path, reports_dir: Path,
                            project: str, asset: str, use_case: str, ai_options: list[str]) -> dict[str, Any]:
        if not selected.is_dir():
            raise FileNotFoundError("所选证据目录不存在。")
        cases_dir.mkdir(parents=True, exist_ok=True)
        cases_root = cases_dir.resolve(strict=True)
        manifest = selected / "manifest.json"
        if manifest.is_file():
            case_path = import_bundle(selected, cases_dir)
        else:
            staging = cases_root / (".desktop-stage-" + uuid.uuid4().hex)
            stage_native_evidence(selected, staging, allowed_names=NATIVE_RAW_ALLOWED_NAMES)
            try:
                target, collection = derive_native_metadata(staging, use_case)
                write_manifest(staging, project_alias=project, asset_alias=asset,
                               target=target, collection=collection)
                case_path = import_bundle(staging, cases_dir)
            finally:
                if staging.exists() or _is_reparse(staging):
                    if _is_reparse(staging):
                        raise BundleError("Temporary evidence staging path changed to a reparse point; it was preserved.")
                    staging_root = staging.resolve(strict=True)
                    if (staging_root.parent != cases_root or not staging.name.startswith(".desktop-stage-")
                            or cases_dir.resolve(strict=True) != cases_root or _is_reparse(staging)
                            or staging.resolve(strict=True) != staging_root):
                        raise BundleError("Temporary evidence staging path escaped its private cases directory; it was preserved.")
                    shutil.rmtree(staging)
        command = cli_command(["analyze", str(case_path), "--output", str(reports_dir), *ai_options])
        result = self._run_cli(command, allow_partial=True)
        result["case"] = str(case_path)
        return result

    def _paste_import_and_analyze(self, selected: Path, cases_dir: Path, reports_dir: Path,
                                  project: str, asset: str, use_case: str, ai_options: list[str]) -> dict[str, Any]:
        if not selected.is_file():
            raise FileNotFoundError("所选粘贴导出文件不存在。")
        command = cli_command([
            "paste-import", str(selected), "--project-alias", project, "--asset-alias", asset,
            "--use-case", use_case, "--cases", str(cases_dir), "--output", str(reports_dir),
        ])
        imported = self._run_cli(command)
        output = imported.get("command_output", "")
        case_path = next((Path(line.split("=", 1)[1].strip()) for line in output.splitlines()
                          if line.startswith("CASE=")), None)
        if not case_path:
            raise RuntimeError("现有 paste-import 命令未返回已导入案例路径。")
        analysis = self._run_cli(
            cli_command(["analyze", str(case_path), "--output", str(reports_dir), *ai_options]),
            allow_partial=True)
        analysis["case"] = str(case_path)
        return analysis

    def _run_cli(self, command: list[str], allow_partial: bool = False) -> dict[str, Any]:
        lines: list[str] = []
        def receive(text: str) -> None:
            lines.append(text)
        try:
            code = _read_process_output(command, timeout=MAX_CHILD_SECONDS,
                                        cancelled=self.cancel_event, on_output=receive)
        except Exception:
            output = "".join(lines)
            if output.strip():
                self.events.put(("log", output[-MAX_CHILD_OUTPUT:]))
            raise
        output = "".join(lines)
        if output.strip():
            self.events.put(("log", output[-MAX_CHILD_OUTPUT:]))
        if code not in ({0, 4} if allow_partial else {0}):
            raise RuntimeError(f"命令退出码 {code}；请检查上方安全错误信息。")
        analysis_path = None
        comparison_path = None
        for line in output.splitlines():
            if line.startswith("JSON="):
                analysis_path = Path(line.split("=", 1)[1].strip())
            elif line.startswith("COMPARISON="):
                comparison_path = Path(line.split("=", 1)[1].strip())
        if analysis_path and analysis_path.is_file():
            value, metadata = self._read_analysis(analysis_path)
            result = {"analysis": value, "metadata": metadata, "analysis_path": str(analysis_path),
                      "report_dir": str(analysis_path.parent), "command_output": output}
            self.events.put(("analysis", result))
            return result
        if comparison_path and comparison_path.is_file():
            self.events.put(("comparison", str(comparison_path)))
            return {"comparison_path": str(comparison_path), "command_output": output}
        return {"command_output": output}

    def _read_analysis(self, path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
        if not path.is_file():
            raise FileNotFoundError("analysis.json 不存在。")
        if path.stat().st_size > MAX_ANALYSIS_BYTES:
            raise ValueError("analysis.json 超出 20 MiB 安全读取上限。")
        from inspection_cli import _load_analysis
        result, metadata = _load_analysis(path)
        return result.to_dict(), metadata

    def _load_analysis_dialog(self) -> None:
        from tkinter import filedialog
        source = filedialog.askopenfilename(
            parent=self.root, title="选择已有 analysis.json",
            filetypes=[("分析 JSON", "analysis.json"), ("JSON", "*.json")])
        if not source:
            return
        try:
            value, metadata = self._read_analysis(Path(source))
        except Exception as exc:
            self._message(f"无法加载分析文件：{type(exc).__name__}: {exc}")
            return
        self._show_analysis({"analysis": value, "metadata": metadata,
                             "analysis_path": source, "report_dir": str(Path(source).parent)})

    def _start_codex(self) -> None:
        from tkinter import filedialog, messagebox
        if self.last_analysis and self.last_analysis.is_file():
            choice = messagebox.askyesnocancel(
                "Codex 脱敏交付", "使用当前已加载的 analysis.json？\n选择“否”以另选文件。",
                parent=self.root)
            if choice is None:
                return
            source = str(self.last_analysis) if choice else filedialog.askopenfilename(
                parent=self.root, title="选择报告的 analysis.json",
                filetypes=[("分析 JSON", "analysis.json"), ("JSON", "*.json")])
        else:
            source = filedialog.askopenfilename(
                parent=self.root, title="选择报告的 analysis.json",
                filetypes=[("分析 JSON", "analysis.json"), ("JSON", "*.json")])
        if not source:
            return
        output = filedialog.asksaveasfilename(
            parent=self.root, title="保存脱敏交付文件",
            defaultextension=".json", filetypes=[("JSON", "*.json")])
        if output:
            command = cli_command(["codex-export", source, "--output", output])
            self._start_worker("Codex 脱敏导出", lambda: self._run_cli(command),
                               activity="正在生成脱敏交付文件")

    def _start_compare(self) -> None:
        from tkinter import filedialog
        before = filedialog.askopenfilename(
            parent=self.root, title="选择整改前 analysis.json",
            filetypes=[("分析 JSON", "analysis.json"), ("JSON", "*.json")])
        if not before:
            return
        after = filedialog.askopenfilename(
            parent=self.root, title="选择整改后 analysis.json",
            filetypes=[("分析 JSON", "analysis.json"), ("JSON", "*.json")])
        if not after:
            return
        output = filedialog.asksaveasfilename(
            parent=self.root, title="保存复查结果",
            defaultextension=".json", filetypes=[("JSON", "*.json")])
        if output:
            command = cli_command(["compare", before, after, "--output", output])
            self._start_worker("复查比较", lambda: self._run_cli(command, allow_partial=True),
                               activity="正在按正式比较规则核对两份分析")

    def _show_analysis(self, result: dict[str, Any]) -> None:
        analysis_path = Path(result["analysis_path"])
        report_dir = Path(result.get("report_dir", analysis_path.parent))
        value = result.get("analysis")
        metadata = result.get("metadata", {})
        if not isinstance(value, dict):
            raise ValueError("分析结果结构不正确。")
        self.last_analysis = analysis_path
        self.last_report_dir = report_dir
        self.analysis_value = value
        self.analysis_metadata = metadata if isinstance(metadata, dict) else {}
        status = value.get("status", "UNKNOWN")
        findings = value.get("findings", [])
        warnings, errors = value.get("warnings", []), value.get("errors", [])
        gaps = (warnings if isinstance(warnings, list) else []) + (errors if isinstance(errors, list) else [])
        self.analysis_status_var.set(str(status))
        self.finding_count_var.set(str(len(findings) if isinstance(findings, list) else 0))
        self.gap_count_var.set(str(len(gaps)))
        identity = self.analysis_metadata.get("asset_alias") or self.analysis_metadata.get("project_alias") or "已加载分析"
        self.analysis_record_var.set(f"{identity}  ·  {analysis_path.name}  ·  {analysis_path}")
        self.report_path_var.set(str(report_dir))
        self._set_analysis_badge(status)
        self._render_findings()
        self._render_gap_text()
        self._render_ai_advisory()
        self.workflow_vars[1][2].set("证据已分析")
        self.workflow_vars[2][2].set(f"{status} · {len(findings) if isinstance(findings, list) else 0} 条")
        self.workflow_vars[3][2].set("报告已生成" if report_dir.is_dir() else "已加载分析文件")
        self._append(
            f"\n已加载分析：{status}；规则 Finding {self.finding_count_var.get()} 条；"
            f"证据缺口/错误 {self.gap_count_var.get()} 条。\n")

    def _set_analysis_badge(self, status: Any) -> None:
        if hasattr(self, "analysis_status_badge"):
            style = {"OK": "StatusOk.TLabel", "PARTIAL": "StatusPartial.TLabel",
                     "FAILED": "StatusFailed.TLabel"}.get(status, "StatusEmpty.TLabel")
            self.analysis_status_badge.configure(style=style)

    def _render_findings(self) -> None:
        if not hasattr(self, "finding_tree"):
            return
        tree = self.finding_tree
        tree.delete(*tree.get_children())
        self._finding_by_iid.clear()
        value = self.analysis_value or {}
        if not value:
            self._show_findings_empty("尚未加载分析。请选择真实 analysis.json；不会使用示例数据填充。")
            return
        findings = value.get("findings", [])
        if self._current_filter == "gaps":
            self._show_findings_empty("证据缺口与分析状态说明显示在下方区域。")
            self._set_text(self.finding_detail, "已选择“证据缺口”。请查看下方的原始警告与错误列表。")
            return
        visible = []
        for finding in findings if isinstance(findings, list) else []:
            if not isinstance(finding, dict):
                continue
            if self._current_filter == "review" and finding.get("needs_human_review", True) is not True:
                continue
            visible.append(finding)
        for index, finding in enumerate(visible):
            iid = str(index)
            severity = str(finding.get("severity", "未知"))
            evidence = finding.get("evidence", {})
            evidence_text = json.dumps(evidence, ensure_ascii=False, sort_keys=True) if isinstance(
                evidence, (dict, list)) else str(evidence)
            evidence_text = evidence_text.replace("\n", " ")[:180]
            tag = severity if severity in {"Critical", "High", "Warning", "Info"} else ""
            tree.insert("", "end", iid=iid, values=(
                severity, str(finding.get("title", finding.get("finding_id", "未命名"))), evidence_text),
                tags=(tag,) if tag else ())
            self._finding_by_iid[iid] = finding
        if visible:
            self._hide_findings_empty()
            first = tree.get_children()[0]
            tree.selection_set(first)
            self._display_finding(self._finding_by_iid[first])
        else:
            if self._current_filter == "review":
                message = "当前筛选条件下没有待复核 Finding；这不改变分析状态。"
            else:
                message = "分析中没有规则 Finding；证据缺口和状态仍需单独查看。"
            self.finding_detail.configure(height=3)
            self._show_findings_empty(message)
            self._set_text(self.finding_detail, message)

    def _show_findings_empty(self, message: str) -> None:
        self.finding_empty_var.set(message)
        self.finding_tree.grid_remove()
        self.finding_scrollbar.grid_remove()
        self.finding_empty_label.grid(row=0, column=0, columnspan=2, sticky="nsew")
        self.finding_detail.configure(height=3)

    def _hide_findings_empty(self) -> None:
        self.finding_empty_label.grid_remove()
        self.finding_tree.grid(row=0, column=0, sticky="nsew")
        self.finding_scrollbar.grid(row=0, column=1, sticky="ns")

    def _set_filter(self, key: str) -> None:
        self._current_filter = key
        for name, button in self.filter_buttons.items():
            button.configure(style="FilterActive.TButton" if name == key else "Filter.TButton")
        self._render_findings()

    def _on_finding_selected(self, _event: Any) -> None:
        selected = self.finding_tree.selection()
        if selected and selected[0] in self._finding_by_iid:
            self._display_finding(self._finding_by_iid[selected[0]])

    def _display_finding(self, finding: dict[str, Any]) -> None:
        self.finding_detail.configure(height=5)
        lines = []
        for key, label in (
            ("finding_id", "Finding ID"), ("rule_id", "规则 ID"), ("title", "检查项目"),
            ("severity", "风险等级"), ("category", "类别"), ("component", "对象"),
            ("description", "描述"), ("evidence", "原始证据"), ("precheck", "整改前核查"),
            ("applicability", "适用性"), ("impact", "影响与条件"),
            ("recommendation", "整改建议"), ("rollback", "回滚"),
            ("verification_checkpoint", "复查要点"),
        ):
            if key not in finding:
                continue
            item = finding[key]
            rendered = json.dumps(item, ensure_ascii=False, indent=2) if isinstance(item, (dict, list)) else str(item)
            lines.append(f"{label}：\n{rendered}")
        self._set_text(self.finding_detail, "\n\n".join(lines) or "该 Finding 没有可显示的详情字段。")

    def _render_gap_text(self) -> None:
        value = self.analysis_value or {}
        lines = []
        for key, label in (("warnings", "警告 / 证据缺口"), ("errors", "分析错误")):
            entries = value.get(key, [])
            if isinstance(entries, list):
                lines.extend(f"{label}：{item}" for item in entries)
        if not lines:
            lines = ["分析文件未记录警告或错误。该信息不代表已检查范围外的安全状态。"]
        self._set_text(self.gaps_text, "\n".join(lines))

    def _render_ai_advisory(self) -> None:
        advisory = self.analysis_metadata.get("ai_advisory")
        if not isinstance(advisory, dict):
            text = "当前分析没有 AI 辅助建议字段。AI 默认关闭，且不会改变确定性 Finding。"
        else:
            lines = [f"AI 状态：{advisory.get('status', '未知')}",
                     "AI 内容仅为辅助建议，不是确定性风险结论。"]
            if advisory.get("reason"):
                lines.append(f"原因：{advisory['reason']}")
            suggestions = advisory.get("suggestions", [])
            if isinstance(suggestions, list):
                for index, suggestion in enumerate(suggestions, start=1):
                    if isinstance(suggestion, dict):
                        refs = suggestion.get("evidence_refs", [])
                        ref_text = ", ".join(str(ref) for ref in refs) if isinstance(refs, list) else str(refs)
                        lines.append(f"{index}. {suggestion.get('text', '')}  （引用：{ref_text or '未提供'}）")
            text = "\n".join(lines)
        self._set_text(self.ai_text, text)

    def _set_text(self, widget: Any, text: str) -> None:
        if not hasattr(widget, "winfo_exists") or not widget.winfo_exists():
            return
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text[:MAX_CHILD_OUTPUT])
        widget.configure(state="disabled")

    def _update_empty_report(self) -> None:
        self.analysis_status_var.set("未加载")
        self._set_analysis_badge("未加载")
        self.finding_count_var.set("—")
        self.gap_count_var.set("—")
        self.finding_detail.configure(height=3)
        self._set_text(self.finding_detail, "未加载分析文件。选择真实 analysis.json 后，这里展示对应 Finding 字段。")
        self._set_text(self.gaps_text, "未加载分析文件。")
        self._set_text(self.ai_text, "AI 默认关闭；加载真实分析文件后显示该分析实际记录的 AI 状态与建议。")
        self._render_findings()

    def _open_last_report(self) -> None:
        if not self.last_report_dir or not self.last_report_dir.is_dir():
            self._message("本次会话还没有可查看的报告目录。")
            return
        self._open_path(self.last_report_dir)

    def _open_report_file(self, name: str) -> None:
        if not self.last_report_dir:
            self._message("尚无本会话报告。请先完成分析或加载分析文件。")
            return
        path = self.last_report_dir / name
        if not path.is_file():
            self._message(f"报告文件不存在：{name}")
            return
        self._open_path(path)

    def _open_path(self, path: Path) -> None:
        try:
            if os.name == "nt":
                os.startfile(str(path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)], shell=False)
            else:
                subprocess.Popen(["xdg-open", str(path)], shell=False)
        except Exception as exc:
            self._message(f"无法打开所选报告：{type(exc).__name__}: {exc}")

    def _start_worker(self, label: str, operation: Callable[[], Any], *, activity: str) -> None:
        if self.busy:
            self._message("已有操作正在运行，请等待完成或先取消。")
            return
        self.cancel_event.clear()
        self.busy = True
        self.activity_var.set(activity)
        self.status_var.set(activity + "；界面可继续响应，也可请求取消。")
        self.cancel_button.configure(state="normal")
        self.footer_progress.grid()
        self.footer_progress.start(12)
        for progress in self.progress_bars:
            progress.grid()
            progress.start(12)
        self._clear_logs()

        def worker() -> None:
            try:
                value = operation()
                self.events.put(("done", (label, value)))
            except Exception as exc:
                self.events.put(("error", (label, f"{type(exc).__name__}: {exc}")))

        threading.Thread(target=worker, daemon=True).start()

    def _clear_logs(self) -> None:
        for widget in self.log_widgets:
            if widget.winfo_exists():
                widget.configure(state="normal")
                widget.delete("1.0", "end")
                widget.configure(state="disabled")

    def _poll(self) -> None:
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "log":
                    self._append(str(value))
                elif kind == "analysis":
                    try:
                        self._show_analysis(value)
                    except Exception as exc:
                        self._append(f"\n结果文件无法安全显示：{type(exc).__name__}: {exc}\n")
                        self.status_var.set("分析已生成，但结果文件未能安全加载；未显示为成功。")
                elif kind == "comparison":
                    self.compare_path = Path(value)
                    self.compare_result_var.set(str(value))
                    self._append(f"\n复查比较文件：{value}\n")
                elif kind == "done":
                    label, result = value
                    self.activity_var.set("已完成（需以分析状态为准）")
                    self.status_var.set(label + " 已结束。PARTIAL / FAILED 不表示检查通过。")
                    if isinstance(result, dict) and result.get("case"):
                        self._append("\n已导入案例：" + str(result["case"]) + "\n")
                    self._finish_worker()
                elif kind == "error":
                    label, error = value
                    cancelled = self.cancel_event.is_set()
                    self.activity_var.set("已取消" if cancelled else "未完成")
                    self._append(f"\n操作未完成：{error}\n")
                    self.status_var.set("操作已取消，未标记成功。" if cancelled else "操作未完成；已有确定性报告（若已生成）仍可查看。")
                    self._finish_worker()
        except queue.Empty:
            pass
        try:
            self.root.after(100, self._poll)
        except self.tk.TclError:
            pass

    def _finish_worker(self) -> None:
        self.busy = False
        self.cancel_button.configure(state="disabled")
        self.footer_progress.stop()
        self.footer_progress.grid_remove()
        for progress in self.progress_bars:
            progress.stop()
            progress.grid_remove()

    def _append(self, text: str) -> None:
        for widget in self.log_widgets:
            if not widget.winfo_exists():
                continue
            widget.configure(state="normal")
            widget.insert("end", text[:MAX_CHILD_OUTPUT])
            widget.see("end")
            widget.configure(state="disabled")

    def _message(self, text: str) -> None:
        from tkinter import messagebox
        messagebox.showinfo("巡检工具", text, parent=self.root)

    def _cancel(self) -> None:
        if self.busy:
            self.cancel_event.set()
            self.status_var.set("正在请求取消，并清理本程序启动的子进程……")

    def _close(self) -> None:
        if self.busy:
            from tkinter import messagebox
            if not messagebox.askyesno("操作仍在运行", "取消当前操作并关闭窗口？", parent=self.root):
                return
            self.cancel_event.set()
            self.status_var.set("正在结束当前子进程；请等待窗口关闭。")
            self.root.after(1200, self._finish_close)
            return
        self.root.destroy()

    def _finish_close(self) -> None:
        if self.busy:
            self.root.after(300, self._finish_close)
        else:
            self.root.destroy()
