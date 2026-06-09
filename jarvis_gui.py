#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         J.A.R.V.I.S. — Network Guardian  Graphical Interface    ║
║         jarvis_gui.py  |  Dark-theme Tkinter command shell       ║
╠══════════════════════════════════════════════════════════════════╣
║  Launch:                                                         ║
║    python jarvis_gui.py                                          ║
║    DEEPSEEK_API_KEY=sk-...  python jarvis_gui.py                 ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import logging
import os
import queue
import re
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

# ── Crash log setup (runs before ANYTHING else) ────────────────────
_LOG_PATH = Path(__file__).parent / "jarvis_crash.log"
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    handlers=[
        logging.FileHandler(_LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
_log = logging.getLogger("jarvis.gui")
_log.info("=" * 60)
_log.info("JARVIS GUI starting — Python %s", sys.version.split()[0])

def _excepthook(exc_type, exc_val, exc_tb):
    """Catch ALL unhandled exceptions — write full traceback to log."""
    msg = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
    _log.critical("UNHANDLED EXCEPTION:\n%s", msg)
    sys.__excepthook__(exc_type, exc_val, exc_tb)

sys.excepthook = _excepthook

def _thread_excepthook(args):
    """Catch unhandled exceptions in ALL background threads."""
    msg = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
    _log.critical("UNHANDLED THREAD EXCEPTION (thread=%s):\n%s", args.thread, msg)

threading.excepthook = _thread_excepthook

# ── Load .env before anything else ────────────────────────────────
try:
    from dotenv import load_dotenv
    _ENV = Path(__file__).parent / ".env"
    if _ENV.exists():
        load_dotenv(_ENV, override=False)
except ImportError:
    pass

# ── Tkinter — macOS Tk 9.0 NaN-scaling workaround ─────────────────
# Tk 9.0 on macOS crashes in ::tk::ScalingPct when [tk scaling] returns NaN
# (no display DPI available). We redirect TK_LIBRARY to a patched copy of the
# Tk scripts that guards against NaN before it can crash the Tcl bootstrap.
import os as _os
_TK_PATCH = Path(__file__).resolve().parent / "tk9.0"
if sys.platform == "darwin" and _TK_PATCH.is_dir() and "TK_LIBRARY" not in _os.environ:
    _os.environ["TK_LIBRARY"] = str(_TK_PATCH)
    _log.info("Using patched TK_LIBRARY: %s", _TK_PATCH)
import tkinter as tk
from tkinter import font as tkfont

# ── JARVIS subsystem imports ───────────────────────────────────────
_NG_ROOT = Path(__file__).resolve().parent
if str(_NG_ROOT) not in sys.path:
    sys.path.insert(0, str(_NG_ROOT))

try:
    from network_guardian.jarvis.jarvis_core import JarvisCore, parse_intent
    from network_guardian.jarvis.telemetry_aggregator import TelemetryAggregator
    from network_guardian.jarvis.threat_report_engine import ThreatReportEngine
    _JARVIS_OK = True
    _JARVIS_ERR = ""
except Exception as _e:
    _JARVIS_OK = False
    _JARVIS_ERR = str(_e)
    JarvisCore = None   # type: ignore[assignment,misc]
    TelemetryAggregator = None   # type: ignore[assignment,misc]
    ThreatReportEngine = None    # type: ignore[assignment,misc]


# ══════════════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════════════

C = {
    "bg":         "#0d1117",
    "bg_chat":    "#0a0f1e",
    "bg_side":    "#0d1117",
    "bg_input":   "#161b27",
    "bg_btn":     "#1c2333",
    "bg_btn_h":   "#21262d",
    "border":     "#30363d",
    "text":       "#e6edf3",
    "dim":        "#8b949e",
    "cyan":       "#58d4f0",
    "green":      "#3fb950",
    "yellow":     "#d29922",
    "red":        "#f85149",
    "blue":       "#58a6ff",
    "magenta":    "#bc8cff",
    "orange":     "#f0883e",
    "white":      "#ffffff",
}

THREAT_COLORS = {
    "NOMINAL":  "#3fb950",
    "ELEVATED": "#d29922",
    "HIGH":     "#f0883e",
    "CRITICAL": "#f85149",
}

# ANSI code → colour tag
_ANSI_MAP = {
    "91": "red",    "92": "green",  "93": "yellow",
    "94": "blue",   "95": "magenta","96": "cyan",
    "97": "white",  "1":  "bold",   "2":  "dim",
    "0":  "reset",
}
_ANSI_RE = re.compile(r"\033\[([0-9;]+)m")

# Quick-action sidebar buttons
QUICK_ACTIONS = [
    ("⬡  Situation",    "situation",  "cyan"),
    ("◈  AI Triage",    "triage",     "blue"),
    ("◉  Fleet",        "fleet",      "magenta"),
    ("◆  Firewall",     "firewall",   "yellow"),
    ("▷  Lateral Scan", "lateral",    "orange"),
    ("≡  Metrics",      "metrics",    "green"),
    ("?  Help",         "help",       "dim"),
]


# ══════════════════════════════════════════════════════════════════
#  STDOUT CAPTURE (real-time streaming)
# ══════════════════════════════════════════════════════════════════

class _StreamCapture:
    """Routes sys.stdout/stderr writes into a queue for live GUI display."""

    def __init__(self, q: "queue.Queue[str]") -> None:
        self._q = q

    def write(self, text: str) -> int:
        if text:
            self._q.put(text)
        return len(text)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


# ══════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════

class JarvisGUI:
    POLL_MS    = 35     # output-queue poll
    METRICS_MS = 4000   # sidebar metrics refresh

    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._out_q: queue.Queue[str] = queue.Queue()
        self._busy   = threading.Event()
        self._core: JarvisCore | None = None
        self._history: list[str] = []
        self._hist_idx = 0
        self._spinning = False
        self._voice_enabled = True
        self._mic_active    = False

        # Redirect all unhandled Tkinter callback exceptions to log
        self._root.report_callback_exception = self._on_tk_error

        self._setup_window()
        self._build_fonts()
        self._build_ui()
        self._configure_tags()
        self._print_banner()
        self._start_polling()
        self._schedule_metrics()

        if not _JARVIS_OK:
            self._append(f"\n  ✗  Import error: {_JARVIS_ERR}\n", "red")
        else:
            # Build JarvisCore WITHOUT voice/ear (those start on background thread)
            self._core = JarvisCore(voice=False, ear=False)
            has_key = bool(os.environ.get("DEEPSEEK_API_KEY"))
            ai_txt  = "DeepSeek-R1 ACTIVE" if has_key else "DeepSeek OFFLINE — set DEEPSEEK_API_KEY"
            ai_col  = "green" if has_key else "yellow"
            self._append(f"\n  ✓  J.A.R.V.I.S. online.  {ai_txt}\n", ai_col)
            self._append("  Natural language accepted — type, click, or speak a command.\n", "dim")
            self._append("─" * 66 + "\n\n", "dim")
            # Start ear polling loop (no calibration yet)
            self._start_ear_polling()
            # Init voice on a background thread so COM stays on that thread
            threading.Thread(target=self._init_voice_bg, daemon=True).start()

    def _on_tk_error(self, exc_type, exc_val, exc_tb) -> None:
        """Catch all Tkinter callback exceptions without crashing the app."""
        msg = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
        _log.error("Tkinter callback exception:\n%s", msg)
        try:
            self._append(f"  ✗ Error: {exc_val}\n  (full traceback → jarvis_crash.log)\n", "red")
        except Exception:
            pass

    def _init_voice_bg(self) -> None:
        """Create JarvisVoice on the thread that will own the COM object."""
        try:
            from network_guardian.jarvis.jarvis_voice import JarvisVoice
            self._core._voice = JarvisVoice()
            op = os.environ.get("JARVIS_OPERATOR", "sir").split()[0]
            self._core._voice.say(f"J.A.R.V.I.S. online. All systems standing by, {op}.")
        except Exception as exc:
            self._root.after(0, lambda: self._append(f"  Voice init error: {exc}\n", "yellow"))

    # ─────────────────────────────────────────────────────────────
    #  Window / font setup
    # ─────────────────────────────────────────────────────────────

    def _setup_window(self) -> None:
        self._root.title("J.A.R.V.I.S. — Network Guardian")
        self._root.configure(bg=C["bg"])
        self._root.geometry("1200x780")
        self._root.minsize(920, 620)

    def _build_fonts(self) -> None:
        self._f_mono    = tkfont.Font(family="Consolas", size=10)
        self._f_mono_sm = tkfont.Font(family="Consolas", size=9)
        self._f_mono_bd = tkfont.Font(family="Consolas", size=10, weight="bold")
        self._f_title   = tkfont.Font(family="Consolas", size=13, weight="bold")
        self._f_sans    = tkfont.Font(family="Segoe UI",  size=9)
        self._f_sans_bd = tkfont.Font(family="Segoe UI",  size=9, weight="bold")
        self._f_sans_sm = tkfont.Font(family="Segoe UI",  size=8)

    # ─────────────────────────────────────────────────────────────
    #  UI layout
    # ─────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_titlebar()
        _hsep(self._root, padx=12, pady=(4, 0))
        self._build_body()
        _hsep(self._root, padx=12, pady=(6, 0))
        self._build_input_row()

    def _build_titlebar(self) -> None:
        bar = tk.Frame(self._root, bg=C["bg"])
        bar.pack(fill=tk.X, padx=14, pady=(10, 4))

        tk.Label(bar, text="◈  J.A.R.V.I.S.", bg=C["bg"],
                 fg=C["cyan"], font=self._f_title).pack(side=tk.LEFT)
        tk.Label(bar, text="  Network Guardian  v48",
                 bg=C["bg"], fg=C["dim"], font=self._f_sans).pack(side=tk.LEFT)

        # Threat badge (far right)
        self._threat_var = tk.StringVar(value="● NOMINAL")
        self._threat_lbl = tk.Label(bar, textvariable=self._threat_var,
                                    bg=C["bg"], fg=C["green"], font=self._f_sans_bd)
        self._threat_lbl.pack(side=tk.RIGHT, padx=(0, 4))
        tk.Label(bar, text="THREAT:", bg=C["bg"], fg=C["dim"],
                 font=self._f_sans).pack(side=tk.RIGHT)

    def _build_body(self) -> None:
        body = tk.Frame(self._root, bg=C["bg"])
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=(8, 0))

        # ── Chat pane ────────────────────────────────────────
        chat_wrap = tk.Frame(body, bg=C["bg_chat"])
        chat_wrap.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._chat = tk.Text(
            chat_wrap,
            bg=C["bg_chat"], fg=C["text"],
            font=self._f_mono,
            insertbackground=C["cyan"],
            selectbackground="#264f78",
            selectforeground=C["text"],
            relief=tk.FLAT, bd=0,
            wrap=tk.WORD,
            state=tk.DISABLED,
            cursor="arrow",
        )
        sb = tk.Scrollbar(chat_wrap, command=self._chat.yview,
                          bg=C["bg"], activebackground=C["border"],
                          troughcolor=C["bg_chat"], bd=0, width=8, relief=tk.FLAT)
        self._chat.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._chat.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(6, 0), pady=6)

        # ── Sidebar ──────────────────────────────────────────
        self._build_sidebar(body)

    def _build_sidebar(self, parent: tk.Frame) -> None:
        side = tk.Frame(parent, bg=C["bg_side"], width=268)
        side.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        side.pack_propagate(False)

        def _hdr(text: str) -> None:
            tk.Label(side, text=text, bg=C["bg_side"], fg=C["dim"],
                     font=self._f_sans_bd).pack(anchor=tk.W, padx=10, pady=(14, 3))
            _hsep(side, padx=10, pady=0)

        # ── System Metrics ────────────────────────────────
        _hdr("SYSTEM METRICS")

        self._metric_vars:  dict[str, tk.StringVar] = {}
        self._bar_cvs:      dict[str, tk.Canvas]    = {}
        self._bar_rects:    dict[str, int]           = {}

        for key, label in (("cpu", "CPU"), ("mem", "MEMORY"), ("disk", "DISK")):
            row = tk.Frame(side, bg=C["bg_side"])
            row.pack(fill=tk.X, padx=10, pady=(6, 0))

            tk.Label(row, text=f"{label:<7}", bg=C["bg_side"], fg=C["dim"],
                     font=self._f_mono_sm, width=7, anchor=tk.W).pack(side=tk.LEFT)

            cv = tk.Canvas(row, height=11, bg=C["bg"],
                           highlightthickness=0, relief=tk.FLAT)
            cv.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 4))
            # track bg rect so bar width is always correct
            cv.create_rectangle(0, 2, 2000, 10, fill=C["border"], outline="")
            rfg = cv.create_rectangle(0, 2, 0, 10, fill=C["green"], outline="")
            self._bar_cvs[key]   = cv
            self._bar_rects[key] = rfg

            vv = tk.StringVar(value="—")
            self._metric_vars[key] = vv
            tk.Label(row, textvariable=vv, bg=C["bg_side"], fg=C["text"],
                     font=self._f_mono_sm, width=5, anchor=tk.E).pack(side=tk.RIGHT)

        # Uptime / procs
        self._uptime_var = tk.StringVar(value="—")
        self._procs_var  = tk.StringVar(value="—")
        for label, var in (("UPTIME ", self._uptime_var), ("PROCS  ", self._procs_var)):
            row = tk.Frame(side, bg=C["bg_side"])
            row.pack(fill=tk.X, padx=10, pady=(5, 0))
            tk.Label(row, text=label, bg=C["bg_side"], fg=C["dim"],
                     font=self._f_mono_sm).pack(side=tk.LEFT)
            tk.Label(row, textvariable=var, bg=C["bg_side"], fg=C["text"],
                     font=self._f_mono_sm).pack(side=tk.LEFT)

        # ── Quick Actions ─────────────────────────────────
        _hdr("QUICK ACTIONS")
        for (lbl, cmd, col) in QUICK_ACTIONS:
            btn = tk.Button(
                side, text=f"  {lbl}",
                command=lambda c=cmd: self._run_quick(c),
                bg=C["bg_btn"], fg=C.get(col, C["text"]),
                activebackground=C["bg_btn_h"],
                activeforeground=C.get(col, C["text"]),
                relief=tk.FLAT, font=self._f_sans, anchor=tk.W,
                padx=6, pady=5, cursor="hand2",
            )
            btn.pack(fill=tk.X, padx=10, pady=2)

        # ── AI Engine Status ──────────────────────────────
        _hdr("AI ENGINE")
        has_key = bool(os.environ.get("DEEPSEEK_API_KEY"))
        ds_col  = C["green"] if has_key else C["yellow"]
        ds_txt  = "● DeepSeek-R1  ACTIVE" if has_key else "● DeepSeek-R1  OFFLINE"
        tk.Label(side, text=ds_txt, bg=C["bg_side"], fg=ds_col,
                 font=self._f_mono_sm).pack(anchor=tk.W, padx=10, pady=(6, 2))

        lg_col = C["green"] if _JARVIS_OK else C["red"]
        lg_txt = "● LangGraph    READY" if _JARVIS_OK else "● LangGraph    ERROR"
        tk.Label(side, text=lg_txt, bg=C["bg_side"], fg=lg_col,
                 font=self._f_mono_sm).pack(anchor=tk.W, padx=10, pady=(0, 2))

        try:
            from network_guardian.jarvis.jarvis_voice import JarvisVoice as _JV
            _vok = True
        except Exception:
            _vok = False
        v_col = C["green"] if _vok else C["yellow"]
        v_txt = "● Voice        READY" if _vok else "● Voice        OFFLINE"
        tk.Label(side, text=v_txt, bg=C["bg_side"], fg=v_col,
                 font=self._f_mono_sm).pack(anchor=tk.W, padx=10, pady=(0, 2))

        try:
            import speech_recognition as _sr; import pyaudio as _pa
            _mok = True
        except Exception:
            _mok = False
        m_col = C["green"] if _mok else C["yellow"]
        m_txt = "● Microphone   READY" if _mok else "● Microphone   OFFLINE"
        tk.Label(side, text=m_txt, bg=C["bg_side"], fg=m_col,
                 font=self._f_mono_sm).pack(anchor=tk.W, padx=10, pady=(0, 4))

        # Footer
        _hsep(side, padx=10, pady=(10, 0))
        tk.Label(side, text="Network Guardian  v48  |  Wolf-Pak Innovations LLC",
                 bg=C["bg_side"], fg=C["dim"], font=self._f_sans_sm,
                 wraplength=240, justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=(4, 6))

    def _build_input_row(self) -> None:
        row = tk.Frame(self._root, bg=C["bg_input"])
        row.pack(fill=tk.X, padx=12, pady=(0, 12))

        tk.Label(row, text=" jarvis > ", bg=C["bg_input"], fg=C["cyan"],
                 font=self._f_mono).pack(side=tk.LEFT, padx=(8, 0))

        self._input_var = tk.StringVar()
        self._entry = tk.Entry(
            row, textvariable=self._input_var,
            bg=C["bg_input"], fg=C["text"],
            insertbackground=C["cyan"],
            relief=tk.FLAT, font=self._f_mono, bd=0,
        )
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        self._entry.bind("<Return>", lambda _e: self._submit())
        self._entry.bind("<Up>",     lambda _e: self._hist_up())
        self._entry.bind("<Down>",   lambda _e: self._hist_down())
        self._entry.focus_set()

        # Busy spinner label
        self._busy_var = tk.StringVar(value="")
        tk.Label(row, textvariable=self._busy_var, bg=C["bg_input"],
                 fg=C["yellow"], font=self._f_sans).pack(side=tk.RIGHT, padx=(0, 6))

        self._send_btn = tk.Button(
            row, text=" Send  ▶ ",
            command=self._submit,
            bg=C["bg_btn"], fg=C["cyan"],
            activebackground=C["bg_btn_h"], activeforeground=C["cyan"],
            relief=tk.FLAT, font=self._f_sans_bd,
            padx=12, pady=6, cursor="hand2",
        )
        self._send_btn.pack(side=tk.RIGHT, padx=(6, 10))

        # Voice toggle button 🔊 / 🔇
        self._voice_btn = tk.Button(
            row, text=" 🔊 ",
            command=self._toggle_voice,
            bg=C["bg_btn"], fg=C["green"],
            activebackground=C["bg_btn_h"],
            relief=tk.FLAT, font=self._f_sans_bd,
            padx=8, pady=6, cursor="hand2",
        )
        self._voice_btn.pack(side=tk.RIGHT, padx=(0, 4))

        # Mic button 🎤
        self._mic_btn = tk.Button(
            row, text=" 🎤 ",
            command=self._toggle_mic,
            bg=C["bg_btn"], fg=C["dim"],
            activebackground=C["bg_btn_h"],
            relief=tk.FLAT, font=self._f_sans_bd,
            padx=8, pady=6, cursor="hand2",
        )
        self._mic_btn.pack(side=tk.RIGHT, padx=(0, 4))
        self._root.after(500, self._poll_mic_state)


    # ─────────────────────────────────────────────────────────────
    #  Chat text tags
    # ─────────────────────────────────────────────────────────────

    def _configure_tags(self) -> None:
        self._chat.configure(state=tk.NORMAL)
        bd = tkfont.Font(family="Consolas", size=10, weight="bold")
        self._chat.tag_configure("cyan",     foreground=C["cyan"])
        self._chat.tag_configure("green",    foreground=C["green"])
        self._chat.tag_configure("yellow",   foreground=C["yellow"])
        self._chat.tag_configure("red",      foreground=C["red"])
        self._chat.tag_configure("blue",     foreground=C["blue"])
        self._chat.tag_configure("magenta",  foreground=C["magenta"])
        self._chat.tag_configure("orange",   foreground=C["orange"])
        self._chat.tag_configure("white",    foreground=C["white"])
        self._chat.tag_configure("dim",      foreground=C["dim"])
        self._chat.tag_configure("bold",     font=bd)
        self._chat.tag_configure("reset",    foreground=C["text"])
        self._chat.tag_configure("input_echo",
                                 foreground=C["cyan"], font=bd)
        self._chat.tag_configure("section_hdr",
                                 foreground=C["white"], font=bd,
                                 background="#161b27", spacing1=4, spacing3=4)
        self._chat.configure(state=tk.DISABLED)

    # ─────────────────────────────────────────────────────────────
    #  Banner
    # ─────────────────────────────────────────────────────────────

    def _print_banner(self) -> None:
        banner_lines = [
            "     ██╗ █████╗ ██████╗ ██╗   ██╗██╗███████╗",
            "     ██║██╔══██╗██╔══██╗██║   ██║██║██╔════╝",
            "     ██║███████║██████╔╝██║   ██║██║███████╗",
            "██   ██║██╔══██║██╔══██╗╚██╗ ██╔╝██║╚════██║",
            "╚█████╔╝██║  ██║██║  ██║ ╚████╔╝ ██║███████║",
            " ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝",
        ]
        for ln in banner_lines:
            self._append(f"  {ln}\n", "cyan")
        self._append(
            "  Just A Rather Very Intelligent System\n"
            "  Network Guardian — Threat Intelligence Layer\n",
            "dim",
        )
        ts = datetime.now().strftime("%A %d %B %Y   %H:%M:%S")
        self._append(f"  {ts}\n", "dim")
        self._append("─" * 66 + "\n", "dim")

    # ─────────────────────────────────────────────────────────────
    #  Output helpers
    # ─────────────────────────────────────────────────────────────

    def _append(self, text: str, tag: str | None = None) -> None:
        """Append coloured text (call from main thread only)."""
        self._chat.configure(state=tk.NORMAL)
        self._chat.insert(tk.END, text, tag or "")
        self._chat.configure(state=tk.DISABLED)
        self._chat.see(tk.END)

    def _append_ansi(self, text: str) -> None:
        """Parse ANSI escape codes and insert with corresponding colour tags."""
        parts = _ANSI_RE.split(text)
        self._chat.configure(state=tk.NORMAL)
        current_tag: str | None = None
        for i, chunk in enumerate(parts):
            if i % 2 == 0:
                if chunk:
                    self._chat.insert(tk.END, chunk, current_tag or "")
            else:
                resolved: str | None = None
                for code in chunk.split(";"):
                    mapped = _ANSI_MAP.get(code)
                    if mapped == "reset":
                        resolved = None
                        break
                    if mapped:
                        resolved = mapped
                current_tag = resolved
        self._chat.configure(state=tk.DISABLED)
        self._chat.see(tk.END)

    # ─────────────────────────────────────────────────────────────
    #  Real-time output polling
    # ─────────────────────────────────────────────────────────────

    def _start_polling(self) -> None:
        self._root.after(self.POLL_MS, self._poll_output)

    def _poll_output(self) -> None:
        try:
            while True:
                self._append_ansi(self._out_q.get_nowait())
        except queue.Empty:
            pass
        self._root.after(self.POLL_MS, self._poll_output)

    # ─────────────────────────────────────────────────────────────
    #  Sidebar metrics (background thread → main-thread update)
    # ─────────────────────────────────────────────────────────────

    def _schedule_metrics(self) -> None:
        threading.Thread(target=self._fetch_metrics, daemon=True).start()
        self._root.after(self.METRICS_MS, self._schedule_metrics)

    def _fetch_metrics(self) -> None:
        if not _JARVIS_OK:
            return
        try:
            t = TelemetryAggregator()
            m = t.get_os_metrics()
            eng = ThreatReportEngine(t)
            label, _ = eng.compute_threat_level()
            self._root.after(0, lambda: self._apply_metrics(m, label))
        except Exception:
            pass

    def _apply_metrics(self, m: dict, threat_label: str) -> None:
        def _pct(v) -> float:
            try:
                return float(str(v).replace("%", "").strip())
            except Exception:
                return 0.0

        self._draw_bar("cpu",  _pct(m.get("cpu_percent",  0)), f'{m.get("cpu_percent",  "—")}%')
        self._draw_bar("mem",  _pct(m.get("mem_percent",  0)), f'{m.get("mem_percent",  "—")}%')
        self._draw_bar("disk", _pct(m.get("disk_percent", 0)), f'{m.get("disk_percent", "—")}%')
        self._uptime_var.set(str(m.get("uptime", "—"))[:20])
        self._procs_var.set(str(m.get("proc_count", "—")))

        self._threat_var.set(f"● {threat_label}")
        self._threat_lbl.configure(fg=THREAT_COLORS.get(threat_label, C["green"]))

    def _draw_bar(self, key: str, pct: float, label: str) -> None:
        self._metric_vars[key].set(label)
        cv   = self._bar_cvs[key]
        rect = self._bar_rects[key]
        cv.update_idletasks()
        w = cv.winfo_width()
        if w < 4:
            return
        filled = max(2, int(w * pct / 100))
        color  = C["red"] if pct >= 90 else (C["yellow"] if pct >= 70 else C["green"])
        cv.coords(rect, 0, 2, filled, 10)
        cv.itemconfigure(rect, fill=color)

    # ─────────────────────────────────────────────────────────────
    #  Command submission
    # ─────────────────────────────────────────────────────────────

    def _run_quick(self, cmd: str) -> None:
        self._input_var.set(cmd)
        self._submit()

    def _submit(self) -> None:
        raw = self._input_var.get().strip()
        if not raw or self._busy.is_set():
            return

        self._input_var.set("")
        self._history.append(raw)
        self._hist_idx = len(self._history)

        # Echo input line
        ts = datetime.now().strftime("%H:%M:%S")
        self._append(f"\n  [{ts}]  jarvis > ", "dim")
        self._append(raw + "\n", "input_echo")

        if not _JARVIS_OK:
            self._append("  JARVIS subsystem not available.\n", "red")
            return

        # Handle exit gracefully — only when typed, not from voice
        intent = parse_intent(raw)
        if intent == "cmd_exit":
            self._append(f"\n  Shutting down. Stay secure.\n", "green")
            self._root.after(1200, self._root.destroy)
            return

        # Dispatch in background thread
        self._busy.set()
        self._busy_var.set("  ⏳ thinking…")
        self._send_btn.configure(state=tk.DISABLED)
        self._start_spinner()
        threading.Thread(target=self._exec, args=(raw,), daemon=True).start()

    def _exec(self, raw: str) -> None:
        """Run command in background, capturing all stdout output."""
        cap = _StreamCapture(self._out_q)
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = cap
        sys.stderr = cap
        try:
            if self._core:
                self._core.dispatch(raw)
        except SystemExit:
            # SystemExit should only close the app when typed — never from voice
            pass
        except Exception as exc:
            self._out_q.put(f"\033[91m  ✗  Error: {exc}\n\033[0m")
        finally:
            sys.stdout = old_out
            sys.stderr = old_err
            self._root.after(0, self._on_done)

    def _on_done(self) -> None:
        self._busy.clear()
        self._stop_spinner()
        self._busy_var.set("")
        self._send_btn.configure(state=tk.NORMAL)
        self._entry.focus_set()
        # Refresh metrics immediately after a command completes
        threading.Thread(target=self._fetch_metrics, daemon=True).start()

    # ─────────────────────────────────────────────────────────────
    #  Spinner animation (title-bar flicker while busy)
    # ─────────────────────────────────────────────────────────────

    _SPIN_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _start_spinner(self) -> None:
        self._spinning = True
        self._spin_idx = 0
        self._tick_spinner()

    def _tick_spinner(self) -> None:
        if not self._spinning:
            return
        frame = self._SPIN_FRAMES[self._spin_idx % len(self._SPIN_FRAMES)]
        self._busy_var.set(f"  {frame} running…")
        self._spin_idx += 1
        self._root.after(80, self._tick_spinner)

    def _stop_spinner(self) -> None:
        self._spinning = False

    # ─────────────────────────────────────────────────────────────
    #  Voice toggle (🔊 / 🔇)
    # ─────────────────────────────────────────────────────────────

    def _toggle_voice(self) -> None:
        if not self._core or not self._core._voice:
            self._append("  Voice engine not available.\n", "yellow")
            return
        self._voice_enabled = not self._voice_enabled
        if self._voice_enabled:
            self._core._voice.unmute()
            self._voice_btn.configure(text=" 🔊 ", fg=C["green"])
            self._append("  Voice output enabled.\n", "green")
        else:
            self._core._voice.mute()
            self._voice_btn.configure(text=" 🔇 ", fg=C["dim"])
            self._append("  Voice output muted.\n", "dim")

    # ─────────────────────────────────────────────────────────────
    #  Mic toggle (🎤)
    # ─────────────────────────────────────────────────────────────

    def _toggle_mic(self) -> None:
        if not self._core:
            self._append("  JARVIS not ready yet.\n", "yellow")
            return
        if not self._mic_active:
            self._mic_active = True
            self._mic_btn.configure(fg=C["yellow"])
            self._append("  Calibrating microphone… please wait.\n", "yellow")
            threading.Thread(target=self._start_mic_bg, daemon=True).start()
        else:
            if self._core._ear:
                self._core._ear.stop()
                self._core._ear = None
            self._mic_active = False
            self._mic_btn.configure(fg=C["dim"])
            self._append("  Microphone deactivated.\n", "dim")

    def _start_mic_bg(self) -> None:
        """Create JarvisEar and start listening on a background thread."""
        try:
            from network_guardian.jarvis.jarvis_ear import JarvisEar, EarConfig
            mic_idx_str = os.environ.get("JARVIS_MIC_INDEX", "")
            try:
                mic_idx = int(mic_idx_str) if mic_idx_str else None
            except ValueError:
                mic_idx = None  # use system default microphone

            cfg = EarConfig()
            cfg.input_source = mic_idx
            cfg.language     = "en-US"

            ear = JarvisEar(cfg=cfg)
            self._core._ear = ear

            try:
                import speech_recognition as _sr
                mics = _sr.Microphone.list_microphone_names()
                if mic_idx is None:
                    mic_name = mics[0] if mics else "system default"
                else:
                    mic_name = mics[mic_idx] if mic_idx < len(mics) else f"device {mic_idx}"
            except Exception:
                mic_name = "system default" if mic_idx is None else f"device {mic_idx}"

            ear.start()
            self._root.after(0, lambda: self._on_mic_ready(mic_name))
        except Exception as exc:
            self._mic_active = False
            self._root.after(0, lambda: self._mic_btn.configure(fg=C["dim"]))
            self._root.after(0, lambda e=exc: self._append(
                f"  Mic error: {e}\n"
                "  Tip: grant Terminal microphone access in\n"
                "  System Settings → Privacy & Security → Microphone.\n",
                "red"
            ))

    def _on_mic_ready(self, mic_name: str) -> None:
        self._mic_btn.configure(fg=C["green"])
        self._append(
            f"  Microphone active — {mic_name}\n"
            "  Wake word: say \"Jarvis\" then your command.\n"
            "  Example: \"Jarvis situation\"  /  \"Jarvis show fleet\"\n"
            "  Tip: disable wake word by setting JARVIS_WAKE_WORD=off in .env\n",
            "green"
        )

    def _poll_mic_state(self) -> None:
        """Update mic button colour based on listening_state."""
        if self._core and self._core._ear and self._mic_active:
            try:
                state = self._core._ear.listening_state
                if state == "awake":
                    self._mic_btn.configure(fg=C["red"])
                elif state == "idle":
                    self._mic_btn.configure(fg=C["green"])
                else:
                    self._mic_btn.configure(fg=C["dim"])
            except Exception:
                pass
        self._root.after(400, self._poll_mic_state)

    # ─────────────────────────────────────────────────────────────
    #  Ear (microphone) polling thread
    # ─────────────────────────────────────────────────────────────

    def _start_ear_polling(self) -> None:
        """Launch background thread that feeds voice commands into the GUI."""
        threading.Thread(target=self._ear_poll_loop, daemon=True).start()

    def _ear_poll_loop(self) -> None:
        """Continuously poll ear queue; inject commands into the GUI safely."""
        while True:
            if (
                self._core
                and self._core._ear
                and self._mic_active
                and not self._busy.is_set()
            ):
                cmd = self._core._ear.get_command(timeout=0.1)
                if cmd:
                    self._root.after(0, lambda c=cmd: self._inject_voice_cmd(c))
            else:
                import time as _t; _t.sleep(0.1)

    def _inject_voice_cmd(self, cmd: str) -> None:
        """Inject a voice-recognised command into the input box and submit."""
        # Never allow voice to trigger exit — must be typed intentionally
        if parse_intent(cmd) == "cmd_exit":
            self._append(f"  🎤  Heard: \"{cmd}\" — exit blocked (type to confirm)\n", "yellow")
            return
        self._input_var.set(cmd)
        self._append(f"  🎤  Heard: \"{cmd}\"\n", "cyan")
        self._submit()

    # ─────────────────────────────────────────────────────────────
    #  History navigation (up/down arrows)
    # ─────────────────────────────────────────────────────────────

    def _hist_up(self) -> None:
        if self._history and self._hist_idx > 0:
            self._hist_idx -= 1
            self._input_var.set(self._history[self._hist_idx])
            self._entry.icursor(tk.END)

    def _hist_down(self) -> None:
        if self._hist_idx < len(self._history) - 1:
            self._hist_idx += 1
            self._input_var.set(self._history[self._hist_idx])
        else:
            self._hist_idx = len(self._history)
            self._input_var.set("")


# ══════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════

def _hsep(parent: tk.Misc, padx: int = 0, pady: int | tuple = 0) -> None:
    tk.Frame(parent, bg=C["border"], height=1).pack(
        fill=tk.X, padx=padx, pady=pady
    )


# ══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    try:
        # Tk 9.0 on macOS can return NaN from [tk scaling] when DPI is
        # unavailable, crashing tk.tcl before the window is fully initialised.
        # Force a safe 1.0 scaling value via the environment before creating
        # the root window so the Tcl bootstrap never evaluates NaN * 75.
        import os as _os
        if sys.platform == "darwin" and "TK_SCALING" not in _os.environ:
            _os.environ.setdefault("TK_SCALING", "1.0")
        root = tk.Tk()
        # Belt-and-suspenders: also set it at the Tcl level in case the
        # env var was not honoured by this Tk build.
        try:
            root.tk.call("tk", "scaling", "1.0")
        except Exception:
            pass
        app  = JarvisGUI(root)
        root.protocol("WM_DELETE_WINDOW", root.destroy)
        _log.info("Entering mainloop.")
        root.mainloop()
        _log.info("Mainloop exited cleanly.")
    except Exception:
        _log.critical("CRASH in main():\n%s", traceback.format_exc())
        raise


if __name__ == "__main__":
    main()
