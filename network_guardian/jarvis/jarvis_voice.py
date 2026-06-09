"""
╔══════════════════════════════════════════════════════════════════╗
║  jarvis_voice.py  |  Cross-Platform TTS Voice Engine            ║
╠══════════════════════════════════════════════════════════════════╣
║  Text-to-speech layer for Jarvis — macOS + Windows.             ║
║                                                                  ║
║  Engine priority chain:                                          ║
║    macOS:   say command (built-in, no extra deps)                ║
║    Windows: win32com.client → SpVoice COM object  (pywin32)      ║
║             PowerShell     → Add-Type SpeechSynthesizer shim     ║
║    All:     Silent mode    → No audio; logs a warning once       ║
║                                                                  ║
║  Features:                                                       ║
║    · Non-blocking async speech via threading.Thread             ║
║    · Voice profile selection (list / set by name fragment)       ║
║    · Rate (-10 … +10), Volume (0 … 100) control                 ║
║    · SSML-aware sanitiser strips terminal colour codes           ║
║    · Jarvis persona phrases baked-in for startup/shutdown/alerts ║
║    · Voice diagnostics CLI  (python jarvis_voice.py --diag)     ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import logging
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Optional

log = logging.getLogger("network_guardian.jarvis.voice")

# ══════════════════════════════════════════════════════════════════
# SAPI 5 DEFAULT CONFIGURATION
# ══════════════════════════════════════════════════════════════════

class VoiceConfig:
    """
    Tuneable defaults for the SAPI 5 engine.

    Attributes
    ----------
    rate        : Speech rate (-10 = slowest, 0 = normal, +10 = fastest).
                  Jarvis persona sounds best between -1 and +1.
    volume      : Output volume (0 – 100).
    async_speak : If True, speech runs in a background thread so the
                  terminal prompt returns immediately.
    voice_hint  : Case-insensitive substring to match a preferred voice.
                  Windows examples: "David", "Zira", "Mark".
                  macOS examples:   "Samantha", "Alex", "Karen".
                  Set to "" to use the system default voice.
    """
    rate:        int   = 0
    volume:      int   = 90
    async_speak: bool  = True
    voice_hint:  str   = ""               # "" = system default; "David" (Windows), "Samantha" (macOS)


# ══════════════════════════════════════════════════════════════════
# JARVIS PERSONA SCRIPT  (spoken lines)
# ══════════════════════════════════════════════════════════════════

class JarvisScript:
    """Pre-written spoken lines for key Jarvis events."""

    STARTUP = (
        "J.A.R.V.I.S. online. "
        "All Network Guardian subsystems are standing by."
    )
    SHUTDOWN = (
        "Shutting down. "
        "Defensive perimeter holding. Stay secure."
    )
    DEFENSES_ON = (
        "Activating Network Guardian. "
        "Firewall, intrusion detection, and fleet monitoring are now live."
    )
    DEFENSES_OFF = (
        "Network Guardian subsystems halted. "
        "Passive monitoring only."
    )
    SITUATION_INTRO = (
        "Running full situation assessment. "
        "Compiling threat intelligence now."
    )
    THREAT_NOMINAL  = "All systems nominal. No active threats detected."
    THREAT_ELEVATED = "Threat level elevated. Recommend reviewing the latest report."
    THREAT_HIGH     = "Warning. High threat level confirmed. Immediate review advised."
    THREAT_CRITICAL = (
        "Alert. Critical threat level detected. "
        "Recommend immediate containment procedures."
    )
    UNKNOWN_INTENT  = "Command not recognised. Please try again."
    FLEET_REPORT    = "Retrieving fleet intelligence. Stand by."
    FIREWALL_REPORT = "Accessing firewall logs and injection history."
    LATERAL_REPORT  = "Scanning for lateral movement activity."
    METRICS_REPORT  = "Sampling system resource telemetry."

    @staticmethod
    def threat_line(label: str) -> str:
        """Return the threat announcement line for a given label."""
        mapping = {
            "NOMINAL":   JarvisScript.THREAT_NOMINAL,
            "ELEVATED":  JarvisScript.THREAT_ELEVATED,
            "HIGH":      JarvisScript.THREAT_HIGH,
            "CRITICAL":  JarvisScript.THREAT_CRITICAL,
        }
        return mapping.get(label.upper(), JarvisScript.THREAT_ELEVATED)


# ══════════════════════════════════════════════════════════════════
# SAPI 5 ENGINE BACKENDS
# ══════════════════════════════════════════════════════════════════

class _Win32ComBackend:
    """
    Primary backend: win32com.client wrapping the SAPI SpVoice COM object.

    Requires: pip install pywin32
    """

    def __init__(self, cfg: VoiceConfig) -> None:
        import win32com.client                           # noqa: F401 (import test)
        self._cfg = cfg
        self._voice = None
        self._lock  = threading.Lock()
        self._init_voice()

    def _init_voice(self) -> None:
        import win32com.client
        v = win32com.client.Dispatch("SAPI.SpVoice")
        v.Rate   = self._cfg.rate
        v.Volume = self._cfg.volume

        # Voice selection ─────────────────────────────────────────
        if self._cfg.voice_hint:
            token_cat = win32com.client.Dispatch("SAPI.SpObjectTokenCategory")
            token_cat.SetId(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices", False)
            tokens = token_cat.EnumerateTokens()
            for i in range(tokens.Count):
                token = tokens.Item(i)
                name  = token.GetDescription()
                if self._cfg.voice_hint.lower() in name.lower():
                    v.Voice = token
                    log.debug("SAPI voice selected: %s", name)
                    break

        self._voice = v

    def speak(self, text: str) -> None:
        """Speak synchronously (caller manages threading)."""
        clean = _strip_ansi(text)
        with self._lock:
            # SVSFlagsAsync=1 | SVSFPurgeBeforeSpeak=2 — speak async at COM level
            # We use SVSFDefault=0 here because our own thread handles async.
            self._voice.Speak(clean, 0)

    def list_voices(self) -> list[str]:
        import win32com.client
        cat    = win32com.client.Dispatch("SAPI.SpObjectTokenCategory")
        cat.SetId(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices", False)
        tokens = cat.EnumerateTokens()
        return [tokens.Item(i).GetDescription() for i in range(tokens.Count)]

    def set_rate(self, rate: int) -> None:
        self._voice.Rate = max(-10, min(10, rate))

    def set_volume(self, vol: int) -> None:
        self._voice.Volume = max(0, min(100, vol))


class _PowerShellBackend:
    """
    Fallback backend: PowerShell Add-Type SpeechSynthesizer.

    Works on any Windows machine with .NET 3.5+ and no extra pip packages.
    Slightly higher latency (~300 ms) due to PS startup cost.
    """

    _PS_TEMPLATE = (
        "Add-Type -AssemblyName System.Speech; "
        "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
        "$s.Rate = {rate}; "
        "$s.Volume = {volume}; "
        "{voice_line}"
        "$s.Speak('{text}');"
    )

    def __init__(self, cfg: VoiceConfig) -> None:
        self._cfg = cfg
        _check_powershell()

    def speak(self, text: str) -> None:
        clean = _strip_ansi(text).replace("'", "")   # PS single-quote escape
        voice_line = ""
        if self._cfg.voice_hint:
            voice_line = (
                f"try {{ $s.SelectVoiceByHints('{self._cfg.voice_hint}') }} "
                f"catch {{}}; "
            )
        script = self._PS_TEMPLATE.format(
            rate=self._cfg.rate,
            volume=self._cfg.volume,
            voice_line=voice_line,
            text=clean,
        )
        subprocess.run(
            ["powershell", "-WindowStyle", "Hidden", "-Command", script],
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )

    def list_voices(self) -> list[str]:
        script = (
            "Add-Type -AssemblyName System.Speech; "
            "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
            "$s.GetInstalledVoices() | ForEach-Object { $_.VoiceInfo.Name }"
        )
        result = subprocess.run(
            ["powershell", "-WindowStyle", "Hidden", "-Command", script],
            capture_output=True, text=True, check=False,
        )
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]

    def set_rate(self, rate: int) -> None:
        self._cfg.rate = max(-10, min(10, rate))

    def set_volume(self, vol: int) -> None:
        self._cfg.volume = max(0, min(100, vol))


class _SilentBackend:
    """
    No-op backend used when no audio engine is available.
    Logs a one-time warning so the user knows why there is no voice.
    """

    _warned = False

    def __init__(self) -> None:
        if not _SilentBackend._warned:
            log.warning(
                "Jarvis voice is SILENT — no TTS backend available. "
                "macOS: 'say' must be in PATH. "
                "Windows: install pywin32 (`pip install pywin32`) for voice support."
            )
            _SilentBackend._warned = True

    def speak(self, _text: str) -> None:
        pass

    def list_voices(self) -> list[str]:
        return []

    def set_rate(self, _rate: int) -> None:
        pass

    def set_volume(self, _vol: int) -> None:
        pass


# ══════════════════════════════════════════════════════════════════
# macOS BACKEND  (built-in 'say' command — no extra dependencies)
# ══════════════════════════════════════════════════════════════════

def _check_say() -> None:
    """Raise RuntimeError if the macOS 'say' command is not in PATH."""
    if not shutil.which("say"):
        raise RuntimeError("macOS 'say' command not found in PATH.")


class _MacOSSayBackend:
    """
    macOS TTS backend using the built-in 'say' command.
    Available on all modern macOS versions with no extra pip packages.
    Rate is mapped from SAPI-style (-10…+10) to words-per-minute (100…300).
    """

    def __init__(self, cfg: VoiceConfig) -> None:
        _check_say()   # raises if unavailable
        self._cfg = cfg
        log.info("Voice engine: macOS 'say' backend active.")

    def speak(self, text: str) -> None:
        clean = _strip_ansi(text)
        cmd = ["say"]
        if self._cfg.voice_hint:
            cmd += ["-v", self._cfg.voice_hint]
        # Map SAPI rate (-10…+10) → wpm (100…300); macOS default is 175 wpm
        wpm = max(100, min(300, 175 + self._cfg.rate * 9))
        cmd += ["-r", str(int(wpm)), clean]
        subprocess.run(cmd, check=False, timeout=60)

    def list_voices(self) -> list[str]:
        try:
            result = subprocess.run(
                ["say", "-v", "?"],
                capture_output=True, text=True, check=False,
            )
            return [line.split()[0] for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def set_rate(self, rate: int) -> None:
        self._cfg.rate = max(-10, min(10, rate))

    def set_volume(self, vol: int) -> None:
        # macOS 'say' has no native volume flag; store for reference only
        self._cfg.volume = max(0, min(100, vol))


# ══════════════════════════════════════════════════════════════════
# ENGINE FACTORY
# ══════════════════════════════════════════════════════════════════

def _build_backend(cfg: VoiceConfig):
    """
    Attempt to construct the best available backend.

    Priority (macOS):   say → Silent
    Priority (Windows): win32com → PowerShell → Silent
    """
    # ── macOS: use built-in 'say' command ─────────────────────────
    if sys.platform == "darwin":
        try:
            return _MacOSSayBackend(cfg)
        except Exception as exc:
            log.debug("macOS say backend unavailable: %s", exc)
        return _SilentBackend()

    # ── Windows: SAPI 5 via win32com or PowerShell ─────────────────
    # ── 1. win32com (pywin32) ─────────────────────────────────────
    try:
        backend = _Win32ComBackend(cfg)
        log.info("SAPI 5 engine: win32com backend active.")
        return backend
    except Exception as exc:
        log.debug("win32com unavailable: %s", exc)

    # ── 2. PowerShell ─────────────────────────────────────────────
    try:
        backend = _PowerShellBackend(cfg)
        log.info("SAPI 5 engine: PowerShell backend active.")
        return backend
    except Exception as exc:
        log.debug("PowerShell backend unavailable: %s", exc)

    # ── 3. Silent ─────────────────────────────────────────────────
    return _SilentBackend()


# ══════════════════════════════════════════════════════════════════
# MAIN VOICE ENGINE  (public API)
# ══════════════════════════════════════════════════════════════════

class JarvisVoice:
    """
    Thread-safe, async-capable SAPI 5 voice engine.

    Usage
    -----
        voice = JarvisVoice()
        voice.say("Initialising systems.")         # async by default
        voice.say("Alert.", blocking=True)         # wait for finish
        voice.say_event("STARTUP")                 # speak a persona line
        voice.shutdown()                           # flush queue and stop
    """

    def __init__(self, cfg: Optional[VoiceConfig] = None) -> None:
        self._cfg     = cfg or VoiceConfig()
        self._backend = _build_backend(self._cfg)
        self._queue: queue.Queue[Optional[str]] = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._enabled = True

        if self._cfg.async_speak:
            self._start_worker()

    # ── Public methods ────────────────────────────────────────────

    def say(self, text: str, blocking: bool = False) -> None:
        """
        Speak `text`.

        Parameters
        ----------
        text     : The string to speak (ANSI codes are stripped automatically).
        blocking : If True, wait until the utterance finishes before returning.
                   Ignored when async_speak=False in the config.
        """
        if not self._enabled or not text.strip():
            return

        if self._cfg.async_speak and not blocking:
            self._queue.put(text)
        else:
            self._backend.speak(text)

    def say_event(self, event_key: str) -> None:
        """
        Speak a baked-in Jarvis persona line by event key.

        Keys: STARTUP | SHUTDOWN | DEFENSES_ON | DEFENSES_OFF |
              SITUATION_INTRO | UNKNOWN_INTENT | FLEET_REPORT |
              FIREWALL_REPORT | LATERAL_REPORT | METRICS_REPORT
        """
        line = getattr(JarvisScript, event_key.upper(), None)
        if line:
            self.say(line)

    def say_threat(self, label: str) -> None:
        """Speak the appropriate threat-level announcement."""
        self.say(JarvisScript.threat_line(label))

    def list_voices(self) -> list[str]:
        """Return all installed SAPI 5 voice names."""
        return self._backend.list_voices()

    def set_voice(self, hint: str) -> None:
        """
        Switch to a different voice by name fragment.

        Rebuilds the backend to apply the change — call before heavy usage.
        """
        self._flush()
        self._cfg.voice_hint = hint
        self._backend = _build_backend(self._cfg)
        if self._cfg.async_speak:
            self._start_worker()

    def set_rate(self, rate: int) -> None:
        """Set speech rate (-10 … +10)."""
        self._backend.set_rate(rate)

    def set_volume(self, volume: int) -> None:
        """Set volume (0 … 100)."""
        self._backend.set_volume(volume)

    def mute(self) -> None:
        """Silence voice output (text output continues)."""
        self._enabled = False

    def unmute(self) -> None:
        """Re-enable voice output."""
        self._enabled = True

    def shutdown(self) -> None:
        """Flush the speech queue and terminate the worker thread."""
        self._flush()
        if self._thread and self._thread.is_alive():
            self._queue.put(None)           # sentinel → worker exits
            self._thread.join(timeout=5)
        log.debug("JarvisVoice shutdown complete.")

    # ── Internal ──────────────────────────────────────────────────

    def _start_worker(self) -> None:
        """Spawn or restart the speech worker thread."""
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._worker_loop,
            name="jarvis-voice-worker",
            daemon=True,
        )
        self._thread.start()

    def _worker_loop(self) -> None:
        """Drain the speech queue sequentially in a background thread.

        On Windows: The COM SpVoice object MUST be created on the same thread
        that calls Speak(). We initialise COM here and rebuild the win32com
        backend so the COM object is owned by this thread.
        On macOS: The 'say' backend is subprocess-based and thread-safe;
        no re-initialisation is needed.
        """
        # 1. Windows only: initialise COM apartment for this thread and
        #    rebuild the win32com backend so the COM object is thread-local.
        if sys.platform == "win32":
            try:
                import pythoncom
                pythoncom.CoInitialize()
            except Exception as exc:
                log.debug("CoInitialize skipped: %s", exc)

            try:
                if not isinstance(self._backend, _SilentBackend):
                    new_backend = _Win32ComBackend(self._cfg)
                    self._backend = new_backend
                    log.debug("win32com backend rebuilt on voice-worker thread.")
            except Exception as exc:
                log.warning("win32com rebuild failed on worker thread (%s) — using PowerShell.", exc)
                try:
                    self._backend = _PowerShellBackend(self._cfg)
                    log.info("Voice worker falling back to PowerShell backend.")
                except Exception as exc2:
                    log.error("PowerShell backend also unavailable: %s — voice will be silent.", exc2)
                    self._backend = _SilentBackend()

        # 3. Drain queue.
        while True:
            item = self._queue.get()
            if item is None:            # shutdown sentinel
                break
            try:
                self._backend.speak(item)
            except Exception as exc:
                log.error("Speech worker error: %s", exc)
            finally:
                self._queue.task_done()

    def _flush(self) -> None:
        """Block until the speech queue is empty."""
        self._queue.join()


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences so SAPI never speaks control codes."""
    return _ANSI_RE.sub("", text)


def _check_powershell() -> None:
    """Raise RuntimeError if PowerShell is not accessible."""
    result = subprocess.run(
        ["powershell", "-Command", "echo ok"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0 or "ok" not in result.stdout:
        raise RuntimeError("PowerShell unavailable.")


# ══════════════════════════════════════════════════════════════════
# DIAGNOSTICS CLI
# ══════════════════════════════════════════════════════════════════

def _run_diagnostics(cfg: VoiceConfig) -> None:
    """Interactive diagnostics — python jarvis_voice.py --diag"""
    print("\n── JARVIS VOICE DIAGNOSTICS ──\n")

    voice = JarvisVoice(cfg)

    print("Installed SAPI 5 voices:")
    voices = voice.list_voices()
    if voices:
        for i, v in enumerate(voices, 1):
            marker = " ◄ active" if cfg.voice_hint.lower() in v.lower() else ""
            print(f"  {i:2}.  {v}{marker}")
    else:
        print("  (none found — voice system may be silent)")

    print(f"\nActive backend : {type(voice._backend).__name__}")
    print(f"Rate           : {cfg.rate}")
    print(f"Volume         : {cfg.volume}")
    print(f"Voice hint     : '{cfg.voice_hint}'")

    print("\nSpeaking startup phrase …")
    voice.say(JarvisScript.STARTUP, blocking=True)
    time.sleep(0.5)

    print("Speaking threat levels …")
    for label in ("NOMINAL", "ELEVATED", "HIGH", "CRITICAL"):
        print(f"  [{label}]")
        voice.say(JarvisScript.threat_line(label), blocking=True)
        time.sleep(0.3)

    voice.shutdown()
    print("\nDiagnostics complete.\n")


# ══════════════════════════════════════════════════════════════════
# ENTRY POINT  (standalone diagnostics)
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(message)s")

    parser = argparse.ArgumentParser(description="Jarvis SAPI 5 Voice Engine")
    parser.add_argument("--diag",   action="store_true", help="Run full voice diagnostics")
    parser.add_argument("--say",    type=str, default="", help="Speak a custom string and exit")
    parser.add_argument("--rate",   type=int, default=VoiceConfig.rate,   help="Speech rate (-10…+10)")
    parser.add_argument("--volume", type=int, default=VoiceConfig.volume, help="Volume (0…100)")
    parser.add_argument("--voice",  type=str, default=VoiceConfig.voice_hint, help="Voice name hint")
    args = parser.parse_args()

    cfg = VoiceConfig()
    cfg.rate        = args.rate
    cfg.volume      = args.volume
    cfg.voice_hint  = args.voice
    cfg.async_speak = False        # use blocking mode for standalone runs

    if args.diag:
        _run_diagnostics(cfg)
    elif args.say:
        v = JarvisVoice(cfg)
        v.say(args.say, blocking=True)
        v.shutdown()
    else:
        parser.print_help()
