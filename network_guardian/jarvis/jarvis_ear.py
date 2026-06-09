"""
╔══════════════════════════════════════════════════════════════════╗
║  jarvis_ear.py  |  Speech Recognition + Voice Input Engine      ║
╠══════════════════════════════════════════════════════════════════╣
║  Listens to the microphone, transcribes speech, feeds the       ║
║  transcribed text directly into the Jarvis REPL command loop.   ║
║                                                                  ║
║  Recognition backend priority chain:                            ║
║    1. SAPI 5 SpInprocRecognizer  (win32com / offline, best)     ║
║    2. SpeechRecognition + Vosk   (offline, no internet needed)  ║
║    3. SpeechRecognition + Google (online, fallback)             ║
║    4. Deaf mode                  (mic unavailable — graceful)   ║
║                                                                  ║
║  Features:                                                       ║
║    · Wake-word gating   — listens only after "Hey Jarvis"       ║
║    · Ambient noise auto-calibration on startup                  ║
║    · Transcription echo — prints exactly what was heard         ║
║    · Energy + phrase timeout tuning per environment             ║
║    · Thread-safe result queue → injects into REPL               ║
║    · Diagnostics CLI  (python jarvis_ear.py --diag)             ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import logging
import os
import queue
import sys
import threading
import time
from typing import Callable, Optional

log = logging.getLogger("network_guardian.jarvis.ear")

# ══════════════════════════════════════════════════════════════════
# RECOGNITION CONFIGURATION
# ══════════════════════════════════════════════════════════════════

class EarConfig:
    """
    Tunable parameters for the speech recognition engine.

    Attributes
    ----------
    wake_word           : Phrase Jarvis listens for before acting.
                          Set to "" to disable wake-word gating
                          (every utterance is treated as a command).
    wake_word_enabled   : Master switch for wake-word gating.
    calibration_secs    : Seconds to sample ambient noise on startup.
    phrase_timeout      : Max seconds of silence before utterance ends.
    listen_timeout      : Seconds to wait for speech to begin (None = forever).
    energy_threshold    : Minimum mic energy level to consider as speech.
                          0 = auto-calibrate (recommended).
    dynamic_energy      : Let SpeechRecognition auto-adjust energy threshold.
    language            : BCP-47 tag used by Google backend.  e.g. "en-IN".
    vosk_model_path     : Path to a local Vosk model folder.
                          Download from https://alphacephei.com/vosk/models
                          e.g. C:\\vosk-models\\vosk-model-small-en-us-0.15
    input_source        : "mic_index" of the input device (None = default).
    """
    wake_word:          str   = "jarvis"
    wake_word_enabled:  bool  = True
    calibration_secs:   float = 1.5
    phrase_timeout:     float = 2.0
    listen_timeout:     Optional[float] = None
    energy_threshold:   int   = 0          # 0 = auto
    dynamic_energy:     bool  = True
    language:           str   = "en-US"
    vosk_model_path:    str   = ""
    input_source:       Optional[int] = None


# ══════════════════════════════════════════════════════════════════
# RECOGNITION BACKENDS
# ══════════════════════════════════════════════════════════════════

class _SpeechRecognitionBackend:
    """
    Universal backend using the 'SpeechRecognition' PyPI package.

    Sub-engine selection (in order):
        1. Vosk offline engine if vosk_model_path is valid
        2. Google Web Speech API (requires internet)

    pip install SpeechRecognition pyaudio vosk
    """

    def __init__(self, cfg: EarConfig) -> None:
        import speech_recognition as sr
        self._sr  = sr
        self._cfg = cfg
        self._rec = sr.Recognizer()

        # Apply energy settings
        if cfg.energy_threshold > 0:
            self._rec.energy_threshold = cfg.energy_threshold
        self._rec.dynamic_energy_threshold = cfg.dynamic_energy
        self._rec.pause_threshold = cfg.phrase_timeout

        # Vosk model probe
        self._vosk_model = None
        if cfg.vosk_model_path:
            self._vosk_model = self._load_vosk(cfg.vosk_model_path)

        log.info(
            "SpeechRecognition backend: %s",
            "Vosk (offline)" if self._vosk_model else "Google (online)"
        )

    def _load_vosk(self, path: str):
        """Attempt to load a Vosk model; return None on failure."""
        try:
            from vosk import Model
            import os
            if not os.path.isdir(path):
                log.warning("Vosk model path not found: %s — falling back to Google.", path)
                return None
            model = Model(path)
            log.info("Vosk model loaded from: %s", path)
            return model
        except ImportError:
            log.debug("vosk not installed — using Google backend.")
            return None
        except Exception as exc:
            log.warning("Vosk model load failed: %s", exc)
            return None

    def calibrate(self, duration: float) -> None:
        """Adjust for ambient noise."""
        sr = self._sr
        try:
            with sr.Microphone() as source:
                print(f"  [EAR] Calibrating microphone for {duration}s …")
                self._rec.adjust_for_ambient_noise(source, duration=duration)
                print(f"  [EAR] Energy threshold set to {self._rec.energy_threshold:.0f}")
        except Exception as exc:
            log.warning("Calibration failed: %s", exc)

    def listen_once(self) -> Optional[str]:
        """
        Block until one utterance is captured and return its text,
        or return None on timeout / recognition failure.
        """
        sr  = self._sr
        cfg = self._cfg
        try:
            mic_kwargs = {}
            if cfg.input_source is not None:
                mic_kwargs["device_index"] = cfg.input_source

            with sr.Microphone(**mic_kwargs) as source:
                audio = self._rec.listen(
                    source,
                    timeout=cfg.listen_timeout,
                    phrase_time_limit=30,
                )

            # ── Vosk offline ──────────────────────────────────────
            if self._vosk_model:
                return self._recognize_vosk(audio)

            # ── Google online ─────────────────────────────────────
            return self._recognize_google(audio)

        except sr.WaitTimeoutError:
            return None
        except sr.UnknownValueError:
            return None
        except sr.RequestError as exc:
            log.error("Speech API request error: %s", exc)
            return None
        except OSError as exc:
            log.error("Microphone error: %s", exc)
            return None

    def _recognize_vosk(self, audio) -> Optional[str]:
        """Transcribe using Vosk offline engine."""
        try:
            from vosk import KaldiRecognizer
            import json
            raw_wav = audio.get_wav_data(convert_rate=16000)
            rec     = KaldiRecognizer(self._vosk_model, 16000)
            rec.AcceptWaveform(raw_wav)
            result  = json.loads(rec.FinalResult())
            text    = result.get("text", "").strip()
            return text if text else None
        except Exception as exc:
            log.error("Vosk recognition error: %s", exc)
            return None

    def _recognize_google(self, audio) -> Optional[str]:
        """Transcribe using Google Web Speech API."""
        try:
            text = self._rec.recognize_google(audio, language=self._cfg.language)
            return text.strip() if text else None
        except self._sr.UnknownValueError:
            return None
        except self._sr.RequestError as exc:
            log.error("Google API error: %s", exc)
            return None

    def list_microphones(self) -> list[str]:
        """Return all available microphone names."""
        try:
            return self._sr.Microphone.list_microphone_names()
        except Exception:
            return []


class _DeafBackend:
    """
    No-op backend when no audio input is available.
    Logs a one-time warning.
    """
    _warned = False

    def __init__(self) -> None:
        if not _DeafBackend._warned:
            log.warning(
                "Jarvis microphone input is UNAVAILABLE. "
                "Install: pip install SpeechRecognition pyaudio"
            )
            _DeafBackend._warned = True

    def calibrate(self, _duration: float) -> None:
        pass

    def listen_once(self) -> Optional[str]:
        time.sleep(0.5)
        return None

    def list_microphones(self) -> list[str]:
        return []


# ══════════════════════════════════════════════════════════════════
# BACKEND FACTORY
# ══════════════════════════════════════════════════════════════════

def _build_ear_backend(cfg: EarConfig):
    """Construct the best available recognition backend."""

    # ── SpeechRecognition (covers Vosk + Google) ──────────────────
    try:
        backend = _SpeechRecognitionBackend(cfg)
        return backend
    except Exception as exc:
        log.debug("SpeechRecognition backend unavailable: %s", exc)

    # ── Deaf fallback ─────────────────────────────────────────────
    return _DeafBackend()


# ══════════════════════════════════════════════════════════════════
# WAKE-WORD DETECTOR
# ══════════════════════════════════════════════════════════════════

class WakeWordDetector:
    """
    Simple substring wake-word detector.

    Scans the raw transcript for the configured wake-word phrase,
    then strips it out and returns the remainder as the clean command.

    Parameters
    ----------
    wake_word : The trigger phrase (case-insensitive).
    """

    def __init__(self, wake_word: str) -> None:
        self._wake = wake_word.lower().strip()

    def contains_wake(self, text: str) -> bool:
        """Return True if the wake-word appears in `text`."""
        return self._wake in text.lower()

    def strip_wake(self, text: str) -> str:
        """
        Remove the wake-word (and any leading/trailing whitespace)
        from the transcript, returning the clean command portion.
        """
        lower = text.lower()
        idx   = lower.find(self._wake)
        if idx == -1:
            return text.strip()
        after = text[idx + len(self._wake):].strip()
        # Strip common filler words that follow the wake phrase
        for filler in ("please", "can you", "i need", "i want"):
            if after.lower().startswith(filler):
                after = after[len(filler):].strip()
        return after


# ══════════════════════════════════════════════════════════════════
# JARVIS EAR  (public API)
# ══════════════════════════════════════════════════════════════════

class JarvisEar:
    """
    Thread-safe, non-blocking speech recognition engine.

    Runs a dedicated listener thread that continuously captures
    microphone audio, transcribes it, applies wake-word filtering,
    and places clean command strings into a thread-safe queue.

    The REPL loop polls `get_command()` each iteration — zero
    blocking on the main thread.

    Usage
    -----
        ear = JarvisEar(on_transcript=my_callback)
        ear.start()
        # ... in REPL loop:
        cmd = ear.get_command(timeout=0.05)
        if cmd:
            dispatch(cmd)
        ear.stop()
    """

    def __init__(
        self,
        cfg: Optional[EarConfig] = None,
        on_transcript: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        """
        Parameters
        ----------
        cfg           : EarConfig instance (uses defaults if None).
        on_transcript : Optional callback invoked on every successful
                        transcription BEFORE wake-word filtering.
                        Signature: on_transcript(raw_text, clean_command)
                        where clean_command is "" if wake-word not matched.
        """
        self._cfg          = cfg or EarConfig()

        # Allow JARVIS_WAKE_WORD env var to override config at runtime.
        # Set to "off" or "" in .env to disable wake-word gating entirely
        # (every utterance is treated as a command).
        _ww_env = os.environ.get("JARVIS_WAKE_WORD", "")
        if _ww_env.lower() in ("off", "false", "0", "disabled", "none"):
            self._cfg.wake_word_enabled = False
            log.info("Wake-word gating DISABLED via JARVIS_WAKE_WORD env var.")
        elif _ww_env:
            self._cfg.wake_word = _ww_env
            log.info("Wake word set to '%s' via JARVIS_WAKE_WORD env var.", _ww_env)

        self._backend      = _build_ear_backend(self._cfg)
        self._wake         = WakeWordDetector(self._cfg.wake_word)
        self._on_transcript = on_transcript
        self._cmd_queue: queue.Queue[str] = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._running      = threading.Event()
        self._is_deaf      = isinstance(self._backend, _DeafBackend)
        self._listening_state = "idle"   # "idle" | "awake" | "deaf"

    # ── Public API ────────────────────────────────────────────────

    def start(self) -> None:
        """
        Calibrate the microphone and start the listener thread.
        Returns immediately — recognition runs in the background.
        """
        if self._is_deaf:
            self._listening_state = "deaf"
            return

        self._backend.calibrate(self._cfg.calibration_secs)
        self._running.set()
        self._thread = threading.Thread(
            target=self._listener_loop,
            name="jarvis-ear-listener",
            daemon=True,
        )
        self._thread.start()
        self._listening_state = (
            "idle" if self._cfg.wake_word_enabled else "awake"
        )
        log.info(
            "JarvisEar started. Wake-word gating: %s  (%r)",
            self._cfg.wake_word_enabled,
            self._cfg.wake_word,
        )

    def stop(self) -> None:
        """Gracefully stop the listener thread."""
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        log.info("JarvisEar stopped.")

    def get_command(self, timeout: float = 0.05) -> Optional[str]:
        """
        Non-blocking poll for a recognised command.

        Returns the clean command string or None if nothing is ready.
        Use in the REPL main loop.
        """
        try:
            return self._cmd_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    @property
    def is_available(self) -> bool:
        """True if a working microphone backend was found."""
        return not self._is_deaf

    @property
    def listening_state(self) -> str:
        """Current state: 'idle' | 'awake' | 'deaf'."""
        return self._listening_state

    def list_microphones(self) -> list[str]:
        """Return all detected input device names."""
        return self._backend.list_microphones()

    # ── Listener thread ───────────────────────────────────────────

    def _listener_loop(self) -> None:
        """
        Continuously listen → transcribe → filter → enqueue.

        Wake-word flow:
            IDLE  :  listens but only enqueues if wake-word heard
            AWAKE :  every utterance is treated as a command

        When wake_word_enabled=False the state is permanently AWAKE.
        """
        while self._running.is_set():
            raw = self._backend.listen_once()
            if not raw:
                continue

            raw_clean = raw.strip().lower()
            log.debug("Raw transcript: %r", raw_clean)

            # ── Wake-word disabled — pass everything through ──────
            if not self._cfg.wake_word_enabled:
                self._emit(raw_clean, raw_clean)
                continue

            # ── IDLE: wait for wake-word ──────────────────────────
            if self._listening_state == "idle":
                if self._wake.contains_wake(raw_clean):
                    cmd = self._wake.strip_wake(raw_clean)
                    self._listening_state = "awake"
                    if cmd:
                        # Command arrived in the same utterance as wake-word
                        self._emit(raw_clean, cmd)
                    else:
                        # Only wake-word heard; wait for next utterance
                        self._emit(raw_clean, "")
                # else: ignore — wake-word not heard
                continue

            # ── AWAKE: treat utterance as command ─────────────────
            if self._listening_state == "awake":
                # Reset to idle after each command so user must re-trigger
                # Disable the reset if you want persistent voice mode:
                self._listening_state = "idle"
                self._emit(raw_clean, raw_clean)

    def _emit(self, raw: str, command: str) -> None:
        """
        Invoke the on_transcript callback and enqueue the command.

        Parameters
        ----------
        raw     : The unfiltered transcription.
        command : The cleaned command (empty string = wake-word only).
        """
        if self._on_transcript:
            try:
                self._on_transcript(raw, command)
            except Exception as exc:
                log.error("on_transcript callback error: %s", exc)

        if command:
            self._cmd_queue.put(command)


# ══════════════════════════════════════════════════════════════════
# TRANSCRIPT DISPLAY HELPER  (used by jarvis_core)
# ══════════════════════════════════════════════════════════════════

def make_transcript_callback(
    print_fn: Callable[[str, str], None],
    say_fn:   Callable[[str], None],
) -> Callable[[str, str], None]:
    """
    Build a callback that:
      1. Echoes the raw transcript to the terminal via print_fn
      2. Speaks a confirmation via say_fn when a valid command is parsed

    Parameters
    ----------
    print_fn : jarvis_say-compatible function(msg, level)
    say_fn   : _say-compatible function(text)

    Returns
    -------
    Callable[[raw, command], None]
    """
    def _callback(raw: str, command: str) -> None:
        if not raw:
            return
        # Echo raw transcript
        print_fn(f"[MIC] Heard: \"{raw}\"", "data")
        if command and command != raw:
            print_fn(f"[MIC] Command: \"{command}\"", "info")
        elif not command:
            # Wake-word heard but no command yet
            print_fn("[MIC] Wake-word detected — listening for command…", "ok")
            import os as _os
            _op = _os.environ.get("JARVIS_OPERATOR", "sir")
            say_fn(f"Yes, {_op}?")

    return _callback


# ══════════════════════════════════════════════════════════════════
# DIAGNOSTICS CLI
# ══════════════════════════════════════════════════════════════════

def _run_ear_diagnostics(cfg: EarConfig) -> None:
    """Standalone mic test: python jarvis_ear.py --diag"""
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(message)s")
    print("\n── JARVIS EAR DIAGNOSTICS ──\n")

    backend = _build_ear_backend(cfg)

    print("Available microphones:")
    mics = backend.list_microphones()
    if mics:
        for i, m in enumerate(mics):
            marker = " ◄ default" if i == 0 else ""
            print(f"  {i:2}.  {m}{marker}")
    else:
        print("  (none detected)")

    if isinstance(backend, _DeafBackend):
        print("\n  Microphone UNAVAILABLE — install pyaudio and SpeechRecognition.")
        return

    backend.calibrate(cfg.calibration_secs)

    print(f"\nWake-word  : {'\"' + cfg.wake_word + '\"' if cfg.wake_word_enabled else 'DISABLED'}")
    print(f"Language   : {cfg.language}")
    print(f"Backend    : {type(backend).__name__}")

    print("\nListening for 3 utterances. Speak now …\n")
    ear = JarvisEar(cfg)
    results = []

    def _cb(raw, cmd):
        results.append((raw, cmd))

    ear._on_transcript = _cb
    ear.start()

    for i in range(3):
        print(f"  Utterance {i+1}/3 — waiting …")
        cmd = None
        deadline = time.time() + 15
        while cmd is None and time.time() < deadline:
            cmd = ear.get_command(timeout=0.1)
        if cmd:
            print(f"    ✓ Heard    : \"{results[-1][0]}\"")
            print(f"      Command  : \"{cmd}\"\n")
        else:
            print("    ✗ Timeout — nothing heard.\n")

    ear.stop()
    print("Diagnostics complete.\n")


# ══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jarvis Speech Recognition Engine")
    parser.add_argument("--diag",     action="store_true",
                        help="Run full microphone diagnostics")
    parser.add_argument("--no-wake",  action="store_true",
                        help="Disable wake-word gating (every utterance is a command)")
    parser.add_argument("--wake",     type=str, default=EarConfig.wake_word,
                        help="Override wake-word phrase")
    parser.add_argument("--lang",     type=str, default=EarConfig.language,
                        help="Recognition language (BCP-47, e.g. en-IN)")
    parser.add_argument("--vosk",     type=str, default="",
                        help="Path to local Vosk model folder (offline mode)")
    parser.add_argument("--mic",      type=int, default=None,
                        help="Microphone device index (default: system default)")
    args = parser.parse_args()

    cfg = EarConfig()
    cfg.wake_word         = args.wake
    cfg.wake_word_enabled = not args.no_wake
    cfg.language          = args.lang
    cfg.vosk_model_path   = args.vosk
    cfg.input_source      = args.mic

    if args.diag:
        _run_ear_diagnostics(cfg)
    else:
        parser.print_help()
