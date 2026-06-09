"""Audio dependency + microphone diagnostic for Jarvis ear/voice."""
import sys
print("=== DEPENDENCY CHECK ===")
try:
    import speech_recognition as sr
    print("SpeechRecognition :", sr.__version__)
except ImportError as e:
    print("SpeechRecognition : MISSING —", e)
    sys.exit(1)

try:
    import pyaudio
    print("PyAudio           :", pyaudio.__version__)
except ImportError as e:
    print("PyAudio           : MISSING —", e)
    sys.exit(1)

print()
print("=== MICROPHONE LIST ===")
mics = sr.Microphone.list_microphone_names()
for i, name in enumerate(mics):
    print(f"  [{i:2}] {name}")
if not mics:
    print("  (no microphones detected — check System Preferences > Privacy > Microphone)")

print()
print("=== JARVIS EAR BACKEND ===")
from network_guardian.jarvis.jarvis_ear import EarConfig, _build_ear_backend
cfg = EarConfig()
backend = _build_ear_backend(cfg)
bname = type(backend).__name__
print("Backend type :", bname)
print("Is available :", "YES" if bname != "_DeafBackend" else "NO — DeafBackend active (SpeechRecognition import failed at runtime)")

print()
print("=== JARVIS VOICE BACKEND ===")
from network_guardian.jarvis.jarvis_voice import VoiceConfig, _build_backend
vcfg = VoiceConfig()
vbackend = _build_backend(vcfg)
print("Platform     :", sys.platform)
print("Backend type :", type(vbackend).__name__)

print()
print("=== AMBIENT CALIBRATION TEST ===")
print("Attempting 1-second mic calibration (tests microphone access)...")
try:
    rec = sr.Recognizer()
    with sr.Microphone() as source:
        rec.adjust_for_ambient_noise(source, duration=1)
    print("Microphone access : OK  (energy threshold:", round(rec.energy_threshold), ")")
except Exception as exc:
    print("Microphone access : FAILED —", exc)
