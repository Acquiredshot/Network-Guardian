# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
J.A.R.V.I.S — Network Guardian Terminal Intelligence Layer
===========================================================

Sub-package providing the JARVIS conversational shell, telemetry
aggregation, threat reporting, voice I/O, and NG process bootstrapping.

Public surface
--------------
    from network_guardian.jarvis import JarvisCore, TelemetryAggregator
    from network_guardian.jarvis import ThreatReportEngine, SubsystemBootstrapper
    from network_guardian.jarvis import JarvisVoice, JarvisEar
"""

from network_guardian.jarvis.telemetry_aggregator import TelemetryAggregator
from network_guardian.jarvis.threat_report_engine import ThreatReportEngine
from network_guardian.jarvis.subsystem_bootstrapper import SubsystemBootstrapper
from network_guardian.jarvis.jarvis_core import JarvisCore, parse_intent, INTENT_MAP
from network_guardian.jarvis.jarvis_voice import JarvisVoice, VoiceConfig
from network_guardian.jarvis.jarvis_ear import JarvisEar, EarConfig
from network_guardian.jarvis.jarvis_conversation import get_spoken_summary, get_chat_reply

__all__ = [
    "JarvisCore",
    "parse_intent",
    "INTENT_MAP",
    "TelemetryAggregator",
    "ThreatReportEngine",
    "SubsystemBootstrapper",
    "JarvisVoice",
    "VoiceConfig",
    "JarvisEar",
    "EarConfig",
    "get_spoken_summary",
    "get_chat_reply",
]
