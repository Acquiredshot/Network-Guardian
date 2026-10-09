import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "app"))

from detection.rules import detect
from enrichment.pipeline import enrich
from risk.scoring import score


def test_deterministic_brute_force_detection():
    event = enrich({"source": "FW", "event_type": "auth", "payload": {"failed_logins": 5}})
    detections = detect(event)
    assert detections == [{"rule": "BRUTE_FORCE", "severity": "high"}]
    assert score(detections) == 75


def test_malware_is_critical():
    detections = detect({"event_type": "malware", "payload": {}})
    assert score(detections) == 100
