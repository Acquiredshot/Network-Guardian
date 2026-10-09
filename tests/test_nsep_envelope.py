import pytest

from network_guardian.core.events import CrossAppEnvelope


@pytest.mark.parametrize("source", ["NSEP", "MASK", "PAKSHIELD", "NETWORK_GUARDIAN"])
def test_supported_platform_envelope_is_accepted(source):
    envelope = CrossAppEnvelope.from_dict({
        "timestamp_ms": 1791511200000,
        "asset_id": "local-audit",
        "source": source,
        "event_type": "detection_event",
        "severity": "high",
        "category": "threat",
        "payload": {"incident_id": "audit-incident"},
    })

    assert envelope.validate() == []


def test_unknown_platform_source_is_still_rejected():
    envelope = CrossAppEnvelope(timestamp_ms=1791511200000, asset_id="audit", source="UNKNOWN")

    assert any("source must be" in error for error in envelope.validate())
