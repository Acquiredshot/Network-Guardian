from datetime import UTC, datetime
from uuid import uuid4

from shared.contracts.events import EventEnvelope, NormalizedEvent

def normalize_event(event: EventEnvelope) -> NormalizedEvent:
    return NormalizedEvent(
        **event.model_dump(),
        event_id=uuid4(),
        accepted_at=datetime.now(UTC),
    )
