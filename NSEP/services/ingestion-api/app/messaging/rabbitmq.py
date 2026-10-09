from typing import Protocol
from uuid import UUID

from celery import Celery

from shared.contracts.events import NormalizedEvent

class EventPublisher(Protocol):
    def publish(self, event: NormalizedEvent) -> None: ...

class RabbitMqPublisher:
    def __init__(self, url: str):
        self.celery = Celery("security-event-ingestion", broker=url)

    def publish(self, event: NormalizedEvent) -> None:
        self.celery.send_task(
            "app.tasks.consume_events.process_event",
            args=[event.model_dump(mode="json")],
            queue="security-events",
            ignore_result=True,
        )

class InMemoryPublisher:
    def __init__(self):
        self.events: dict[UUID, NormalizedEvent] = {}

    def publish(self, event: NormalizedEvent) -> None:
        self.events[event.event_id] = event
