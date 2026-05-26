# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Task Automator — automates routine maintenance tasks.

Handles scheduling, execution, and reporting of automated tasks such as
system updates, patch management, and configuration changes.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus

if TYPE_CHECKING:
    from network_guardian.config import Config

logger = logging.getLogger("network_guardian.automator")

TaskFunc = Callable[..., Coroutine[Any, Any, Any]]


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskResult:
    task_name: str
    status: TaskStatus
    result: Any = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


@dataclass
class RegisteredTask:
    name: str
    func: TaskFunc
    description: str = ""


class Automator:
    """Registry and executor for automated maintenance tasks."""

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus
        self._tasks: dict[str, RegisteredTask] = {}
        self._history: list[TaskResult] = []

    def register(self, name: str, func: TaskFunc, description: str = "") -> None:
        """Register a task that can be executed by name."""
        self._tasks[name] = RegisteredTask(name=name, func=func, description=description)
        logger.info("Task registered: %s", name)

    async def run(self, name: str, **kwargs: Any) -> TaskResult:
        """Execute a registered task by name."""
        if name not in self._tasks:
            raise KeyError(f"Unknown task: {name}")

        task = self._tasks[name]
        result = TaskResult(task_name=name, status=TaskStatus.RUNNING,
                            started_at=datetime.now(timezone.utc))
        logger.info("Running task: %s", name)

        try:
            result.result = await task.func(**kwargs)
            result.status = TaskStatus.COMPLETED
        except Exception as exc:
            logger.exception("Task %s failed", name)
            result.status = TaskStatus.FAILED
            result.error = str(exc)
        finally:
            result.finished_at = datetime.now(timezone.utc)

        self._history.append(result)
        await self.event_bus.publish(Event(
            topic="automator.task_complete",
            data={"result": result},
        ))
        return result

    def list_tasks(self) -> list[RegisteredTask]:
        return list(self._tasks.values())

    @property
    def history(self) -> list[TaskResult]:
        return list(self._history)
