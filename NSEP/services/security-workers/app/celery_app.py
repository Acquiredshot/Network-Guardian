from celery import Celery
from app.settings import settings

celery = Celery(
	"security-workers",
	broker=settings.rabbitmq_url,
	backend=settings.redis_url,
	include=["app.tasks.consume_events"],
)
celery.conf.task_default_queue = "security-events"
