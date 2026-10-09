import logging
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import DependencyState, router
from app.config import settings
from app.messaging.rabbitmq import RabbitMqPublisher
from app.pages import PAGES, render_pages
from shared.logging import configure_logging

configure_logging("ingestion-api")
logger = logging.getLogger("security_event_pipeline.ingestion")

app = FastAPI(
    title="Network Security Event Pipeline",
    version="0.1.0",
    description="Ingest network security events, track their processing status and fetch correlated incidents.",
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
    openapi_tags=[
        {"name": "Health", "description": "Liveness, readiness and dependency diagnostics."},
        {"name": "Events", "description": "Publish security events and track their processing."},
        {"name": "Incidents", "description": "Incidents correlated from ingested events."},
    ],
)
app.state.dependencies = DependencyState(RabbitMqPublisher(settings.rabbitmq_url))
app.include_router(router)

STATIC_DIR = Path(__file__).parent / "static"
SOC_PAGES = render_pages()
DOCS_TEMPLATE = (STATIC_DIR / "docs.html").read_text(encoding="utf-8")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse("/dashboard")


def soc_page(html: str):
    async def handler() -> HTMLResponse:
        return HTMLResponse(html)
    return handler


for page in PAGES:
    app.add_api_route(f"/{page.route}", soc_page(SOC_PAGES[page.route]), methods=["GET"], include_in_schema=False)


@app.get("/api/docs", include_in_schema=False)
async def api_docs() -> HTMLResponse:
    html = (
        DOCS_TEMPLATE.replace("{{title}}", app.title)
        .replace("{{version}}", app.version)
        .replace("{{openapi_url}}", app.openapi_url)
        .replace("{{diagnostics_url}}", "/api/diagnostics")
    )
    return HTMLResponse(html)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "http_request_completed",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "request_id": request_id,
        },
    )
    return response

@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request, _exc):
    return JSONResponse(status_code=422, content={"error": {"code": "VALIDATION_ERROR", "message": "Request validation failed", "details": None}})

@app.exception_handler(HTTPException)
async def http_error_handler(_request: Request, exc: HTTPException):
    if exc.status_code == 404:
        code = "NOT_FOUND"
    elif exc.status_code >= 500:
        code = "INTERNAL_ERROR"
    else:
        code = "BAD_REQUEST"
    details = exc.detail.get("services") if isinstance(exc.detail, dict) else None
    message = "One or more dependencies are unavailable" if details is not None else str(exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": code, "message": message, "details": details}},
    )
