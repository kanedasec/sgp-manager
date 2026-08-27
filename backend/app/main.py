import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app.api import access, admin, auth, evaluation, health
from app.api.dependencies import docs_user
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.services.bootstrap import bootstrap_admin


configure_logging()
logger = logging.getLogger("http")
REQUESTS = Counter("sgbm_http_requests_total", "HTTP requests", ["method", "path", "status"])
DURATION = Histogram("sgbm_http_request_duration_seconds", "HTTP request duration", ["method", "path"])


@asynccontextmanager
async def lifespan(_: FastAPI):
    bootstrap_admin()
    yield


settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    debug=False,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(_: Request, exc: RequestValidationError):
    details = [{"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": details})


@app.middleware("http")
async def security_and_observability(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", "")
    if not request_id or len(request_id) > 128:
        request_id = str(uuid.uuid4())
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("unhandled request error", extra={"request_id": request_id, "method": request.method, "path": request.url.path})
        response = JSONResponse(status_code=500, content={"detail": "Internal server error", "request_id": request_id})
    duration = time.perf_counter() - started
    route = request.scope.get("route")
    path_template = getattr(route, "path", request.url.path)
    REQUESTS.labels(request.method, path_template, str(response.status_code)).inc()
    DURATION.labels(request.method, path_template).observe(duration)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'none'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'unsafe-inline' https://cdn.jsdelivr.net; img-src data: https://fastapi.tiangolo.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    response.headers["Cache-Control"] = "no-store"
    logger.info(
        "request completed",
        extra={"request_id": request_id, "method": request.method, "path": request.url.path, "status": response.status_code, "duration_ms": round(duration * 1000, 2)},
    )
    return response


@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/openapi.json", include_in_schema=False)
def protected_openapi(_: object = Depends(docs_user)):
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False)
def protected_swagger(_: object = Depends(docs_user)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{settings.app_name} - Swagger UI")


@app.get("/redoc", include_in_schema=False)
def protected_redoc(_: object = Depends(docs_user)):
    return get_redoc_html(openapi_url="/openapi.json", title=f"{settings.app_name} - ReDoc")


app.include_router(health.router)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(access.router, prefix="/api/v1")
app.include_router(evaluation.router, prefix="/api/v1")
