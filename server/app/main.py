"""OGK-Server FastAPI application entrypoint."""

from __future__ import annotations

import asyncio
import ssl
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from server.app.api import audit, auth, commands, enroll, events, policy, reports, web
from server.app.config import get_settings
from server.app.database import Base, engine
from server.app.security import get_client_ip, rate_limiter
from server.app.services.retention_service import retention_background_loop


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Initialize schema and launch the 90-day automated event retention job."""
    Base.metadata.create_all(bind=engine)
    stop_event = asyncio.Event()
    retention_task = asyncio.create_task(retention_background_loop(stop_event))
    try:
        yield
    finally:
        stop_event.set()
        retention_task.cancel()
        try:
            await retention_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="OGK-Server",
    description="Child Computer Usage Management Application — 'A companion tool, not stealth spyware.'",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    """Enforce global IP-based rate limiting and attach security headers."""
    settings = get_settings()
    ip = get_client_ip(request)
    if request.url.path != "/health":
        if not rate_limiter.check(ip, "global", settings.rate_limit_per_minute):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests from this IP. Please slow down."},
            )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Mount dashboard static assets
_static_dir = Path(__file__).resolve().parents[2] / "dashboard" / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# Register core API routers & Web UI routes
app.include_router(auth.router)
app.include_router(enroll.router)
app.include_router(policy.router)
app.include_router(events.router)
app.include_router(commands.router)
app.include_router(reports.router)
app.include_router(audit.router)
app.include_router(web.router)


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "ogk-server"}


def run_server() -> None:
    """Run Uvicorn with TLS 1.2+ using generated lab certificates."""
    settings = get_settings()
    cert_path = Path(settings.tls_cert_path)
    key_path = Path(settings.tls_key_path)

    uvicorn_kwargs: dict = {
        "host": settings.host,
        "port": settings.port,
        "log_level": "info",
    }
    if cert_path.exists() and key_path.exists():
        uvicorn_kwargs["ssl_certfile"] = str(cert_path)
        uvicorn_kwargs["ssl_keyfile"] = str(key_path)
        uvicorn_kwargs["ssl_version"] = ssl.PROTOCOL_TLS_SERVER

    uvicorn.run("server.app.main:app", **uvicorn_kwargs)


if __name__ == "__main__":
    run_server()
