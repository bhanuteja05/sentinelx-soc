from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException

from app.api.alerts import router as alerts_router
from app.api.auth import router as auth_router
from app.api.cases import router as cases_router
from app.api.deps import get_current_active_user
from app.api.enrichment import router as enrichment_router
from app.db import check_database
from app.wazuh.routes import router as wazuh_router
from app.wazuh.scheduler import wazuh_scheduler


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Manage application background tasks on startup and shutdown."""
    await wazuh_scheduler.start()
    try:
        yield
    finally:
        await wazuh_scheduler.stop()


app = FastAPI(
    title="SentinelX",
    version="0.1.0",
    description="SentinelX SOC lab API (application foundation).",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/health")
def api_v1_health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/health/db")
def api_v1_health_db() -> dict[str, str]:
    try:
        check_database()
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="database unreachable",
        ) from None

    return {"status": "ok", "database": "reachable"}


app.include_router(auth_router)
app.include_router(alerts_router, dependencies=[Depends(get_current_active_user)])
app.include_router(enrichment_router, dependencies=[Depends(get_current_active_user)])
app.include_router(cases_router, dependencies=[Depends(get_current_active_user)])
app.include_router(wazuh_router, dependencies=[Depends(get_current_active_user)])
