from fastapi import FastAPI, HTTPException

from app.api.alerts import router as alerts_router
from app.db import check_database
from app.wazuh.routes import router as wazuh_router

app = FastAPI(
    title="SentinelX",
    version="0.1.0",
    description="SentinelX SOC lab API (application foundation).",
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


app.include_router(alerts_router)
app.include_router(wazuh_router)
