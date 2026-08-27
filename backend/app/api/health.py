from fastapi import APIRouter, HTTPException
from sqlalchemy import text

from app.core.database import SessionLocal


router = APIRouter(tags=["health"])


@router.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@router.get("/ready", include_in_schema=False)
def ready():
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except Exception:
        raise HTTPException(503, "Service dependencies are not ready") from None
