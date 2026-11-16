from fastapi import APIRouter, Response, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.database import engine


router = APIRouter(
    prefix="/api/v1/health",
    tags=["Health"],
)


@router.get("/ready")
def database_readiness(response: Response) -> dict[str, str]:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    except SQLAlchemyError:
        response.status_code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
        )

        return {
            "status": "unavailable",
            "database": "unavailable",
        }

    return {
        "status": "ok",
        "database": "connected",
    }
