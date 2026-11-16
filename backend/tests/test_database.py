from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.database import engine
from app.main import app


def test_database_connection():
    with engine.connect() as connection:
        result = connection.execute(
            text("SELECT 1")
        ).scalar_one()

    assert result == 1


def test_runtime_database_permissions():
    with engine.connect() as connection:
        row = connection.execute(
            text("""
                SELECT
                    current_database() AS database_name,
                    current_user AS role_name,
                    current_schema() AS schema_name,
                    has_database_privilege(
                        current_user,
                        current_database(),
                        'CREATE'
                    ) AS can_create_database_objects,
                    has_schema_privilege(
                        current_user,
                        'payflow',
                        'CREATE'
                    ) AS can_create_schema_objects
            """)
        ).mappings().one()

    assert row["database_name"] == "payflow_db"
    assert row["role_name"] == "payflow_runtime"
    assert row["schema_name"] == "payflow"
    assert row["can_create_database_objects"] is False
    assert row["can_create_schema_objects"] is False


def test_database_readiness():
    with TestClient(app) as client:
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "database": "connected",
    }


def test_database_readiness_failure_is_safe(monkeypatch):
    class UnavailableEngine:
        def connect(self):
            raise SQLAlchemyError("private database details")

    monkeypatch.setattr(
        "app.api.health.engine",
        UnavailableEngine(),
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "database": "unavailable",
    }
    assert "private database details" not in response.text
