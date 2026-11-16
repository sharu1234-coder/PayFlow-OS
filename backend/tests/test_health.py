from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "payflow-api",
    }


def test_openapi_schema():
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "PayFlow OS API"


def test_unknown_endpoint_returns_404():
    response = client.get("/api/v1/not-found")

    assert response.status_code == 404
