import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app
from app.database import Base, get_db

@pytest.fixture()
def client():
    test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)
    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)

def create_sample_project(client):
    response = client.post("/projects", json={
        "name": "demo-sast", "repository_url": "https://example.com/demo.git",
        "source_code": 'password = "very-secret-value"\nuser.innerHTML = input_value\n'
    })
    assert response.status_code == 201
    return response.json()["id"]

def test_root_and_openapi(client):
    assert client.get("/").status_code == 200
    assert client.get("/openapi.json").status_code == 200

def test_project_crud(client):
    project_id = create_sample_project(client)
    assert client.get("/projects").status_code == 200
    assert client.get(f"/projects/{project_id}").status_code == 200
    assert client.put(f"/projects/{project_id}", json={"name": "updated"}).json()["name"] == "updated"
    assert client.delete(f"/projects/{project_id}").status_code == 204
    assert client.get(f"/projects/{project_id}").status_code == 404

def test_scan_findings_quality_gate(client):
    project_id = create_sample_project(client)
    scan = client.post("/scans", json={"project_id": project_id})
    assert scan.status_code == 201
    scan_id = scan.json()["id"]
    assert len(client.get(f"/scans/{scan_id}/findings").json()) >= 1
    assert client.get(f"/scans/{scan_id}/quality-gate").json()["passed"] is False

def test_scan_list_and_detail(client):
    project_id = create_sample_project(client)
    scan_id = client.post("/scans", json={"project_id": project_id}).json()["id"]
    assert client.get("/scans").status_code == 200
    assert client.get(f"/scans/{scan_id}").status_code == 200

@pytest.mark.parametrize("fmt", ["json", "html", "sarif"])
def test_report_formats(client, fmt):
    project_id = create_sample_project(client)
    scan_id = client.post("/scans", json={"project_id": project_id}).json()["id"]
    response = client.post(f"/scans/{scan_id}/reports", json={"format": fmt})
    assert response.status_code == 201
    report_id = response.json()["id"]
    assert client.get(f"/reports/{report_id}").status_code == 200

def test_missing_resources_return_404(client):
    assert client.get("/projects/999").status_code == 404
    assert client.get("/scans/999").status_code == 404
    assert client.get("/reports/999").status_code == 404
