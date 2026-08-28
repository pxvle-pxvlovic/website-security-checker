from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from main import app
import httpx

client = TestClient(app)

def test_health():
	response = client.get("/health")
	assert response.status_code == 200
	assert response.json() == {"status": "ok"}

def test_scan_tls_success():
	fake_response_data = {
		"domain": "example.com",
        "valid": True,
        "expires_at": "2027-01-01T00:00:00Z",
        "days_until_expiry": 100,
        "protocol_version": "TLS 1.3",
        "issuer": "Fake CA",
        "issues": [],
	}	

	fake_response = MagicMock()
	fake_response.json.return_value = fake_response_data

	with patch("main.httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
		response = client.post("/scan/tls", json={"domain": "example.com"})

	assert response.status_code == 200
	assert response.json()["domain"] == "example.com"
	assert response.json()["valid"] is True

def test_scan_tls_scanner_unreachable():
    with patch("main.httpx.AsyncClient.post", new=AsyncMock(side_effect=httpx.ConnectError("connection refused"))):
        response = client.post("/scan/tls", json={"domain": "example.com"})

    assert response.status_code == 502
    assert "unreachable" in response.json()["detail"]

def test_scan_headers_success():
    fake_response_data = {
        "domain": "example.com",
        "valid": True,
        "checks": [
            {"name": "Strict-Transport-Security", "present": True, "value": "max-age=31536000"},
        ],
        "issues": [],
    }

    fake_response = MagicMock()
    fake_response.json.return_value = fake_response_data

    with patch("main.httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
        response = client.post("/scan/headers", json={"domain": "example.com"})

    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"
    assert response.json()["valid"] is True


def test_scan_headers_scanner_unreachable():
    with patch("main.httpx.AsyncClient.post", new=AsyncMock(side_effect=httpx.ConnectError("connection refused"))):
        response = client.post("/scan/headers", json={"domain": "example.com"})

    assert response.status_code == 502
    assert "unreachable" in response.json()["detail"]