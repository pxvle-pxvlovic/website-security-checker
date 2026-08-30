from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from main import app, call_scanner
import httpx
import pytest

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

def test_scan_email_success():
    fake_response_data = {
        "domain": "github.com",
        "valid": True,
        "has_spf": True,
        "spf_record": "v=spf1 ~all",
        "has_dmarc": True,

        "dmarc_policy": "quarantine",
        "issues": [],
    }

    fake_response = MagicMock()
    fake_response.json.return_value = fake_response_data

    with patch("main.httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
        response = client.post("/scan/email", json={"domain": "github.com"})

    assert response.status_code == 200
    assert response.json()["has_spf"] is True


def test_scan_email_scanner_unreachable():
    with patch("main.httpx.AsyncClient.post", new=AsyncMock(side_effect=httpx.ConnectError("connection refused"))):
        response = client.post("/scan/email", json={"domain": "github.com"})

    assert response.status_code == 502
    assert "unreachable" in response.json()["detail"]

@pytest.mark.asyncio
async def test_call_scanner_uses_correct_url():
    fake_response = MagicMock()
    fake_response.json.return_value = {"domain": "example.com"}

    with patch("main.httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)) as mock_post:
        await call_scanner("/scan/tls", "example.com")

    mock_post.assert_called_with("http://localhost:8081/scan/tls", json={"domain": "example.com"})