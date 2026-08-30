import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

SCANNER_URL = "http://localhost:8081"

class ScanRequest(BaseModel):
	domain: str

@app.get("/health")
def health():
	return {"status": "ok"}

async def call_scanner(path: str, domain: str):
	async with httpx.AsyncClient() as client:
		try:
			response = await client.post(
				f"{SCANNER_URL}{path}",
				json={"domain": domain},
			)
		except httpx.ConnectError:
			raise HTTPException(status_code=502, detail="scanner service is unreachable")

		return response.json()

@app.post("/scan/tls")
async def scan_tls(request: ScanRequest):
	return await call_scanner("/scan/tls", request.domain)
		

@app.post("/scan/headers")
async def scan_headers(request: ScanRequest):
	return await call_scanner("/scan/headers", request.domain)

@app.post("/scan/email")
async def scan_email(request: ScanRequest):
	return await call_scanner("/scan/email", request.domain)