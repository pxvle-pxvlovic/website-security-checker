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

@app.post("/scan/tls")
async def scan_tls(request: ScanRequest):
	async with httpx.AsyncClient() as client:
		try:
			response = await client.post(
				f"{SCANNER_URL}/scan/tls",
				json={"domain": request.domain},
			)
		except httpx.ConnectError:
			raise HTTPException(status_code=502, detail="scanner service is unreachable")

		return response.json()

@app.post("/scan/headers")
async def scan_headers(request: ScanRequest):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SCANNER_URL}/scan/headers",
                json={"domain": request.domain},
            )
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="scanner service is unreachable")

        return response.json()

@app.post("/scan/email")
async def scan_email(request: ScanRequest):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SCANNER_URL}/scan/email",
                json={"domain": request.domain},
            )
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="scanner service is unreachable")

        return response.json()