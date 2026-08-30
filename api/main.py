import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import asyncio

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

async def run_all_checks(domain: str) -> dict:
	async with asyncio.TaskGroup() as tg:
	    tls_task= tg.create_task(call_scanner("/scan/tls", domain))
	    headers_task = tg.create_task(call_scanner("/scan/headers", domain))
	    email_task = tg.create_task(call_scanner("/scan/email", domain))

	score = calculate_score(tls_task.result(), headers_task.result(), email_task.result())

	return {"tls": tls_task.result(), "headers": headers_task.result(), "email": email_task.result(), "score": score}


@app.post("/scan/tls")
async def scan_tls(request: ScanRequest):
	return await call_scanner("/scan/tls", request.domain)
		

@app.post("/scan/headers")
async def scan_headers(request: ScanRequest):
	return await call_scanner("/scan/headers", request.domain)

@app.post("/scan/email")
async def scan_email(request: ScanRequest):
	return await call_scanner("/scan/email", request.domain)

@app.post("/scan")
async def scan(request: ScanRequest):
	return await run_all_checks(request.domain)


def calculate_score(tls: dict, headers: dict, email: dict) -> int:
	counter = 0

	if tls["valid"]:
		counter += 1
	if headers["valid"]:
		counter += 1
	if email["valid"]:
		counter += 1

	return counter