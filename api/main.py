import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import asyncio
from database import init_db, save_scan, get_scans_by_domain, get_all_scans
import json
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
	init_db()
	yield

app = FastAPI(lifespan=lifespan)

SCANNER_URL = os.environ.get("SCANNER_URL", "http://localhost:8081")

class ScanRequest(BaseModel):
	domain: str

class ScanSummary(BaseModel):
	id: int
	domain: str
	score: int
	scanned_at: str

app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_methods=["*"],
	allow_headers=["*"],
)


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
	scanned_at = datetime.now().isoformat()

	save_scan(domain, score, json.dumps(tls_task.result()), json.dumps(headers_task.result()), json.dumps(email_task.result()), scanned_at)


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

@app.get("/scans/{domain}")
def get_scans(domain: str):
	rows = get_scans_by_domain(domain)

	summaries = []
	for row in rows:
		summary = ScanSummary(id=row[0], domain=row[1], score=row[2], scanned_at=row[3])
		summaries.append(summary)

	return summaries

@app.get("/scans")
def get_scans_whole():
	rows = get_all_scans()
	summaries = []
	for row in rows:
		summary = ScanSummary(id=row[0], domain=row[1], score=row[2], scanned_at=row[3])
		summaries.append(summary)

	return summaries

