import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "scans.db")

def init_db():
	conn = sqlite3.connect(DB_PATH)
	cursor = conn.cursor()
	cursor.execute(
		"""
		CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL,
			score INTEGER NOT NULL,
			tls_result TEXT NOT NULL,
			headers_result TEXT NOT NULL,
			email_result TEXT NOT NULL,
			scanned_at TEXT NOT NULL
		)
		"""
	)
	conn.commit()
	conn.close()

def save_scan(domain: str, score: int, tls_result: str, headers_result: str, email_result: str, scanned_at: str):
	conn = sqlite3.connect(DB_PATH)
	cursor = conn.cursor()
	cursor.execute(
		        "INSERT INTO scans (domain, score, tls_result, headers_result, email_result, scanned_at) VALUES (?, ?, ?, ?, ?, ?)",
		        (domain, score, tls_result, headers_result, email_result, scanned_at)
	)
	conn.commit()
	conn.close()


def get_scans_by_domain(domain: str):
	conn = sqlite3.connect(DB_PATH)
	cursor = conn.cursor()
	cursor.execute(
		"SELECT id, domain, score, scanned_at FROM scans WHERE domain = ? ORDER BY scanned_at DESC",
		(domain,)
	)
	rows = cursor.fetchall()
	conn.close()
	return rows


def get_all_scans():
	conn = sqlite3.connect(DB_PATH)
	cursor = conn.cursor()
	cursor.execute(
		"SELECT id, domain, score, scanned_at FROM scans ORDER BY scanned_at DESC",
	)
	rows = cursor.fetchall()
	conn.close()
	return rows

if __name__ == "__main__":
    init_db()
    print("Database initialized")

    save_scan(
        domain="example.com",
        score=2,
        tls_result='{"valid": true}',
        headers_result='{"valid": false}',
        email_result='{"valid": true}',
        scanned_at="2026-08-30T12:00:00"
    )
    print("Test scan saved")