import sqlite3
import os
from datetime import datetime, timedelta

DB_PATH = os.path.expanduser("~/pkg-shield/database/pkg_shield.db")

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Main scan results table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256           TEXT NOT NULL,
        pkg_name         TEXT NOT NULL,
        version          TEXT NOT NULL,
        risk_score       REAL NOT NULL,
        zone             TEXT NOT NULL,       -- ZONE1, ZONE2, ZONE3, FAST_BLOCK
        scan_type        TEXT NOT NULL,       -- STATIC_ONLY, FULL, TIMEOUT_PARTIAL
        features_json    TEXT,               -- 112 features as JSON
        explanation_json TEXT,               -- XAI bullet points as JSON
        scanned_at       DATETIME NOT NULL,
        expires_at       DATETIME,           -- NULL = never expires
        UNIQUE(sha256, pkg_name, version)
    );
    """)

    # 2. Zone 2 override audit log table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        pkg_name    TEXT NOT NULL,
        version     TEXT NOT NULL,
        sha256      TEXT NOT NULL,
        risk_score  REAL NOT NULL,
        decision    TEXT NOT NULL,           -- USER_APPROVED, USER_REJECTED
        os_user     TEXT NOT NULL,
        hostname    TEXT NOT NULL,
        logged_at   DATETIME NOT NULL
    );
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialized successfully at:", DB_PATH)

def check_cache(sha256: str, pkg_name: str, version: str):
    """Checks if a valid, non-expired cache entry exists."""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = """
    SELECT * FROM scan_results 
    WHERE sha256 = ? AND pkg_name = ? AND version = ?
    """
    cursor.execute(query, (sha256, pkg_name, version))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None  # Cache Miss

    # Check TTL Expiry
    if row["expires_at"]:
        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.utcnow() > expires_at:
            return None  # Expired Cache

    return dict(row)  # Cache Hit

if __name__ == "__main__":
    init_db()