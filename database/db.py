import sqlite3
import os
import json
import socket
import getpass
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

# Dynamic database path relative to repository
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pkg_shield.db")

def get_connection() -> sqlite3.Connection:
    """Creates a connection to the SQLite database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database tables per SafePip v2.0 specifications."""
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Main scan results cache table
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

def calculate_ttl(zone: str, scan_type: str = "FULL") -> Optional[str]:
    """Calculates expires_at timestamp based on SafePip v2.0 TTL rules:
    - Zone 1 (Clean)       -> 30 days
    - Zone 2 (Suspicious)  -> 7 days
    - Zone 3 (Malicious)   -> Never (None)
    - Fast Block           -> Never (None)
    - Timeout Partial      -> 7 days
    """
    now = datetime.utcnow()
    if zone in ("FAST_BLOCK", "ZONE3"):
        return None
    elif zone == "ZONE1":
        return (now + timedelta(days=30)).isoformat()
    elif zone == "ZONE2" or scan_type == "TIMEOUT_PARTIAL":
        return (now + timedelta(days=7)).isoformat()
    return None

def check_cache(sha256: str, pkg_name: str, version: str) -> Optional[Dict[str, Any]]:
    """Checks if a valid, non-expired cache entry exists for the package digest."""
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
        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
            if datetime.utcnow() > expires_at:
                return None  # Expired Cache
        except Exception:
            pass

    result = dict(row)
    if result.get("features_json"):
        try:
            result["features"] = json.loads(result["features_json"])
        except Exception:
            pass
    if result.get("explanation_json"):
        try:
            result["explanations"] = json.loads(result["explanation_json"])
        except Exception:
            pass
    return result

def insert_scan_result(
    sha256: str,
    pkg_name: str,
    version: str,
    risk_score: float,
    zone: str,
    scan_type: str = "FULL",
    features: Optional[Dict[str, Any]] = None,
    explanations: Optional[List[str]] = None
) -> None:
    """Inserts or replaces a scan result into scan_results with automatic TTL."""
    conn = get_connection()
    cursor = conn.cursor()

    now_iso = datetime.utcnow().isoformat()
    expires_at = calculate_ttl(zone, scan_type)
    features_str = json.dumps(features) if features else None
    explanations_str = json.dumps(explanations) if explanations else None

    query = """
    INSERT INTO scan_results (
        sha256, pkg_name, version, risk_score, zone, scan_type,
        features_json, explanation_json, scanned_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(sha256, pkg_name, version) DO UPDATE SET
        risk_score = excluded.risk_score,
        zone = excluded.zone,
        scan_type = excluded.scan_type,
        features_json = excluded.features_json,
        explanation_json = excluded.explanation_json,
        scanned_at = excluded.scanned_at,
        expires_at = excluded.expires_at;
    """
    cursor.execute(query, (
        sha256, pkg_name, version, risk_score, zone, scan_type,
        features_str, explanations_str, now_iso, expires_at
    ))
    conn.commit()
    conn.close()

def insert_audit_log(
    pkg_name: str,
    version: str,
    sha256: str,
    risk_score: float,
    decision: str,
    os_user: Optional[str] = None,
    hostname: Optional[str] = None
) -> None:
    """Records an override decision to the audit_log table."""
    conn = get_connection()
    cursor = conn.cursor()

    user = os_user or getpass.getuser()
    host = hostname or socket.gethostname()
    now_iso = datetime.utcnow().isoformat()

    cursor.execute("""
    INSERT INTO audit_log (
        pkg_name, version, sha256, risk_score, decision, os_user, hostname, logged_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (pkg_name, version, sha256, risk_score, decision, user, host, now_iso))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()