# Phase 1: Database Module
import sqlite3
import json
import hashlib
import os
import shutil

# In Vercel serverless environment, filesystem is read-only except /tmp
if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/cyber_risk.db"
    orig_db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'cyber_risk.db')
    if os.path.exists(orig_db) and not os.path.exists(DB_PATH):
        try:
            shutil.copy2(orig_db, DB_PATH)
        except Exception:
            pass
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'cyber_risk.db')


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_reset=False):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    if force_reset:
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS assets")
        cursor.execute("DROP TABLE IF EXISTS vulnerabilities")
        cursor.execute("DROP TABLE IF EXISTS security_controls")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        email TEXT
    )
    """)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except Exception:
        pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        asset_type TEXT NOT NULL,
        criticality TEXT NOT NULL,
        asset_value REAL NOT NULL,
        data_sensitivity TEXT NOT NULL,
        department TEXT NOT NULL,
        internet_exposure INTEGER NOT NULL,
        exposure_factor REAL NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        title TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        exploitability REAL NOT NULL,
        asset_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        patch_available INTEGER NOT NULL,
        exposure_level TEXT NOT NULL,
        threat_likelihood REAL NOT NULL,
        description TEXT,
        FOREIGN KEY(asset_id) REFERENCES assets(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_controls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        cost REAL NOT NULL,
        risk_reduction_pct REAL NOT NULL,
        loss_reduction_pct REAL NOT NULL,
        affected_asset_types TEXT NOT NULL,
        description TEXT NOT NULL,
        implementation_time_weeks INTEGER NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        otp_code TEXT NOT NULL,
        expires_at REAL NOT NULL,
        used INTEGER DEFAULT 0,
        created_at REAL NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scanned_websites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_url TEXT NOT NULL,
        hostname TEXT NOT NULL,
        scheme TEXT NOT NULL,
        http_status INTEGER,
        response_time_ms REAL,
        security_score INTEGER NOT NULL,
        security_grade TEXT NOT NULL,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        findings_json TEXT,
        passed_checks_json TEXT,
        ssl_audit_json TEXT,
        ports_audit_json TEXT,
        raw_headers_json TEXT,
        tech_stack_json TEXT,
        exposed_info_json TEXT,
        created_at TEXT NOT NULL
    )
    """)

    try:
        cursor.execute("ALTER TABLE scanned_websites ADD COLUMN tech_stack_json TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE scanned_websites ADD COLUMN exposed_info_json TEXT")
    except Exception:
        pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT NOT NULL,
        updated_at REAL NOT NULL
    )
    """)

    # Seed default firewall master passcode if not present
    cursor.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'firewall_passcode'")
    if not cursor.fetchone():
        cursor.execute("INSERT OR IGNORE INTO system_settings (setting_key, setting_value, updated_at) VALUES ('firewall_passcode', ?, ?)", ('*121#', 0.0))

    conn.commit()

    # Ensure admin user
    cursor.execute("SELECT id, email FROM users WHERE username = ?", ("admin",))
    admin_row = cursor.fetchone()
    if not admin_row:
        cursor.execute("""
        INSERT INTO users (username, password_hash, role, email)
        VALUES (?, ?, ?, ?)
        """, ("admin", hash_password("admin123"), "CISO / Security Director", "cyberquant26@gmail.com"))
    elif not admin_row["email"]:
        cursor.execute("UPDATE users SET email = ? WHERE username = ?", ("cyberquant26@gmail.com", "admin"))

    # Ensure cyber admin user
    cursor.execute("SELECT id, email FROM users WHERE username = ?", ("cyber admin",))
    cyber_row = cursor.fetchone()
    if not cyber_row:
        cursor.execute("""
        INSERT INTO users (username, password_hash, role, email)
        VALUES (?, ?, ?, ?)
        """, ("cyber admin", hash_password("cyber admin"), "Cyber Risk Administrator", "cyberquant26@gmail.com"))
    elif not cyber_row["email"]:
        cursor.execute("UPDATE users SET email = ? WHERE username = ?", ("cyberquant26@gmail.com", "cyber admin"))

    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM assets")
    if cursor.fetchone()[0] == 0:
        seed_data(cursor)
        conn.commit()

    conn.close()

def seed_data(cursor):
    assets = [
        ("Customer Database", "Database", "Critical", 5000000.0, "Confidential / PII", "Core Engineering and IT", 1, 0.80),
        ("Web Application (E-Commerce)", "Web Application", "High", 2500000.0, "Restricted", "E-Commerce and Sales", 1, 0.70),
        ("Payment Processing Server", "Payment Server", "Critical", 4000000.0, "Confidential / PCI-DSS", "Finance and Billing", 1, 0.75),
        ("Employee Endpoint Network (500 Workstations)", "Endpoint", "High", 2000000.0, "Internal", "Enterprise IT", 0, 0.60),
        ("Internal File Server and NAS", "File Server", "Medium", 1500000.0, "Internal", "Operations and Legal", 0, 0.50)
    ]
    cursor.executemany("""
    INSERT INTO assets (name, asset_type, criticality, asset_value, data_sensitivity, department, internet_exposure, exposure_factor)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, assets)

    vulnerabilities = [
        ("CVE-2024-3400", "Critical SQL Injection and Remote Code Execution in Customer DB API", 9.8, 0.90, 1, "Remote Code Execution", 1, "Public Internet", 0.50, 
         "Flaw in public API endpoints allowing unauthenticated remote code execution and direct exfiltration of sensitive PII. Demonstrates hypothetical potential impact of approx Rs 50 Lakh."),
        ("CVE-2023-38606", "Broken Access Control and Session Token Hijacking", 8.4, 0.85, 2, "Authentication Bypass", 1, "Public Internet", 0.60,
         "Improper session validation allowing attackers to impersonate administrative users and alter cart transactions."),
        ("CVE-2024-21413", "Payment Gateway Deserialization Vulnerability", 9.1, 0.80, 3, "Code Injection", 0, "Public Internet", 0.45,
         "Vulnerability in payment request serialization pipe risking cardholder data breach and PCI-DSS compliance penalties."),
        ("CVE-2024-21338", "Kernel Driver Elevation of Privilege via Phishing Vector", 7.8, 0.70, 4, "Privilege Escalation", 1, "Internal / Phishing", 0.55,
         "Malicious email lure can exploit local system driver to achieve domain admin control across workstation fleet."),
        ("CVE-2023-4911", "Buffer Overflow in Core Operating System Utilities (Looney Tunables)", 7.2, 0.60, 5, "Memory Corruption", 1, "Internal LAN", 0.35,
         "Local buffer overflow enabling unprivileged internal users to gain root privileges on internal storage cluster.")
    ]
    cursor.executemany("""
    INSERT INTO vulnerabilities (cve_id, title, cvss_score, exploitability, asset_id, category, patch_available, exposure_level, threat_likelihood, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, vulnerabilities)

    controls = [
        ("Vulnerability Patching and Hotfix Automation", "Patch Management", 120000.0, 38.0, 42.0, 
         json.dumps(["Database", "Web Application", "Payment Server", "Endpoint", "File Server"]),
         "Automated zero-day patch pipeline for critical RCE and web vulnerabilities.", 2),
        ("Multi-Factor Authentication (MFA) Zero-Trust Enforcement", "Identity and Access", 60000.0, 24.0, 26.0,
         json.dumps(["Web Application", "Endpoint", "Payment Server"]),
         "Hardware token/FIDO2 MFA enforcement for all remote access and admin portals.", 1),
        ("Cloudflare / Next-Gen Web Application Firewall (WAF)", "Perimeter Defense", 90000.0, 30.0, 32.0,
         json.dumps(["Web Application", "Database"]),
         "L7 deep inspection blocking SQLi, XSS, and automated credential stuffing.", 2),
        ("Micro-Segmentation and Zero-Trust Network Isolation", "Network Security", 150000.0, 34.0, 36.0,
         json.dumps(["Database", "Payment Server", "File Server"]),
         "Restricts lateral movement between workstation VLANs and mission-critical databases.", 4),
        ("Next-Gen Endpoint Detection and Response (EDR / XDR)", "Endpoint Security", 80000.0, 22.0, 25.0,
         json.dumps(["Endpoint"]),
         "AI-driven behavioral telemetry and anti-ransomware rollback on employee laptops.", 2),
        ("Air-Gapped Immutable Backup and Disaster Recovery", "Data Resilience", 70000.0, 26.0, 28.0,
         json.dumps(["Database", "File Server", "Payment Server"]),
         "Write-once-read-many (WORM) cloud backups ensuring 4-hour RTO during ransomware.", 2),
        ("24/7 Managed SOC and SIEM Telemetry Monitoring", "Monitoring and Incident Response", 180000.0, 36.0, 40.0,
         json.dumps(["Database", "Web Application", "Payment Server", "Endpoint", "File Server"]),
         "Round-the-clock threat hunting, anomaly detection, and rapid containment.", 3),
        ("Employee Security Awareness and Phishing Simulation", "Human Layer Security", 40000.0, 16.0, 18.0,
         json.dumps(["Endpoint"]),
         "Monthly simulated phishing campaigns and interactive cyber hygiene modules.", 1)
    ]
    cursor.executemany("""
    INSERT INTO security_controls (name, category, cost, risk_reduction_pct, loss_reduction_pct, affected_asset_types, description, implementation_time_weeks)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, controls)

def update_user_password(username: str, new_password: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    clean = (username or "").strip().lower()
    new_h = hash_password(new_password)
    if clean in ("admin", "cyberadmin", "cyber admin", "cyberquant26@gmail.com", "suryakowshik8@gmail.com", "pavansaikumar5616@gmail.com"):
        c.execute("""
        UPDATE users 
        SET password_hash = ?, email = COALESCE(email, 'cyberquant26@gmail.com')
        WHERE LOWER(username) IN ('admin', 'cyber admin') OR LOWER(email) = ?
        """, (new_h, clean))
    else:
        c.execute("UPDATE users SET password_hash = ? WHERE LOWER(username) = ? OR LOWER(email) = ?", (new_h, clean, clean))
    updated = c.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def db_get_user_by_username_or_email(identifier: str):
    """Fetches user record by username or email (case-insensitive)."""
    conn = get_db_connection()
    c = conn.cursor()
    clean = (identifier or "").strip().lower()
    c.execute("SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ? LIMIT 1", (clean, clean))
    row = c.fetchone()
    # Fallback: if queried with known admin email or admin clean name and row missing email, map to admin
    if not row:
        if clean in ("cyberquant26@gmail.com", "suryakowshik8@gmail.com", "pavansaikumar5616@gmail.com", "admin", "cyberadmin", "cyber admin"):
            c.execute("SELECT * FROM users WHERE LOWER(username) = 'admin' LIMIT 1")
            row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def db_create_user(username: str, email: str, password_hash: str, role: str = "Cyber Risk Analyst"):
    """Inserts a newly verified registered user into the database."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO users (username, email, password_hash, role)
    VALUES (?, ?, ?, ?)
    """, (username.strip(), email.strip().lower(), password_hash, role))
    conn.commit()
    user_id = c.lastrowid
    conn.close()
    return user_id

def db_update_user_password_by_email_or_username(identifier: str, new_password_hash: str) -> bool:
    """Updates password hash for a user by email or username."""
    conn = get_db_connection()
    c = conn.cursor()
    clean = (identifier or "").strip().lower()
    if clean in ("admin", "cyberadmin", "cyber admin", "cyberquant26@gmail.com", "suryakowshik8@gmail.com", "pavansaikumar5616@gmail.com"):
        c.execute("""
        UPDATE users 
        SET password_hash = ?, email = COALESCE(email, 'cyberquant26@gmail.com')
        WHERE LOWER(username) IN ('admin', 'cyber admin') OR LOWER(email) = ?
        """, (new_password_hash, clean))
    else:
        c.execute("UPDATE users SET password_hash = ? WHERE LOWER(username) = ? OR LOWER(email) = ?", (new_password_hash, clean, clean))
    updated = c.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def db_get_firewall_passcode() -> str:
    """Retrieves current master firewall passcode from DB (defaults to *121#)."""
    default_pass = "*121#"
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS system_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL, updated_at REAL NOT NULL)")
        c.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'firewall_passcode'")
        row = c.fetchone()
        conn.close()
        return row[0] if row else default_pass
    except Exception:
        return default_pass

def db_set_firewall_passcode(new_passcode: str) -> bool:
    """Updates master firewall passcode in SQLite system_settings."""
    import time
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS system_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL, updated_at REAL NOT NULL)")
        c.execute("""
        INSERT INTO system_settings (setting_key, setting_value, updated_at)
        VALUES ('firewall_passcode', ?, ?)
        ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = excluded.updated_at
        """, (new_passcode.strip(), time.time()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB FIREWALL PASSCODE UPDATE NOTICE] {e}")
        return False

def save_scanned_website(scan_data: dict) -> int:
    conn = get_db_connection()
    c = conn.cursor()
    fc = scan_data.get("findings_count", {})
    c.execute("""
    INSERT INTO scanned_websites (
        target_url, hostname, scheme, http_status, response_time_ms,
        security_score, security_grade, critical_count, high_count,
        medium_count, low_count, findings_json, passed_checks_json,
        ssl_audit_json, ports_audit_json, raw_headers_json, tech_stack_json, exposed_info_json, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data.get("target_url", ""),
        scan_data.get("hostname", ""),
        scan_data.get("scheme", "https"),
        scan_data.get("http_status"),
        scan_data.get("response_time_ms", 0),
        scan_data.get("security_score", 0),
        scan_data.get("security_grade", "F"),
        fc.get("critical", 0),
        fc.get("high", 0),
        fc.get("medium", 0),
        fc.get("low", 0),
        json.dumps(scan_data.get("findings", [])),
        json.dumps(scan_data.get("passed_checks", [])),
        json.dumps(scan_data.get("ssl_audit", {})),
        json.dumps(scan_data.get("ports_audit", [])),
        json.dumps(scan_data.get("raw_headers", {})),
        json.dumps(scan_data.get("tech_stack", [])),
        json.dumps(scan_data.get("exposed_info", {})),
        scan_data.get("timestamp", "")
    ))
    conn.commit()
    new_id = c.lastrowid
    conn.close()
    return new_id

def get_recent_scans(limit: int = 10) -> list:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    SELECT id, target_url, hostname, scheme, http_status, response_time_ms,
           security_score, security_grade, critical_count, high_count,
           medium_count, low_count, created_at
    FROM scanned_websites
    ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_scan_by_id(scan_id: int) -> dict:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM scanned_websites WHERE id = ?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["findings"] = json.loads(d["findings_json"] or "[]")
    d["passed_checks"] = json.loads(d["passed_checks_json"] or "[]")
    d["ssl_audit"] = json.loads(d["ssl_audit_json"] or "{}")
    d["ports_audit"] = json.loads(d["ports_audit_json"] or "[]")
    d["raw_headers"] = json.loads(d["raw_headers_json"] or "{}")
    d["tech_stack"] = json.loads(d.get("tech_stack_json") or "[]")
    d["exposed_info"] = json.loads(d.get("exposed_info_json") or "{}")
    d["findings_count"] = {
        "critical": d["critical_count"],
        "high": d["high_count"],
        "medium": d["medium_count"],
        "low": d["low_count"],
        "total": d["critical_count"] + d["high_count"] + d["medium_count"] + d["low_count"]
    }
    return d

def delete_scan_by_id(scan_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scanned_websites WHERE id = ?", (scan_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def log_audit_event(action: str, username: str = None, details: str = None, ip_address: str = None):
    import datetime
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO audit_logs (username, action, details, ip_address, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (username or "anonymous", action, details or "", ip_address or "127.0.0.1", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_audit_logs(limit: int = 25) -> list:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

# ==============================================================================
# ASSETS CRUD OPERATIONS
# ==============================================================================

def db_get_all_assets() -> list:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM assets ORDER BY id ASC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def db_get_asset(asset_id: int) -> dict:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return None
    asset_dict = dict(row)
    c.execute("SELECT * FROM vulnerabilities WHERE asset_id = ?", (asset_id,))
    asset_dict["vulnerabilities"] = [dict(v) for v in c.fetchall()]
    conn.close()
    return asset_dict

def db_create_asset(data: dict) -> int:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO assets (name, asset_type, criticality, asset_value, data_sensitivity, department, internet_exposure, exposure_factor)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["name"], data["asset_type"], data["criticality"],
        float(data["asset_value"]), data["data_sensitivity"],
        data["department"], int(data.get("internet_exposure", 1)),
        float(data.get("exposure_factor", 0.75))
    ))
    conn.commit()
    new_id = c.lastrowid
    conn.close()
    return new_id

def db_update_asset(asset_id: int, data: dict) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    fields = []
    values = []
    for k in ["name", "asset_type", "criticality", "asset_value", "data_sensitivity", "department", "internet_exposure", "exposure_factor"]:
        if k in data and data[k] is not None:
            fields.append(f"{k} = ?")
            values.append(data[k])
    if not fields:
        conn.close()
        return False
    values.append(asset_id)
    query = f"UPDATE assets SET {', '.join(fields)} WHERE id = ?"
    c.execute(query, tuple(values))
    updated = c.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def db_delete_asset(asset_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM vulnerabilities WHERE asset_id = ?", (asset_id,))
    c.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

# ==============================================================================
# VULNERABILITIES CRUD OPERATIONS
# ==============================================================================

def db_get_all_vulnerabilities() -> list:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    SELECT v.*, a.name as asset_name, a.asset_type, a.criticality as asset_criticality, a.asset_value
    FROM vulnerabilities v
    JOIN assets a ON v.asset_id = a.id
    ORDER BY v.cvss_score DESC
    """)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def db_get_vulnerability(vuln_id: int) -> dict:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    SELECT v.*, a.name as asset_name, a.asset_type, a.criticality as asset_criticality, a.asset_value, a.exposure_factor
    FROM vulnerabilities v
    JOIN assets a ON v.asset_id = a.id
    WHERE v.id = ?
    """, (vuln_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def db_create_vulnerability(data: dict) -> int:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO vulnerabilities (cve_id, title, cvss_score, exploitability, asset_id, category, patch_available, exposure_level, threat_likelihood, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["cve_id"], data["title"], float(data["cvss_score"]),
        float(data["exploitability"]), int(data["asset_id"]),
        data["category"], int(data.get("patch_available", 1)),
        data.get("exposure_level", "Public Internet"),
        float(data.get("threat_likelihood", 0.50)),
        data.get("description", "")
    ))
    conn.commit()
    new_id = c.lastrowid
    conn.close()
    return new_id

def db_update_vulnerability(vuln_id: int, data: dict) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    fields = []
    values = []
    for k in ["cve_id", "title", "cvss_score", "exploitability", "asset_id", "category", "patch_available", "exposure_level", "threat_likelihood", "description"]:
        if k in data and data[k] is not None:
            fields.append(f"{k} = ?")
            values.append(data[k])
    if not fields:
        conn.close()
        return False
    values.append(vuln_id)
    query = f"UPDATE vulnerabilities SET {', '.join(fields)} WHERE id = ?"
    c.execute(query, tuple(values))
    updated = c.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def db_delete_vulnerability(vuln_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

# ==============================================================================
# SECURITY CONTROLS CRUD OPERATIONS
# ==============================================================================

def db_get_all_controls() -> list:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM security_controls ORDER BY id ASC")
    rows = []
    for r in c.fetchall():
        d = dict(r)
        if isinstance(d.get("affected_asset_types"), str):
            try:
                d["affected_asset_types"] = json.loads(d["affected_asset_types"])
            except Exception:
                d["affected_asset_types"] = [d["affected_asset_types"]]
        rows.append(d)
    conn.close()
    return rows

def db_get_control(control_id: int) -> dict:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM security_controls WHERE id = ?", (control_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if isinstance(d.get("affected_asset_types"), str):
        try:
            d["affected_asset_types"] = json.loads(d["affected_asset_types"])
        except Exception:
            d["affected_asset_types"] = [d["affected_asset_types"]]
    return d

def db_create_control(data: dict) -> int:
    conn = get_db_connection()
    c = conn.cursor()
    affected = data.get("affected_asset_types", [])
    if not isinstance(affected, str):
        affected = json.dumps(affected)
    c.execute("""
    INSERT INTO security_controls (name, category, cost, risk_reduction_pct, loss_reduction_pct, affected_asset_types, description, implementation_time_weeks)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["name"], data["category"], float(data["cost"]),
        float(data["risk_reduction_pct"]), float(data["loss_reduction_pct"]),
        affected, data["description"], int(data["implementation_time_weeks"])
    ))
    conn.commit()
    new_id = c.lastrowid
    conn.close()
    return new_id

def db_update_control(control_id: int, data: dict) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    fields = []
    values = []
    for k in ["name", "category", "cost", "risk_reduction_pct", "loss_reduction_pct", "description", "implementation_time_weeks"]:
        if k in data and data[k] is not None:
            fields.append(f"{k} = ?")
            values.append(data[k])
    if "affected_asset_types" in data and data["affected_asset_types"] is not None:
        affected = data["affected_asset_types"]
        if not isinstance(affected, str):
            affected = json.dumps(affected)
        fields.append("affected_asset_types = ?")
        values.append(affected)
    if not fields:
        conn.close()
        return False
    values.append(control_id)
    query = f"UPDATE security_controls SET {', '.join(fields)} WHERE id = ?"
    c.execute(query, tuple(values))
    updated = c.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def db_delete_control(control_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_controls WHERE id = ?", (control_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def db_reset_database() -> dict:
    init_db(force_reset=True)
    return {"success": True, "message": "Database reset to factory default demonstration dataset."}

if __name__ == "__main__":
    init_db(force_reset=True)
    print("PHASE 1 COMPLETE: Database successfully initialized and seeded!")


