# Phase 1: Database Module
import sqlite3
import json
import hashlib
import os

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
        role TEXT NOT NULL
    )
    """)

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

    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
        """, ("admin", hash_password("admin123"), "CISO / Security Director"))

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

if __name__ == "__main__":
    init_db(force_reset=True)
    print("PHASE 1 COMPLETE: Database successfully initialized and seeded!")
