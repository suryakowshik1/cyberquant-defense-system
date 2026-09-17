# CyberQuant AI - System Architecture & Technical Specifications

## 1. System Overview
**CyberQuant AI** is an enterprise-grade Quantitative Cyber Risk Management and Security Investment Optimization platform built for C-Suite leaders (CISO, CFO, Board) and SOC engineering teams. It bridges the gap between technical vulnerability telemetry (CVE/CVSS/EPSS) and boardroom financial decisions by implementing the **Open FAIR™ (Factor Analysis of Information Risk)** standard and integer programming optimization.

```text
                               ┌──────────────────────────────────────────────┐
                               │   Interactive SOC & Executive Dashboard      │
                               │  (3D Earth Globe, Real-time HUD, FAIR Matrix)│
                               └──────────────────────┬───────────────────────┘
                                                      │ HTTP / WebSocket REST
                               ┌──────────────────────▼───────────────────────┐
                               │        CyberQuant WAF & Gateway Shield       │
                               │   (Sliding Window Rate Limit, SSRF Guard)    │
                               └──────────────────────┬───────────────────────┘
                                                      │
         ┌────────────────────────────────────────────┼────────────────────────────────────────────┐
         │                                            │                                            │
┌────────▼──────────────┐                  ┌──────────▼────────────┐                  ┌────────────▼──────────┐
│ Defensive Recon Engine│                  │  FAIR Financial Model │                  │ Knapsack ILP Optimizer│
│ • Passive Web Scanner │                  │  • SLE, ARO, ALE (₹)  │                  │ • 0/1 Knapsack Solver │
│ • TLS 1.3 Handshake   │                  │  • Monte Carlo Engine │                  │ • Security ROI (ROSI) │
│ • Database Auditor    │                  │  • DPDP Statutory Fine│                  │ • Budget Allocator    │
└────────┬──────────────┘                  └──────────┬────────────┘                  └────────────┬──────────┘
         │                                            │                                            │
         └────────────────────────────────────────────┼────────────────────────────────────────────┘
                                                      │
                               ┌──────────────────────▼───────────────────────┐
                               │    Encrypted Telemetry Data Store            │
                               │   • SQLite Database (cyber_risk.db)          │
                               │   • 31 Global Hub Facilities & Asset DB      │
                               │   • Active State Sync & Audit Event Ledger   │
                               └──────────────────────────────────────────────┘
```

---

## 2. Core Components

### A. Frontend Layer (Single-Page Application)
* **Interactive 3D Tactical Globe (Three.js):** Displays global infrastructure across 31 enterprise facilities with real-time CVSS threat vectors, active breach rings, and center-pin focus.
* **Floating Telemetry HUD:** Live streaming ticker reflecting active breach defense metrics, Single Loss Expectancy (SLE), and Annualized Loss Expectancy (ALE).
* **Responsive Command Views:**
  * View 1: Executive C-Suite Dashboard & What-If Sliders
  * View 2: Passive Website Vulnerability Checkup (HTTP headers, SSL, Cookie flags)
  * View 3: Zero-Trust Read-Only Database Security Auditor (Port exposure, TLS, DPDP risk)
* **Role-Based Access Control (RBAC):** Admin, Analyst, and Viewer authorization with HMAC-SHA256 session vaulting.

### B. Defensive Reconnaissance & Surface Auditing
* **Web Security Posture Auditor:** Non-invasive passive scanning analyzing TLS certificates, HSTS, CSP, X-Frame-Options, cookie security flags, and server software banners.
* **Zero-Trust Database Security Inspector:** Probes TCP port exposure (Postgres 5432, MySQL 3306, MongoDB 27017, MSSQL 1433), negotiates SSLRequest protocols without reading user data rows, and tallies table records for statutory liability calculation.

### C. Quantitative FAIR Risk Engine
* Translates CVSS severity scores, Exploit Prediction Scoring System (EPSS) probabilities, and historical threat frequencies into monetary exposure (₹ INR / $ USD).
* Calculates Single Loss Expectancy (SLE), Annualized Rate of Occurrence (ARO), and Annualized Loss Expectancy (ALE).
* Applies statutory penalty formulas under the **Indian Digital Personal Data Protection Act (DPDP Act, 2023)** and GDPR.

### D. 0/1 Knapsack Investment Optimizer
* Solves the classic budget-constrained 0/1 knapsack optimization problem:
  $$\max \sum_{i=1}^n \Delta\text{ALE}_i \cdot x_i \quad \text{s.t.} \quad \sum_{i=1}^n C_i \cdot x_i \le B, \quad x_i \in \{0, 1\}$$
* Dynamically identifies the optimal portfolio of defensive mitigations under a designated financial budget, computing exact Return on Security Investment (ROSI).

---

## 3. Security & Hardening Architecture
* **Web Application Firewall (WAF):** Sliding-window rate limiter (20 requests/min for auth routes, 180 requests/min for general routes).
* **Strict SSRF Guard:** Dual DNS resolution and private IP blocklist (RFC 1918, RFC 3927) preventing scanner abuse.
* **Cryptographic Vault:** PBKDF2-HMAC-SHA256 password hashing with 100,000 iterations and 16-byte cryptographically secure salts.
* **Audit Trail:** Immutable append-only audit log in SQLite recording all administrative actions and security checks.
