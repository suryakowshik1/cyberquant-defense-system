# CyberQuant AI: Continuous Cyber Risk Quantification & Security Investment Optimization Platform

[![Smart India Hackathon 2026](https://img.shields.io/badge/SIH%202026-PS%20ID%3A%2026105-cyan.svg)](https://sih.gov.in)
[![AICTE Cyber Security Cell](https://img.shields.io/badge/Organization-AICTE%20Cyber%20Cell-blue.svg)](#)
[![Theme](https://img.shields.io/badge/Theme-Blockchain%20%26%20Cybersecurity-purple.svg)](#)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20Python-009688.svg)](https://fastapi.tiangolo.com/)
[![FAIR Standard](https://img.shields.io/badge/Standard-Open%20FAIR%E2%84%A2%20Quantitative%20Risk-indigo.svg)](https://www.fairinstitute.org/)
[![DPDP Act](https://img.shields.io/badge/Compliance-India%20DPDP%20Act%20(2023)-emerald.svg)](#)
[![Status](https://img.shields.io/badge/Prototype-Ready%20%26%20Field--Tested-success.svg)](#)

> **Enterprise Defensive Cybersecurity Platform** engineered for C-Suite executives (CISO, CFO, Board) and SOC engineering teams to translate technical vulnerabilities (CVE/CVSS/EPSS) into quantifiable financial risk (₹ INR / $ USD), prioritize remediation, and mathematically optimize cybersecurity budget allocation using 0/1 Knapsack algorithms.

---

## 📑 Table of Contents
1. [Project Information & SIH Problem Statement](#1-project-information--sih-problem-statement)
2. [Platform Features](#2-platform-features)
3. [Architecture Overview](#3-architecture-overview)
4. [Mathematical Formulations (FAIR & Knapsack)](#4-mathematical-formulations-fair--knapsack)
5. [Repository Structure](#5-repository-structure)
6. [Quick Start & Installation](#6-quick-start--installation)
7. [SIH Judge Walkthrough & Demo Flow](#7-sih-judge-walkthrough--demo-flow)
8. [Industry Pilot Roadmap](#8-industry-pilot-roadmap)

---

## 1. Project Information & SIH Problem Statement

* **Hackathon:** Smart India Hackathon (SIH 2026)
* **Problem Statement ID (PS ID):** 26105
* **Problem Statement Title:** AI-Powered Continuous Cyber Risk Quantification and Investment Optimization Platform
* **Category:** Software
* **Theme:** Blockchain & Cybersecurity
* **Nodal Organization:** All India Council for Technical Education (AICTE) — Cyber Security Cell

### The Problem:
Enterprises invest heavily in cybersecurity, yet cyber risk is communicated using subjective labels like "Low", "Medium", or "High". These labels fail to express financial exposure, leaving executive leadership unable to determine whether security spend is adequate or how to allocate limited budgets.

### The CyberQuant Solution:
CyberQuant combines technical vulnerability telemetry with the **Open FAIR™ standard**, **Monte Carlo simulations**, and an **Integer Linear Programming (0/1 Knapsack) solver** to quantify risk in Indian Rupees and allocate security budgets for maximum risk reduction.

---

## 2. Platform Features

### 🌐 A. Interactive 3D SOC Command Center (Three.js)
* Visualizes 31 global enterprise hub facilities (Tokyo, Frankfurt, Sao Paulo, Singapore, Mumbai) with real-time CVSS threat vectors and breach rings.
* Floating Telemetry HUD calculating dynamic asset valuation, Single Loss Expectancy (SLE), and Annualized Loss Expectancy (ALE).

### 🔍 B. Passive Website Vulnerability Scanner
* Non-invasive surface reconnaissance auditing SSL/TLS configuration, missing HTTP security headers (HSTS, CSP, X-Frame-Options), cookie security flags, and exposed ports.

### 🗄️ C. Zero-Trust Database Security Auditor
* Audits live enterprise database engines (PostgreSQL, MySQL, MSSQL, MongoDB, SQLite) via read-only catalog inspection.
* Evaluates perimeter port exposure, in-transit encryption, and table row volume telemetry to quantify statutory liability under the **Digital Personal Data Protection Act (DPDP Act, 2023)**.

### 💰 D. 0/1 Knapsack Budget Optimization
* Dynamically determines the exact portfolio of security mitigations that maximizes loss avoidance within a designated budget, calculating exact Return on Security Investment (ROSI).

---

## 3. Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Executive SOC Web Interface                              │
│   (3D Earth Globe, Real-Time HUD, Web Scanner, DB Auditor, FAIR Matrix)     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / JSON REST APIs
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                    CyberQuant WAF & FastAPI Backend                         │
│  ┌────────────────────────┐ ┌────────────────────────┐ ┌──────────────────┐ │
│  │    FAIR Risk Engine    │ │   Budget Optimizer     │ │ Reconnaissance   │ │
│  │ (SLE, ARO, ALE in ₹/$) │ │ (0/1 Knapsack Solver)  │ │ (Web & DB Audits)│ │
│  └────────────────────────┘ └────────────────────────┘ └──────────────────┘ │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ SQLite Engine
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                    Encrypted Database (cyber_risk.db)                       │
│   • Assets Inventory   • CVE Vulnerability Feed   • Audit Event Ledger      │
└─────────────────────────────────────────────────────────────────────────────┘
```

Detailed architectural diagrams and component specifications are documented in [`docs/architecture.md`](docs/architecture.md).

---

## 4. Mathematical Formulations (FAIR & Knapsack)

### A. FAIR Quantitative Financial Risk Model
1. **Single Loss Expectancy (SLE)**: Maximum direct financial loss if an exploit succeeds:
   $$\text{SLE} = \text{Asset Valuation (₹)} \times \text{Exposure Factor (0.05 - 1.0)}$$
2. **Annualized Rate of Occurrence (ARO)**: Estimated breach frequency per year:
   $$\text{ARO} = \text{Threat Likelihood} \times \left(\frac{\text{CVSS Score}}{10.0}\right) \times \text{EPSS Exploitability}$$
3. **Annualized Loss Expectancy (ALE)**: Expected yearly financial loss in Indian Rupees:
   $$\text{ALE} = \text{SLE} \times \text{ARO}$$

### B. 0/1 Knapsack Budget Optimization & Security ROI
$$\max \sum_{i=1}^n \Delta\text{ALE}_i \cdot x_i \quad \text{subject to} \quad \sum_{i=1}^n C_i \cdot x_i \le B, \quad x_i \in \{0, 1\}$$
$$\text{Security ROI (\%)} = \frac{\Delta\text{ALE}_{\text{portfolio}} - \text{Cost}_{\text{portfolio}}}{\text{Cost}_{\text{portfolio}}} \times 100\%$$

Complete mathematical derivations are available in [`docs/fair_mathematics.md`](docs/fair_mathematics.md).

---

## 5. Repository Structure

```text
cyber-risk-platform/
├── README.md                                  # Executive platform overview & documentation
├── run.py                                     # Local application launcher
├── requirements.txt                           # Backend Python dependencies
├── CyberQuant_AI_Prototype_Presentation.pptx  # Official SIH Presentation Deck (Prototype)
├── CyberQuant_Problem_Solving_Presentation.pptx# Official SIH Presentation Deck (Problem Solving)
├── app/                                       # Python FastAPI application core
│   ├── main.py                                # API endpoints & router orchestration
│   ├── database_auditor.py                    # Zero-Trust Database Security Inspector
│   ├── website_scanner.py                     # Defensive Web Vulnerability Scanner
│   ├── risk_engine.py                         # Open FAIR quantitative calculation engine
│   ├── optimizer.py                           # 0/1 Knapsack budget optimizer
│   ├── database.py                            # SQLite database schema & auth vault
│   ├── models.py                              # Pydantic schemas & validation models
│   ├── waf.py                                 # Web Application Firewall & rate limiter
│   ├── email_service.py                       # Live Gmail SMTP OTP dispatch
│   └── static/                                # Frontend Single-Page Application (HTML5/JS/3D)
│       └── index.html                         # Full interactive SOC dashboard
├── docs/                                      # Technical architecture & specifications
│   ├── architecture.md                        # Component breakdown & data flows
│   ├── fair_mathematics.md                    # Actuarial FAIR models & Knapsack formulation
│   └── database_security.md                   # Zero-Trust DB auditor specification
├── submission/                                # Hackathon submission assets
│   ├── PRESENTATION.md                        # Slide breakdown & problem statement mapping
│   └── DEMO.md                                # 5-minute live judge walkthrough guide
├── assets/                                    # Visual media & screenshots
│   └── screenshots/                           # UI captures of 3D SOC, HUD, and Scanners
└── public/                                    # Static assets for serverless deployment
```

---

## 6. Quick Start & Installation

### Prerequisites
* Python 3.10+
* Git

### Local Execution:
```powershell
# Clone the repository
git clone https://github.com/suryakowshik1/cyberquant-defense-system.git
cd cyberquant-defense-system

# Install dependencies
pip install -r requirements.txt

# Launch application
python run.py
```
Navigate to **`http://127.0.0.1:8000`** in your browser.

### Default Credentials:
* **Username:** `admin`
* **Password:** `admin123`
* **Role:** `CISO / Security Director`

---

## 7. SIH Judge Walkthrough & Demo Flow

1. **The Financial Translation:** Demonstrate how an enterprise with ₹1.5 Crore in assets faces **₹39.70 Lakhs in Annualized Loss Expectancy (ALE)** under baseline CVSS threats.
2. **0/1 Knapsack Optimization:** Allocate a budget of **₹5,00,000** and watch the optimizer drop risk by **71.8%**, avoiding **₹30.51 Lakhs in loss** with **+522.8% ROSI**.
3. **3D Global Infrastructure:** Pan across 31 global branches with live CVSS threat vectors and asset valuation KPIs.
4. **Active Reconnaissance:** Run live scans against external web targets and audit databases against DPDP Act statutory liability.

See [`submission/DEMO.md`](submission/DEMO.md) for the complete script.

---

## 8. Industry Pilot Roadmap

In response to hackathon evaluation recommendations regarding real-time enterprise deployment:
* **Phase 1 (Completed):** 100% functional MVP with simulated enterprise telemetry, 3D SOC command center, and passive surface scanning.
* **Phase 2 (In Progress):** Pilot trial on campus/institutional network infrastructure and local MSME IT environments.
* **Phase 3 (Future Scope):** Direct API connectors for CloudTrail, Qualys, and CrowdStrike EDR telemetry.
