# CyberQuant AI: Continuous Cyber Risk Quantification & Security Investment Optimization Platform

[![Smart India Hackathon Prototype](https://img.shields.io/badge/SIH-Cybersecurity%20Defense-cyan.svg)](https://sih.gov.in)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20Python-009688.svg)](https://fastapi.tiangolo.com/)
[![FAIR Standard](https://img.shields.io/badge/Standard-FAIR%20Quantitative%20Risk-purple.svg)](https://www.fairinstitute.org/)
[![Status](https://img.shields.io/badge/Prototype-Ready%20%26%20Tested-success.svg)](#)

> **Defensive Cybersecurity Platform** designed for C-Suite executives (CISO, CFO, Board) and SOC teams to translate technical cyber vulnerabilities (CVSS/CVEs) into quantifiable financial risk (₹ INR), prioritize remediation, and mathematically optimize cybersecurity budget allocation using 0/1 Knapsack algorithms.

---

## 🏛️ 1. Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Executive SOC Web Interface                              │
│  (Dark-Themed SOC, Real-Time Gauges, 4x4 Matrix, Sliders, PDF Report Modal) │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / JSON REST APIs
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                            FastAPI Backend Server                           │
│  ┌────────────────────────┐ ┌────────────────────────┐ ┌──────────────────┐ │
│  │   FAIR Risk Engine     │ │   Budget Optimizer     │ │ What-If Simulator│ │
│  │  (SLE, ARO, ALE in ₹)  │ │ (0/1 Knapsack Solver)  │ │ (Dynamic Sliders)│ │
│  └────────────────────────┘ └────────────────────────┘ └──────────────────┘ │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ SQLite Engine
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                    Local SQLite Database (cyber_risk.db)                    │
│   • Assets Inventory   • CVE Vulnerability Feed   • Controls & Mitigations  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📐 2. Mathematical Models & Formulation

### A. FAIR Quantitative Financial Risk Model
1. **Single Loss Expectancy (SLE)**: Maximum direct financial loss if an exploit succeeds:
   $$\text{SLE} = \text{Asset Valuation (₹)} \times \text{Exposure Factor (0.05 - 1.0)}$$
2. **Annualized Rate of Occurrence (ARO)**: Estimated breach frequency per year:
   $$\text{ARO} = \text{Threat Likelihood} \times \left(\frac{\text{CVSS Score}}{10.0}\right) \times \text{Exploitability}$$
3. **Annualized Loss Expectancy (ALE)**: Expected yearly financial loss in Indian Rupees:
   $$\text{ALE} = \text{SLE} \times \text{ARO}$$

### B. Normalized Composite Cyber Risk Score (0–100)
Combines technical vulnerability metrics with business criticality and internet exposure:
$$\text{Score} = \min\left(100, \left[\text{CVSS} \times 5.5 + \text{Exploitability} \times 25 + \text{Threat} \times 20\right] \times \text{BizFactor} \times \text{ExpMultiplier}\right)$$
- **Low**: 0–39
- **Medium**: 40–69
- **High**: 70–89
- **Critical**: 90–100

### C. 0/1 Knapsack Budget Optimization & Security ROI
$$\text{Maximize} \sum (\text{Financial Loss Avoided}_i) \quad \text{subject to} \sum \text{Cost}_i \le \text{Budget}$$
$$\text{Security ROI (\%)} = \frac{\text{Total Loss Avoided (₹)} - \text{Total Cost (₹)}}{\text{Total Cost (₹)}} \times 100\%$$

---

## 🚀 3. Installation & Run Instructions

### Prerequisites
- Python 3.10+
- Dependencies: `fastapi`, `uvicorn`, `pydantic` (already installed)

### Quick Run
```powershell
cd C:\Users\HP\cyber-risk-platform
python run.py
```
Open your browser and navigate to:
👉 **`http://127.0.0.1:8000`**

### Demo Login Credentials
- **Username**: `admin`
- **Password**: `admin123`
- **Role**: `CISO / Security Director`

---

## 🎬 4. SIH Demo Presentation Flow (For Judges)

1. **The Problem Statement**:
   *"Cybersecurity teams report thousands of CVEs (e.g. CVSS 9.8), but CFOs and CEOs speak in budgets and financial risk. Leaders don't know which vulnerability to fix first or how to spend a limited ₹5 Lakhs budget."*
2. **The Baseline Reality (Before)**:
   - Point to the **Customer Database (CVE-2024-3400)**.
   - Show that an organization with ₹1.5 Crore in assets faces **₹39.70 Lakhs in Annualized Loss Expectancy (ALE)** and an overall risk score of **69.2 (Medium/High)**.
3. **Running the 0/1 Knapsack Optimizer**:
   - Set the budget slider to **₹5,00,000**.
   - Click **Run 0/1 Knapsack Optimizer**.
   - Show the dynamic result:
     - **Risk Score drops from 69.2 ➔ 19.5 (71.8% Risk Reduction)**.
     - **Annual Loss drops from ₹39.70L ➔ ₹9.18L (₹30.51 Lakhs loss avoided)**.
     - **Cost utilized: ₹4,90,000**.
     - **Net Financial Savings: ₹25.61 Lakhs**.
     - **Portfolio Security ROI: +522.8%**.
4. **Interactive What-If Simulation**:
   - Move the Threat Likelihood slider to **2.0x** to demonstrate how an aggressive ransomware wave increases risk in real-time, and how active controls cushion the financial blow.
5. **Executive Export**:
   - Click **Executive Report** to preview and print the C-Suite executive briefing.

---

## 💡 5. Key Innovations
- **Bridge between Technical & Business**: Converts obscure CVEs directly into Rupee exposure.
- **Zero-Dependency Portable Delivery**: Entire reactive dark SOC UI served seamlessly via FastAPI.
- **Algorithmic Capital Allocation**: Eliminates guesswork using discrete 0/1 Knapsack mathematical optimization.
- **Explainable AI**: Provides plain-English rationales for the CFO while generating technical remediation roadmaps for SOC engineers.

---

## ❓ 6. Possible Judge Questions & Answers

**Q1: How do you validate your financial loss numbers? Are they arbitrary?**
> *Answer:* We strictly implement the **FAIR (Factor Analysis of Information Risk)** standard—the gold-standard open framework for quantitative cyber risk used by Fortune 500 CISOs and approved by ISO/IEC 27005. SLE and ALE are derived directly from empirical asset replacement value, exposure factor, and CVSS exploitability metrics.

**Q2: What happens if two security controls overlap in protection?**
> *Answer:* Our optimization engine incorporates **compounding diminishing returns**. If automated patching and a Web Application Firewall both protect the Customer Database, the second control acts on the *residual* risk, preventing double-counting and ensuring realistic budgeting.

**Q3: Can this handle custom enterprise assets and CVE feeds?**
> *Answer:* Yes. Our REST APIs (`/api/assets` and `/api/vulnerabilities`) accept continuous live ingestion from scanners like Nessus, Qualys, or OpenVAS, dynamically recalculating the financial exposure in real time.
