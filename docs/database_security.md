# Zero-Trust Database Security Auditor & Risk Engine Specification

## 1. Overview
The **CyberQuant Database Security Auditor** is a specialized module designed to assess the defensive security posture and regulatory financial risk of enterprise database instances without reading or storing private customer data.

Supported Database Engines:
* **PostgreSQL** (Port 5432)
* **MySQL / MariaDB** (Port 3306)
* **Microsoft SQL Server** (Port 1433)
* **MongoDB** (Port 27017)
* **SQLite 3** (Local file & storage engines)

---

## 2. Zero-Trust Read-Only Audit Principles

### Principle 1: Least-Privilege Execution
Audits require only catalog and metadata read permissions (`information_schema`, `pg_stat_user_tables`). The auditor never executes `UPDATE`, `INSERT`, `DELETE`, or `DROP` statements.

```sql
-- Sample Enterprise Least-Privilege Role Setup:
CREATE USER 'cyberquant_audit'@'%' IDENTIFIED BY 'AuditSecurePass@2026';
GRANT SELECT ON information_schema.* TO 'cyberquant_audit'@'%';
```

### Principle 2: Zero Sensitive Data Ingestion
The auditor inspects schema structure (table names, column names) to identify sensitive fields (`password`, `token`, `aadhaar`, `credit_card`) and counts total row volumes (`SELECT COUNT(*)` or catalog statistics). **Zero user payload rows are captured or transmitted.**

---

## 3. The 4-Tier Audit Pipeline

```text
[1. Network & Port Probe] ──> [2. Cryptographic Handshake] ──> [3. Hardening & CVE Check] ──> [4. FAIR Financial Mapping]
      (TCP latency)               (TLS 1.3 / SSLRequest)             (CIS Benchmark 3.1)           (DPDP Statutory Exposure)
```

1. **Network Perimeter Probe:** Measures socket latency and determines whether default database ports are exposed to public IP space (`0.0.0.0/0`) or properly isolated within private VPC subnets.
2. **Cryptographic Handshake Verification:** Sends native protocol SSLRequest packets (e.g. 8-byte PostgreSQL `0x04D2162F`) to verify that transport-layer encryption is enforced and cleartext sniffing is prevented.
3. **CIS Hardening & CVE Correlation:** Analyzes database server version strings against NVD/CVE databases (e.g. flagging MySQL 5.7 EOL or PostgreSQL legacy memory disclosure vulnerabilities).
4. **FAIR Loss Quantification:** Multiplies total sensitive records by the Indian **Digital Personal Data Protection Act (DPDP Act, 2023)** benchmark fine (₹2,000 / record) to calculate statutory liability, Expected Annual Loss (EAL), and Return on Security Investment (ROSI).
