# Open FAIR™ Quantitative Risk Formulation & Mathematical Models

## 1. Introduction to Open FAIR™
The Open FAIR (Factor Analysis of Information Risk) framework is the premier international standard for quantitative cyber risk analysis. Unlike subjective heatmaps that label vulnerabilities vaguely as "Low", "Medium", or "High", CyberQuant mathematically models risk as a financial probability distribution.

---

## 2. Core Mathematical Formulations

### A. Single Loss Expectancy (SLE)
The monetary loss expected every time a single successful breach occurs against an enterprise asset:
$$\text{SLE} = \text{Asset Valuation (₹)} \times \text{Exposure Factor (EF)}$$
* **Asset Valuation ($V$):** Economic and operational value of the target infrastructure (servers, proprietary databases, customer records).
* **Exposure Factor ($EF$):** Percentage of asset value compromised during a security incident ($0.05 \le EF \le 1.0$).

### B. Annualized Rate of Occurrence (ARO)
The estimated frequency at which a specific threat vector will successfully exploit a vulnerability within a single calendar year:
$$\text{ARO} = \text{Threat Event Frequency (TEF)} \times \text{Vulnerability Exploitability Factor (VEF)}$$
Where:
$$\text{VEF} = \left(\frac{\text{CVSS Base Score}}{10.0}\right) \times \text{EPSS Percentile}$$

### C. Annualized Loss Expectancy (ALE / EAL)
The expected annual financial loss incurred by the organization:
$$\text{ALE} = \text{SLE} \times \text{ARO}$$

---

## 3. Statutory Regulatory Risk Integration (India DPDP Act 2023)
For database assets storing customer personally identifiable information (PII), CyberQuant embeds statutory liability benchmarks under the **Digital Personal Data Protection Act (DPDP Act, 2023)**:
$$\text{Statutory Liability} = N_{\text{records}} \times R_{\text{penalty}}$$
* $N_{\text{records}}$: Total row count extracted from read-only database catalog metadata.
* $R_{\text{penalty}}$: Statutory benchmark penalty rate (set to ₹2,000 / $24 USD per compromised record).

---

## 4. 0/1 Knapsack Budget Optimization & Security ROI (ROSI)

### A. 0/1 Knapsack Formulation
Let:
* $n$ = Total candidate security mitigations (e.g., MFA, WAF, Endpoint Detection, Database TLS).
* $C_i$ = Annual implementation and operational cost of control $i$.
* $\Delta\text{ALE}_i$ = Annualized loss reduction achieved by control $i$.
* $B$ = Maximum allowable cybersecurity budget.
* $x_i \in \{0, 1\}$ = Decision variable indicating whether control $i$ is adopted.

$$\max \sum_{i=1}^n \Delta\text{ALE}_i \cdot x_i \quad \text{subject to} \quad \sum_{i=1}^n C_i \cdot x_i \le B$$

### B. Return on Security Investment (ROSI)
$$\text{ROSI (\%)} = \frac{\Delta\text{ALE}_{\text{portfolio}} - \text{Cost}_{\text{portfolio}}}{\text{Cost}_{\text{portfolio}}} \times 100\%$$
This metric directly translates engineering spend into C-Suite boardroom justification, demonstrating how a ₹5 Lakh investment yields ₹30+ Lakhs in avoided breach liability.
