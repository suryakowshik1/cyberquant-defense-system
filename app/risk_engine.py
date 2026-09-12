"""
Phase 2: Risk Scoring & Financial Quantification Engine (FAIR-aligned)

Calculates:
  - Normalized Cyber Risk Score (0-100)
  - Single Loss Expectancy (SLE = Asset Value * Exposure Factor)
  - Annualized Rate of Occurrence (ARO = Threat Likelihood * (CVSS / 10) * Exploitability)
  - Annualized Loss Expectancy (ALE = SLE * ARO)
  - Qualitative Risk Levels: Low (0-39), Medium (40-69), High (70-89), Critical (90-100)
  - Residual Risk & Expected Loss Avoided under Security Controls
"""
from typing import Dict, List, Any, Optional

# Criticality Weights
CRITICALITY_WEIGHTS = {
    "Critical": 1.0,
    "High": 0.8,
    "Medium": 0.5,
    "Low": 0.2
}

# Data Sensitivity Weights
SENSITIVITY_WEIGHTS = {
    "Confidential / PII": 1.0,
    "Confidential / PCI-DSS": 1.0,
    "Restricted": 0.8,
    "Internal": 0.5,
    "Public": 0.2
}

def get_risk_level(score: float) -> str:
    """Classifies risk score into standard SIH/NIST brackets."""
    if score >= 90.0:
        return "Critical"
    elif score >= 70.0:
        return "High"
    elif score >= 40.0:
        return "Medium"
    else:
        return "Low"

def calculate_vulnerability_risk(
    cvss_score: float,
    exploitability: float,
    threat_likelihood: float,
    asset_criticality: str,
    asset_sensitivity: str,
    internet_exposed: bool
) -> Dict[str, Any]:
    """
    Calculates normalized risk score (0-100) for a vulnerability given its asset context.
    Combines technical severity with business impact and perimeter exposure.
    """
    crit_weight = CRITICALITY_WEIGHTS.get(asset_criticality, 0.5)
    sens_weight = SENSITIVITY_WEIGHTS.get(asset_sensitivity, 0.5)
    exposure_multiplier = 1.25 if internet_exposed else 0.85

    # Technical Score (0-100): CVSS (55%) + Exploitability (25%) + Threat Likelihood (20%)
    tech_score = (cvss_score * 10.0 * 0.55) + (exploitability * 100.0 * 0.25) + (threat_likelihood * 100.0 * 0.20)
    
    # Business Impact Factor (0.2 to 1.0)
    biz_factor = (crit_weight * 0.60) + (sens_weight * 0.40)
    
    # Composite calculation normalized to 0-100
    raw_score = tech_score * biz_factor * exposure_multiplier
    normalized_score = round(min(100.0, max(5.0, raw_score)), 1)
    
    return {
        "risk_score": normalized_score,
        "risk_level": get_risk_level(normalized_score)
    }

def calculate_financial_exposure(
    asset_value: float,
    exposure_factor: float,
    threat_likelihood: float,
    cvss_score: float,
    exploitability: float
) -> Dict[str, float]:
    """
    FAIR Quantitative Risk Engine:
      - SLE (Single Loss Expectancy): Asset Value * Exposure Factor (₹ INR)
      - ARO (Annualized Rate of Occurrence): Estimated frequency of exploit per year
      - ALE (Annualized Loss Expectancy): SLE * ARO (₹ INR / year)
    """
    exp_factor = max(0.05, min(1.0, exposure_factor))
    tl = max(0.05, min(1.0, threat_likelihood))
    
    # SLE: Maximum financial damage of a single successful exploit
    sle = round(asset_value * exp_factor, 2)
    
    # ARO: Likelihood scaled by technical vulnerability severity and exploit availability
    aro = round(tl * (cvss_score / 10.0) * exploitability, 4)
    
    # ALE: Annualized financial loss expectancy in Indian Rupees
    ale = round(sle * aro, 2)
    
    return {
        "sle": sle,
        "aro": aro,
        "ale": ale,
        "potential_max_loss": sle
    }

def evaluate_organization_risk(
    assets: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    applied_controls: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Evaluates the complete organization security posture:
      1. Baseline Risk Scores and Financial Losses (SLE, ARO, ALE)
      2. Residual Risk Scores and Losses after applying selected Security Controls
      3. Aggregated metrics: Org Risk Score, Total ALE, Total Asset Value, Total SLE
    """
    applied_controls = applied_controls or []
    
    # Pre-map controls to affected asset types
    control_effects_by_type: Dict[str, Dict[str, float]] = {}
    for ctrl in applied_controls:
        types = ctrl.get("affected_asset_types", [])
        risk_red = ctrl.get("risk_reduction_pct", 0.0)
        loss_red = ctrl.get("loss_reduction_pct", 0.0)
        
        for atype in types:
            if atype not in control_effects_by_type:
                control_effects_by_type[atype] = {"risk_red_mult": 1.0, "loss_red_mult": 1.0}
            
            # Diminishing compounding returns for overlapping controls
            control_effects_by_type[atype]["risk_red_mult"] *= (1.0 - (risk_red / 100.0))
            control_effects_by_type[atype]["loss_red_mult"] *= (1.0 - (loss_red / 100.0))

    asset_lookup = {a["id"]: a for a in assets}
    enriched_vulns = []
    
    total_asset_value = sum(a["asset_value"] for a in assets)
    baseline_total_ale = 0.0
    residual_total_ale = 0.0
    baseline_scores = []
    residual_scores = []

    for v in vulnerabilities:
        asset = asset_lookup.get(v["asset_id"])
        if not asset:
            continue
        
        # Baseline Risk
        risk_info = calculate_vulnerability_risk(
            cvss_score=v["cvss_score"],
            exploitability=v["exploitability"],
            threat_likelihood=v.get("threat_likelihood", 0.5),
            asset_criticality=asset["criticality"],
            asset_sensitivity=asset["data_sensitivity"],
            internet_exposed=bool(asset["internet_exposure"])
        )
        
        fin_info = calculate_financial_exposure(
            asset_value=asset["asset_value"],
            exposure_factor=asset["exposure_factor"],
            threat_likelihood=v.get("threat_likelihood", 0.5),
            cvss_score=v["cvss_score"],
            exploitability=v["exploitability"]
        )
        
        base_score = risk_info["risk_score"]
        base_ale = fin_info["ale"]
        
        # Calculate Residuals if controls are active
        effects = control_effects_by_type.get(asset["asset_type"], {"risk_red_mult": 1.0, "loss_red_mult": 1.0})
        residual_score = round(base_score * effects["risk_red_mult"], 1)
        residual_ale = round(base_ale * effects["loss_red_mult"], 2)
        
        baseline_scores.append(base_score)
        residual_scores.append(residual_score)
        baseline_total_ale += base_ale
        residual_total_ale += residual_ale
        
        enriched_vulns.append({
            **v,
            "asset_name": asset["name"],
            "asset_type": asset["asset_type"],
            "asset_criticality": asset["criticality"],
            "asset_value": asset["asset_value"],
            "baseline_risk_score": base_score,
            "baseline_risk_level": risk_info["risk_level"],
            "baseline_sle": fin_info["sle"],
            "baseline_aro": fin_info["aro"],
            "baseline_ale": base_ale,
            "residual_risk_score": residual_score,
            "residual_risk_level": get_risk_level(residual_score),
            "residual_ale": residual_ale,
            "loss_avoided": round(base_ale - residual_ale, 2)
        })

    # Organization-wide normalized composite score (0-100)
    org_baseline_score = round(sum(baseline_scores) / max(len(baseline_scores), 1), 1)
    org_residual_score = round(sum(residual_scores) / max(len(residual_scores), 1), 1)
    
    overall_risk_reduction_pct = round(((org_baseline_score - org_residual_score) / max(org_baseline_score, 1)) * 100.0, 1)
    total_loss_avoided = round(baseline_total_ale - residual_total_ale, 2)

    return {
        "org_baseline_score": org_baseline_score,
        "org_baseline_level": get_risk_level(org_baseline_score),
        "org_residual_score": org_residual_score,
        "org_residual_level": get_risk_level(org_residual_score),
        "overall_risk_reduction_pct": overall_risk_reduction_pct,
        "total_asset_value": total_asset_value,
        "baseline_total_ale": round(baseline_total_ale, 2),
        "residual_total_ale": round(residual_total_ale, 2),
        "total_loss_avoided": total_loss_avoided,
        "vulnerabilities": enriched_vulns
    }

if __name__ == "__main__":
    # Test suite for Phase 2
    from database import get_db_connection
    import json
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM assets")
    assets = [dict(row) for row in c.fetchall()]
    
    c.execute("SELECT * FROM vulnerabilities")
    vulns = [dict(row) for row in c.fetchall()]
    conn.close()

    print("--- Phase 2 Test: Baseline Calculations ---")
    posture = evaluate_organization_risk(assets, vulns)
    print(f"Total Assets Evaluated: {len(assets)}")
    print(f"Total Vulnerabilities: {len(vulns)}")
    print(f"Org Baseline Risk Score: {posture['org_baseline_score']}/100 ({posture['org_baseline_level']})")
    print(f"Total Asset Value: Rs. {posture['total_asset_value']:,.2f}")
    print(f"Baseline Expected Annual Loss (ALE): Rs. {posture['baseline_total_ale']:,.2f}")
    
    print("\nTop 2 Highest Risk Assets & Financial Exposure:")
    sorted_v = sorted(posture['vulnerabilities'], key=lambda x: x['baseline_ale'], reverse=True)
    for v in sorted_v[:2]:
        print(f"  - [{v['cve_id']}] {v['asset_name']}: Score={v['baseline_risk_score']}, ALE=Rs. {v['baseline_ale']:,.2f}")
    
    print("\nPHASE 2 COMPLETE: Risk & Financial Quantification Engine tested successfully!")
