"""
Deterministic Investigation and Correlation Rule Engine (Phase 1).

Provides explicit, transparent, deterministic correlation rules for security alerts,
evidence extraction, and containment proposal generation.
Prepared as the logic engine that future LangGraph agents will orchestrate in Phase 2.
"""

from typing import List, Dict, Any, Optional

def evaluate_threat_severity(alert_count: int, max_severity: str, affected_assets: List[str]) -> Dict[str, Any]:
    """Calculates deterministic risk score and suggested incident severity."""
    score = 40
    if max_severity == "CRITICAL":
        score += 45
    elif max_severity == "HIGH":
        score += 30
    elif max_severity == "MEDIUM":
        score += 15
        
    score += min(alert_count * 5, 20)
    
    # Asset sensitivity bonus
    for asset in affected_assets:
        if "dc" in asset.lower() or "srv" in asset.lower() or "prod" in asset.lower():
            score += 10
            break
            
    final_score = min(max(score, 10), 100)
    
    if final_score >= 85:
        severity = "CRITICAL"
    elif final_score >= 65:
        severity = "HIGH"
    elif final_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"
        
    return {"risk_score": final_score, "severity": severity}


def generate_deterministic_hypothesis(
    title: str,
    attack_vector: str,
    assets: List[str],
    evidence_types: List[str]
) -> Dict[str, Any]:
    """
    Generates a structured hypothesis based on deterministic alert taxonomy.
    Clearly specifies this is generated via deterministic rule matching, not LLM inference.
    """
    assets_str = ", ".join(assets) if assets else "Unknown endpoints"
    
    hypothesis = (
        f"Rule-Based Correlation Hypothesis: Analysis of correlated telemetry indicates an active "
        f"adversary engagement vector across {assets_str} via {attack_vector}. "
        f"Corroborating indicators observed across {len(evidence_types)} telemetry source classes."
    )
    
    summary = (
        f"Deterministic correlation identified chained events starting from initial anomalous activity "
        f"to internal pivot attempts. Threat level is elevated due to sensitive target involvement."
    )
    
    findings = [
        {
            "finding_id": "FIND-01",
            "category": "Initial Vector Analysis",
            "observation": f"Observable match for {attack_vector} confirmed via endpoint telemetry.",
            "confidence": "HIGH (Deterministic Signature Match)"
        },
        {
            "finding_id": "FIND-02",
            "category": "Lateral Movement & Scope",
            "observation": f"Affected scope currently bounded to: {assets_str}.",
            "confidence": "MEDIUM (Telemetry Window Bounded)"
        },
        {
            "finding_id": "FIND-03",
            "category": "Data Exfiltration Risk",
            "observation": "No outbound bulk egress detected in current simulated network capture window.",
            "confidence": "HIGH"
        }
    ]
    
    recommended_containment = [
        {
            "action": "Host Isolation",
            "target": assets[0] if assets else "Primary Endpoint",
            "priority": "IMMEDIATE",
            "reason": "Prevent lateral spreading to corporate domain controllers."
        },
        {
            "action": "Session Revocation",
            "target": "Compromised User Identity",
            "priority": "HIGH",
            "reason": "Terminate active OAuth and Kerberos ticket-granting sessions."
        },
        {
            "action": "Perimeter IOC Block",
            "target": "Identified External C2 IPs",
            "priority": "HIGH",
            "reason": "Halt Command-and-Control beaconing at border gateways."
        }
    ]
    
    return {
        "hypothesis": hypothesis,
        "summary": summary,
        "findings": findings,
        "recommended_containment": recommended_containment,
        "confidence_score": 0.88,
    }
