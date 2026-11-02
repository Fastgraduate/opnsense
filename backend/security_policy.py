from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable


DEFAULT_ALLOWED_CLASSES = [
    "Cross_Site_Scripting",
    "SQL_Injection",
    "System_Cmd_Execution",
]

ML_CLASS_BASE_RISK = {
    "Normal": 0,
    "HOST_Scan": 45,
    "Vulnerability_Scan": 68,
    "Cross_Site_Scripting": 75,
    "SQL_Injection": 78,
    "Path_Disclosure": 70,
    "System_Cmd_Execution": 85,
}


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def risk_level(score: int) -> Dict[str, str]:
    if score >= 90:
        return {"level": "critical", "label": "매우 높음", "recommended_action": "auto_block_candidate"}
    if score >= 70:
        return {"level": "high", "label": "높음", "recommended_action": "approval_required"}
    if score >= 40:
        return {"level": "medium", "label": "중간", "recommended_action": "watch"}
    return {"level": "low", "label": "낮음", "recommended_action": "notify"}


def ml_risk_component(ml: Dict[str, Any], occurrences: int = 1) -> Dict[str, Any]:
    if not ml.get("available"):
        return {"score": 0, "reasons": ["V32 prediction unavailable"]}

    prediction = str(ml.get("prediction") or "Normal")
    confidence = _clamp(float(ml.get("confidence_percent") or 0.0), 0.0, 100.0)
    base = ML_CLASS_BASE_RISK.get(prediction, 50)
    if prediction == "Normal":
        return {"score": 0, "reasons": [f"V32 Normal {confidence:.1f}%"]}

    confidence_bonus = int(max(0.0, confidence - 50.0) * 0.30)
    repeat_bonus = min(15, max(0, int(occurrences) - 1) * 4)
    score = int(_clamp(base + confidence_bonus + repeat_bonus, 0, 100))
    return {
        "score": score,
        "reasons": [
            f"V32 {prediction} base +{base}",
            f"V32 confidence {confidence:.1f}% +{confidence_bonus}",
            f"repeated source {max(1, int(occurrences))} +{repeat_bonus}",
        ],
    }


def ip_in_allowlist(ip_text: str, allowlist: Iterable[str]) -> bool:
    try:
        ip = ipaddress.ip_address(str(ip_text).strip())
    except Exception:
        return True

    for entry in allowlist:
        text = str(entry).strip()
        if not text:
            continue
        try:
            if "/" in text and ip in ipaddress.ip_network(text, strict=False):
                return True
            if "/" not in text and ip == ipaddress.ip_address(text):
                return True
        except Exception:
            continue
    return False


def evaluate_auto_block(
    *,
    settings: Dict[str, Any],
    risk: Dict[str, Any],
    ml: Dict[str, Any],
    source_ip: str,
    occurrences: int,
    corroborated: bool,
    private_or_reserved: bool,
) -> Dict[str, Any]:
    score = int(risk.get("score") or 0)
    prediction = str(ml.get("prediction") or "")
    confidence = float(ml.get("confidence_percent") or 0.0)
    reasons = []

    if score < 40:
        action = "notify"
    elif score < 70:
        action = "watch"
    elif score < int(settings.get("risk_threshold", 90)):
        action = "approval_required"
    else:
        action = "auto_block_candidate"

    blockers = []
    if not settings.get("enabled", False):
        blockers.append("automation disabled")
    if not ml.get("available", False):
        blockers.append("V32 prediction unavailable")
    if prediction not in set(settings.get("allowed_classes") or DEFAULT_ALLOWED_CLASSES):
        blockers.append(f"class {prediction or 'unknown'} is not in the auto-block class list")
    if score < int(settings.get("risk_threshold", 90)):
        blockers.append("risk score below threshold")
    if confidence < float(settings.get("confidence_threshold", 85.0)):
        blockers.append("ML confidence below threshold")
    if int(occurrences) < int(settings.get("min_occurrences", 3)):
        blockers.append("not enough repeated events from the source")
    if settings.get("require_suricata_confirmation", True) and not corroborated:
        blockers.append("Suricata alert/drop confirmation missing")
    if not source_ip or source_ip == "-":
        blockers.append("source IP missing")
    if private_or_reserved and not settings.get("allow_private", False):
        blockers.append("private/reserved/local IP is protected")
    if ip_in_allowlist(source_ip, settings.get("allowlist", [])):
        blockers.append("source IP is allowlisted")

    if blockers:
        reasons.extend(blockers)
        return {"eligible": False, "action": action, "reasons": reasons}

    action = "auto_block_dry_run" if settings.get("dry_run", True) else "auto_block"
    return {
        "eligible": True,
        "action": action,
        "reasons": [
            f"risk {score} >= {int(settings.get('risk_threshold', 90))}",
            f"V32 {prediction} {confidence:.1f}%",
            f"source repeated {int(occurrences)} times",
            "Suricata confirmation present",
        ],
    }

