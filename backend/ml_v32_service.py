from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
_DEFAULT_V32_DIR = BASE_DIR / "ml" / "v32"
if not _DEFAULT_V32_DIR.exists():
    _DEFAULT_V32_DIR = PROJECT_ROOT / "ml" / "v32"
V32_DIR = Path(os.getenv("ML_V32_DIR", str(_DEFAULT_V32_DIR))).resolve()
MODEL_PATH = Path(
    os.getenv("ML_V32_MODEL_PATH", str(V32_DIR / "ttp_v32_final_7class_bundle.joblib"))
).resolve()
CONFIG_PATH = V32_DIR / "config_v32_final.json"
CODE_PATH = V32_DIR / "final_model.py"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _deep_get(data: Any, path: str, default: Any = None) -> Any:
    current = data
    for key in path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def _first(data_sources: list[Dict[str, Any]], paths: list[str], default: Any = None) -> Any:
    for source in data_sources:
        for path in paths:
            value = _deep_get(source, path, None)
            if value not in (None, "", [], {}):
                return value
    return default


def _maybe_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    text = value.strip()
    if not text.startswith("{"):
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except Exception:
        return default


def _iso_duration_seconds(start: Any, end: Any) -> float:
    if not start or not end:
        return 0.0
    try:
        from datetime import datetime
        def parse(value: Any):
            text = str(value).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            # Suricata often emits +0900; datetime.fromisoformat supports it.
            return datetime.fromisoformat(text)
        delta = (parse(end) - parse(start)).total_seconds()
        return max(0.0, float(delta))
    except Exception:
        return 0.0


def _safe_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {str(k): _safe_json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_json_value(v) for v in value]
    if hasattr(value, "item"):
        try:
            return _safe_json_value(value.item())
        except Exception:
            pass
    return str(value)


def _load_config() -> Dict[str, Any]:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


@lru_cache(maxsize=1)
def _classifier():
    if not CODE_PATH.exists():
        raise FileNotFoundError(f"V32 inference code not found: {CODE_PATH}")
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"V32 model not found: {MODEL_PATH}")

    spec = importlib.util.spec_from_file_location("opnsense_v32_final_model", CODE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to import V32 inference code: {CODE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.FinalClassifier.load(MODEL_PATH)


def model_status(load_model: bool = False) -> Dict[str, Any]:
    config = _load_config()
    expected = config.get("hashes", {}) if isinstance(config, dict) else {}
    model_hash = _sha256(MODEL_PATH) if MODEL_PATH.exists() else ""
    code_hash = _sha256(CODE_PATH) if CODE_PATH.exists() else ""
    warnings = []

    if expected.get("model_sha256") and expected.get("model_sha256") != model_hash:
        warnings.append("model hash does not match config_v32_final.json")
    if expected.get("code_sha256") and expected.get("code_sha256") != code_hash:
        warnings.append(
            "inference code hash differs from the frozen hash; the supplied package contains a documented display patch"
        )

    ready = MODEL_PATH.exists() and CODE_PATH.exists()
    load_error = ""
    if load_model and ready:
        try:
            _classifier()
        except Exception as exc:
            ready = False
            load_error = f"{type(exc).__name__}: {exc}"

    return {
        "version": config.get("version", "V32-FINAL"),
        "release_status": config.get("release_status", "unknown"),
        "ready": ready,
        "model_path": str(MODEL_PATH),
        "model_hash_ok": bool(model_hash and model_hash == expected.get("model_sha256")),
        "code_hash_ok": bool(code_hash and code_hash == expected.get("code_sha256")),
        "load_error": load_error,
        "warnings": warnings,
    }


def _extract_payload(row: Dict[str, Any]) -> Tuple[str, str]:
    raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
    message_json = row.get("messageJson") if isinstance(row.get("messageJson"), dict) else {}
    event_original_json = _maybe_json(row.get("event_original"))
    message_as_json = _maybe_json(row.get("message"))
    sources = [row, raw, message_json, event_original_json, message_as_json]

    payload = _first(
        sources,
        [
            "payload",
            "payload_printable",
            "suricata.eve.payload_printable",
            "http.request.body.content",
            "suricata.eve.http.request_body",
            "http.request_body",
        ],
        "",
    )
    if isinstance(payload, str) and payload.strip():
        return payload.strip(), "payload"

    method = str(
        _first(
            sources,
            ["http.request.method", "suricata.eve.http.http_method", "http.http_method", "http_method"],
            "GET",
        )
    ).upper()
    url = str(
        _first(
            sources,
            ["url.original", "suricata.eve.http.url", "http.url", "http.hostname", "url"],
            "",
        )
    )
    hostname = str(
        _first(
            sources,
            ["url.domain", "suricata.eve.http.hostname", "http.hostname", "destination.ip"],
            row.get("destination_ip", ""),
        )
    )
    user_agent = str(
        _first(
            sources,
            ["user_agent.original", "suricata.eve.http.http_user_agent", "http.http_user_agent"],
            "",
        )
    )

    if url:
        target = url if url.startswith("/") or "://" in url else f"/{url}"
        lines = [f"{method} {target} HTTP/1.1"]
        if hostname:
            lines.append(f"Host: {hostname}")
        if user_agent:
            lines.append(f"User-Agent: {user_agent}")
        return "\n".join(lines), "suricata_http"

    for field in ("event_original", "message"):
        value = row.get(field)
        if isinstance(value, str):
            text = value.strip()
            if text and not text.startswith("{") and (
                text.upper().startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD "))
                or any(token in text.lower() for token in ("<script", "union select", "../", "cmd.exe", "powershell"))
            ):
                return text, field

    return "", "missing"


def _extract_flow(row: Dict[str, Any]) -> Optional[Dict[str, float]]:
    raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
    message_json = row.get("messageJson") if isinstance(row.get("messageJson"), dict) else {}
    event_original_json = _maybe_json(row.get("event_original"))
    sources = [row, raw, message_json, event_original_json]

    to_server_pkts = _number(_first(sources, ["flow.pkts_toserver", "suricata.eve.flow.pkts_toserver"], 0))
    to_client_pkts = _number(_first(sources, ["flow.pkts_toclient", "suricata.eve.flow.pkts_toclient"], 0))
    to_server_bytes = _number(_first(sources, ["flow.bytes_toserver", "suricata.eve.flow.bytes_toserver"], 0))
    to_client_bytes = _number(_first(sources, ["flow.bytes_toclient", "suricata.eve.flow.bytes_toclient"], 0))

    pkts = _number(_first(sources, ["pkts", "network.packets"], to_server_pkts + to_client_pkts))
    byte_count = _number(_first(sources, ["bytes", "network.bytes"], to_server_bytes + to_client_bytes))
    duration = _number(
        _first(sources, ["duration", "flow.age", "suricata.eve.flow.age", "event.duration"], 0)
    )
    if duration > 1000000:
        duration /= 1_000_000_000.0
    if duration <= 0:
        start = _first(sources, ["flow.start", "suricata.eve.flow.start"], "")
        end = _first(sources, ["flow.end", "suricata.eve.flow.end"], "")
        duration = _iso_duration_seconds(start, end)

    if pkts <= 0 and byte_count <= 0 and duration <= 0:
        return None

    duration_for_rate = max(duration, 0.001)
    flags = str(_first(sources, ["tcp.tcp_flags", "suricata.eve.tcp.tcp_flags"], "")).upper()
    syn = _number(_first(sources, ["syn", "tcp.syn"], 1 if "S" in flags else 0))
    fin = _number(_first(sources, ["fin", "tcp.fin"], 1 if "F" in flags else 0))
    rst = _number(_first(sources, ["rst", "tcp.rst"], 1 if "R" in flags else 0))
    psh = _number(_first(sources, ["psh", "tcp.psh"], 1 if "P" in flags else 0))

    return {
        "pkts": pkts,
        "bytes": byte_count,
        "duration": duration,
        "pkts_per_sec": _number(_first(sources, ["pkts_per_sec"], pkts / duration_for_rate)),
        "bytes_per_sec": _number(_first(sources, ["bytes_per_sec"], byte_count / duration_for_rate)),
        "mean_iat": _number(
            _first(sources, ["mean_iat"], duration / max(pkts - 1.0, 1.0) if duration > 0 else 0)
        ),
        "syn": syn,
        "fin": fin,
        "rst": rst,
        "psh": psh,
        "syn_ratio": _number(_first(sources, ["syn_ratio"], syn / max(pkts, 1.0))),
    }


def predict_event(row: Dict[str, Any]) -> Dict[str, Any]:
    status = model_status(load_model=False)
    payload, payload_source = _extract_payload(row)
    if not payload:
        return {
            "available": False,
            "version": status["version"],
            "reason": "HTTP payload or URL was not present in this event",
            "payload_source": payload_source,
        }

    flow = _extract_flow(row)
    try:
        prediction = _classifier().predict_one(payload, flow)
    except Exception as exc:
        return {
            "available": False,
            "version": status["version"],
            "reason": f"{type(exc).__name__}: {exc}",
            "payload_source": payload_source,
        }

    result = _safe_json_value(prediction)
    return {
        "available": True,
        "version": status["version"],
        "prediction": result.get("final_pred", "Normal"),
        "confidence_percent": result.get("final_confidence_percent", 0.0),
        "confidence_basis": result.get("confidence_basis", ""),
        "result_display": result.get("result_display", ""),
        "main_result_display": result.get("main_result_display", ""),
        "secondary_result_display": result.get("secondary_result_display", ""),
        "stage1_prediction": result.get("stage1_pred", ""),
        "stage1_alert_percent": result.get("stage1_alert_percent", 0.0),
        "secondary_class": result.get("secondary_class", ""),
        "secondary_confidence_percent": result.get("secondary_confidence_percent"),
        "show_secondary": bool(result.get("show_secondary", False)),
        "flow_features_used": flow is not None,
        "payload_source": payload_source,
    }

