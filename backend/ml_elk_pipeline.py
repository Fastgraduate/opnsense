from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests

try:
    from .ml_v32_service import model_status, predict_event
except ImportError:
    from ml_v32_service import model_status, predict_event


PIPELINE_VERSION = "v32-elk-enricher-1"


def _env_int(name: str, default: int, minimum: int = 1, maximum: Optional[int] = None) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except Exception:
        value = default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def pipeline_config() -> Dict[str, Any]:
    return {
        "enabled": os.getenv("ML_PIPELINE_ENABLED", "false").strip().lower() in {"1", "true", "yes", "y", "on"},
        "interval_seconds": _env_int("ML_PIPELINE_INTERVAL_SECONDS", 5, 1, 3600),
        "batch_size": _env_int("ML_PIPELINE_BATCH_SIZE", 100, 1, 500),
        "lookback_minutes": _env_int("ML_PIPELINE_LOOKBACK_MINUTES", 180, 1, 5256000),
        "mark_skipped": os.getenv("ML_PIPELINE_MARK_SKIPPED", "true").strip().lower() in {"1", "true", "yes", "y", "on"},
    }


def _candidate_query(batch_size: int, lookback_minutes: int, force: bool = False) -> Dict[str, Any]:
    filters = [
        {"range": {"@timestamp": {"gte": f"now-{max(1, lookback_minutes)}m", "lte": "now"}}},
    ]
    must_not = []
    if not force:
        must_not.extend([
            {"exists": {"field": "main_result_display"}},
            {"exists": {"field": "ml_pipeline_checked_at"}},
        ])

    # The V32 model needs a payload-like input. We query only events that have
    # raw payload/HTTP request material or textual originals that may contain it.
    should = [
        {"exists": {"field": "payload"}},
        {"exists": {"field": "payload_printable"}},
        {"exists": {"field": "suricata.eve.payload"}},
        {"exists": {"field": "suricata.eve.payload_printable"}},
        {"exists": {"field": "http.request.body.content"}},
        {"exists": {"field": "suricata.eve.http.url"}},
        {"exists": {"field": "url.original"}},
        {"exists": {"field": "event.original"}},
        {"exists": {"field": "message"}},
    ]

    return {
        "size": max(1, min(int(batch_size), 500)),
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "_source": True,
        "query": {
            "bool": {
                "filter": filters,
                "must_not": must_not,
                "should": should,
                "minimum_should_match": 1,
            }
        },
    }


def _row_from_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
    src = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
    return {
        "_id": hit.get("_id", ""),
        "_index": hit.get("_index", ""),
        "raw": src,
        "message": src.get("message", ""),
        "event_original": ((src.get("event") or {}).get("original", "") if isinstance(src.get("event"), dict) else ""),
        "source_ip": ((src.get("source") or {}).get("ip", "") if isinstance(src.get("source"), dict) else ""),
        "destination_ip": ((src.get("destination") or {}).get("ip", "") if isinstance(src.get("destination"), dict) else ""),
    }


def _analysis_doc(result: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    prediction = str(result.get("prediction") or "")
    confidence = result.get("confidence_percent")
    return {
        "final_pred": prediction,
        "detected_class": prediction,
        "final_confidence_percent": confidence,
        "detected_confidence_percent": confidence,
        "main_result_display": result.get("main_result_display", ""),
        "secondary_result_display": result.get("secondary_result_display", ""),
        "show_secondary": bool(result.get("show_secondary", False)),
        "result_display": result.get("result_display", ""),
        "secondary_class": result.get("secondary_class", ""),
        "secondary_confidence_percent": result.get("secondary_confidence_percent"),
        "ml_model_version": result.get("version", "V32-FINAL"),
        "ml_input_source": result.get("payload_source", ""),
        "ml_flow_features_used": bool(result.get("flow_features_used", False)),
        "ml_pipeline_status": "analyzed",
        "ml_pipeline_version": PIPELINE_VERSION,
        "ml_pipeline_checked_at": now,
    }


def _skip_doc(result: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "ml_pipeline_status": "skipped",
        "ml_pipeline_version": PIPELINE_VERSION,
        "ml_pipeline_checked_at": now,
        "ml_skip_reason": str(result.get("reason") or "V32 input unavailable"),
        "ml_input_source": str(result.get("payload_source") or "missing"),
        "ml_model_version": str(result.get("version") or "V32-FINAL"),
    }


def _error_doc(exc: Exception) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "ml_pipeline_status": "error",
        "ml_pipeline_version": PIPELINE_VERSION,
        "ml_pipeline_checked_at": now,
        "ml_pipeline_error": f"{type(exc).__name__}: {exc}"[:1000],
    }


def run_pipeline_batch(
    *,
    target: Dict[str, Any],
    base_url: str,
    log_index: str,
    headers: Dict[str, str],
    auth: Any,
    verify_ssl: bool,
    batch_size: int,
    lookback_minutes: int,
    force: bool = False,
    mark_skipped: bool = True,
) -> Dict[str, Any]:
    if not base_url:
        raise RuntimeError("Elastic URL is empty")
    if not log_index:
        raise RuntimeError("Elastic log index is empty")

    model = model_status(load_model=True)
    if not model.get("ready"):
        raise RuntimeError(model.get("load_error") or "V32 model is not ready")

    search_url = f"{base_url.rstrip('/')}/{quote(log_index, safe='*,-_.')}/_search"
    response = requests.post(
        search_url,
        headers=headers,
        auth=auth,
        json=_candidate_query(batch_size, lookback_minutes, force=force),
        verify=verify_ssl,
        timeout=(5, 30),
    )
    response.raise_for_status()
    hits = response.json().get("hits", {}).get("hits", [])

    analyzed = 0
    skipped = 0
    failed = 0
    updates = []

    for hit in hits:
        index_name = str(hit.get("_index") or "")
        doc_id = str(hit.get("_id") or "")
        if not index_name or not doc_id:
            failed += 1
            continue

        try:
            result = predict_event(_row_from_hit(hit))
            if result.get("available"):
                doc = _analysis_doc(result)
                analyzed += 1
            else:
                if not mark_skipped:
                    skipped += 1
                    continue
                doc = _skip_doc(result)
                skipped += 1
        except Exception as exc:
            doc = _error_doc(exc)
            failed += 1

        update_url = (
            f"{base_url.rstrip('/')}/{quote(index_name, safe='-_.')}/_update/"
            f"{quote(doc_id, safe='')}"
        )
        update_response = requests.post(
            update_url,
            headers=headers,
            auth=auth,
            json={"doc": doc},
            verify=verify_ssl,
            timeout=(5, 30),
        )
        if not update_response.ok:
            failed += 1
            updates.append({
                "index": index_name,
                "id": doc_id,
                "ok": False,
                "status": update_response.status_code,
                "error": update_response.text[:500],
            })
            continue
        updates.append({
            "index": index_name,
            "id": doc_id,
            "ok": True,
            "ml_status": doc.get("ml_pipeline_status"),
            "display": doc.get("main_result_display", ""),
        })

    return {
        "firewall_id": target.get("id"),
        "firewall_name": target.get("name"),
        "index": log_index,
        "candidates": len(hits),
        "analyzed": analyzed,
        "skipped": skipped,
        "failed": failed,
        "model": model,
        "updates": updates,
    }


def pipeline_diagnostics(
    *,
    base_url: str,
    log_index: str,
    headers: Dict[str, str],
    auth: Any,
    verify_ssl: bool,
    lookback_minutes: int = 180,
) -> Dict[str, Any]:
    base = base_url.rstrip('/')
    index_path = quote(log_index, safe='*,-_.')
    recent_filter = {"range": {"@timestamp": {"gte": f"now-{max(1, int(lookback_minutes))}m", "lte": "now"}}}

    queries = {
        "recent_total": {"bool": {"filter": [recent_filter]}},
        "analyzed": {"bool": {"filter": [recent_filter, {"exists": {"field": "main_result_display"}}]}},
        "payload": {"bool": {"filter": [recent_filter, {"exists": {"field": "payload"}}]}},
        "payload_printable": {"bool": {"filter": [recent_filter, {"exists": {"field": "payload_printable"}}]}},
        "suricata_payload_printable": {"bool": {"filter": [recent_filter, {"exists": {"field": "suricata.eve.payload_printable"}}]}},
        "http_url": {
            "bool": {
                "filter": [recent_filter],
                "should": [
                    {"exists": {"field": "suricata.eve.http.url"}},
                    {"exists": {"field": "url.original"}},
                    {"exists": {"field": "http.request.body.content"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "suricata_alerts": {"bool": {"filter": [recent_filter, {"exists": {"field": "suricata.eve.alert.signature"}}]}},
        "pipeline_skipped": {"bool": {"filter": [recent_filter, {"term": {"ml_pipeline_status.keyword": "skipped"}}]}},
        "pipeline_errors": {"bool": {"filter": [recent_filter, {"term": {"ml_pipeline_status.keyword": "error"}}]}},
    }

    counts: Dict[str, int] = {}
    for name, query in queries.items():
        response = requests.post(
            f"{base}/{index_path}/_count",
            headers=headers,
            auth=auth,
            json={"query": query},
            verify=verify_ssl,
            timeout=(5, 20),
        )
        if response.status_code == 400 and name in {"pipeline_skipped", "pipeline_errors"}:
            # If the status field was dynamically mapped as text without .keyword.
            fallback_status = "skipped" if name == "pipeline_skipped" else "error"
            response = requests.post(
                f"{base}/{index_path}/_count",
                headers=headers,
                auth=auth,
                json={"query": {"bool": {"filter": [recent_filter, {"match_phrase": {"ml_pipeline_status": fallback_status}}]}}},
                verify=verify_ssl,
                timeout=(5, 20),
            )
        response.raise_for_status()
        counts[name] = int(response.json().get("count", 0))

    counts["model_input_candidates"] = (
        counts.get("payload", 0)
        + counts.get("payload_printable", 0)
        + counts.get("suricata_payload_printable", 0)
        + counts.get("http_url", 0)
    )
    return {
        "index": log_index,
        "lookback_minutes": max(1, int(lookback_minutes)),
        "counts": counts,
        "note": "V32 requires payload-like text; Suricata alert count alone does not guarantee ML-classifiable input.",
    }
