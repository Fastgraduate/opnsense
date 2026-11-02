import json
import csv
import base64
import os
import re
import html
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urljoin

import requests
import urllib3
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from .manual_response import ManualResponse, ResponseError, contents
    from .elk_results import decorate, is_attack
    from .ml_v32_service import model_status as ml_model_status, predict_event as ml_predict_event
    from .ml_elk_pipeline import pipeline_config as ml_pipeline_config, pipeline_diagnostics, run_pipeline_batch
except ImportError:
    from manual_response import ManualResponse, ResponseError, contents
    from elk_results import decorate, is_attack
    from ml_v32_service import model_status as ml_model_status, predict_event as ml_predict_event
    from ml_elk_pipeline import pipeline_config as ml_pipeline_config, pipeline_diagnostics, run_pipeline_batch

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# =========================
# 환경변수 파싱
# =========================
def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


APP_ENCRYPTION_KEY = os.getenv("APP_ENCRYPTION_KEY", "").strip()

OPNSENSE_TIMEOUT = int(os.getenv("OPNSENSE_TIMEOUT", "20"))
if not OPNSENSE_TIMEOUT:
    OPNSENSE_TIMEOUT = 20

OPNSENSE_VERIFY_SSL = parse_bool(os.getenv("OPNSENSE_VERIFY_SSL"), default=False)

# Legacy optional global Elastic defaults
ELASTIC_URL = os.getenv("ELASTIC_URL", "").strip().rstrip("/")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "").strip()
ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME", "").strip()
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "").strip()
ELASTIC_VERIFY_SSL = parse_bool(os.getenv("ELASTIC_VERIFY_SSL"), default=False)

# 하나라도 self-signed 환경이면 경고 비활성화
if not OPNSENSE_VERIFY_SSL or not ELASTIC_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FIREWALLS_FILE = BASE_DIR / "firewalls.json"

app = FastAPI(title="Multi Firewall Dashboard Backend")
try:
    from .auth import install_auth
except ImportError:
    from auth import install_auth

AUTH_ALLOWED_ORIGINS = [value.strip().rstrip('/') for value in os.getenv(
    'AUTH_ALLOWED_ORIGINS',
    'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173'
).split(',') if value.strip()]
install_auth(app, BASE_DIR, AUTH_ALLOWED_ORIGINS)
# CORS must be outside authentication so error responses also carry CORS headers.
app.add_middleware(
    CORSMiddleware, allow_origins=AUTH_ALLOWED_ORIGINS,
    allow_credentials=True, allow_methods=['*'], allow_headers=['*'],
)


# =========================
# 요청 바디 모델
# =========================
class FirewallCreateBody(BaseModel):
    name: str = Field(min_length=1)
    host: str = Field(min_length=1)
    api_key: str = Field(min_length=1)
    api_secret: str = Field(min_length=1)
    verify_ssl: bool = False
    log_index: str = "logs-suricata.eve-*"
    event_log_index: str = "opnsense-firewall-*"
    description: str = ""
    elastic_url: str = ""
    elastic_api_key: str = ""
    elastic_username: str = ""
    elastic_password: str = ""
    elastic_verify_ssl: bool = False


class FirewallUpdateBody(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    verify_ssl: Optional[bool] = None
    log_index: Optional[str] = None
    event_log_index: Optional[str] = None
    description: Optional[str] = None
    elastic_url: Optional[str] = None
    elastic_api_key: Optional[str] = None
    elastic_username: Optional[str] = None
    elastic_password: Optional[str] = None
    elastic_verify_ssl: Optional[bool] = None


class RuleCreateBody(BaseModel):
    description: str = ""
    action: str = "pass"
    interface: str = "lan"
    direction: str = "in"
    protocol: str = "TCP"
    sourceNet: str = "any"
    sourcePort: str = ""
    destinationNet: str = "any"
    destinationPort: str = ""
    enabled: str = "1"
    quick: str = "1"
    log: bool = False


class EventLogsQueryBody(BaseModel):
    size: int = 50
    minutes: int = 60
    action: str = ""
    interface: str = ""
    protocol: str = ""
    source: str = ""
    destination: str = ""
    query: str = ""


class OpnsenseLogFilter(BaseModel):
    search: Optional[str] = ""
    field: Optional[str] = "any"
    operator: Optional[str] = "contains"
    tableSize: Optional[int] = 25
    historySize: Optional[int] = 300
    # Legacy full-archive mode kept for compatibility.
    fetchAll: Optional[bool] = False
    pageSize: Optional[int] = 500
    maxRows: Optional[int] = 50000
    resolveHostnames: Optional[bool] = False
    onlyImportant: Optional[bool] = False
    # Optimized server-side view. The browser only receives one page while the
    # backend keeps a short-lived archive cache for the selected time range.
    serverView: Optional[bool] = False
    minutes: Optional[int] = 60
    page: Optional[int] = 1
    includeHistogram: Optional[bool] = True
    protocol: Optional[str] = ""
    source: Optional[str] = ""
    destination: Optional[str] = ""
    interface: Optional[str] = ""
    action: Optional[str] = ""
    forceRefresh: Optional[bool] = False
    fromMs: Optional[int] = None
    toMs: Optional[int] = None


class AliasAddressBody(BaseModel):
    address: str


class MlPipelineRunBody(BaseModel):
    batch_size: int = 100
    lookback_minutes: int = 180
    force: bool = False


class MlPredictBody(BaseModel):
    payload: str
    flow: Optional[Dict[str, Any]] = None


# =========================
# security / storage
# =========================
def ensure_encryption_key() -> Fernet:
    if not APP_ENCRYPTION_KEY:
        raise HTTPException(status_code=500, detail="APP_ENCRYPTION_KEY 누락")
    try:
        return Fernet(APP_ENCRYPTION_KEY.encode())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"APP_ENCRYPTION_KEY 오류: {exc}")


def encrypt_text(text: str) -> str:
    return ensure_encryption_key().encrypt(text.encode()).decode()


def decrypt_text(token: str) -> str:
    return ensure_encryption_key().decrypt(token.encode()).decode()


def load_firewalls() -> List[Dict[str, Any]]:
    if not FIREWALLS_FILE.exists():
        return []
    try:
        return json.loads(FIREWALLS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_firewalls(items: List[Dict[str, Any]]) -> None:
    FIREWALLS_FILE.write_text(
        json.dumps(items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def next_firewall_id(items: List[Dict[str, Any]]) -> int:
    return max([int(x.get("id", 0)) for x in items] + [0]) + 1


def serialize_firewall(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": item["id"],
        "name": item["name"],
        "host": item["host"],
        "verify_ssl": item.get("verify_ssl", OPNSENSE_VERIFY_SSL),
        "log_index": item.get("log_index", "logs-suricata.eve-*"),
        "event_log_index": item.get("event_log_index", ""),
        "description": item.get("description", ""),
        "has_secret": bool(item.get("api_key_enc") and item.get("api_secret_enc")),
        "elastic": {
            "enabled": bool(item.get("elastic_url") or ELASTIC_URL),
            "url": item.get("elastic_url", ""),
            "verify_ssl": item.get("elastic_verify_ssl", ELASTIC_VERIFY_SSL),
            "has_api_key": bool(item.get("elastic_api_key_enc")),
            "has_username_password": bool(
                item.get("elastic_username") and item.get("elastic_password_enc")
            ),
        },
        "created_at": item.get("created_at", 0),
        "updated_at": item.get("updated_at", 0),
    }


def get_firewall_or_404(firewall_id: int) -> Dict[str, Any]:
    for item in load_firewalls():
        if int(item.get("id", 0)) == firewall_id:
            return item
    raise HTTPException(status_code=404, detail="방화벽을 찾을 수 없습니다.")


# =========================
# shared helpers
# =========================
def opnsense_request(
    target: Dict[str, Any],
    method: str,
    path: str,
    json_data: Optional[Dict[str, Any]] = None,
) -> Any:
    host = str(target.get("host", "")).strip().rstrip("/")
    if not host:
        raise HTTPException(status_code=500, detail="방화벽 host 누락")

    url = f"{host}{path}"
    headers: Dict[str, str] = {}
    if json_data is not None:
        headers["Content-Type"] = "application/json"

    api_key = decrypt_text(target["api_key_enc"])
    api_secret = decrypt_text(target["api_secret_enc"])

    verify_ssl = bool(target.get("verify_ssl", OPNSENSE_VERIFY_SSL))

    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            auth=(api_key, api_secret),
            json=json_data,
            verify=verify_ssl,
            timeout=(5, OPNSENSE_TIMEOUT),
            headers=headers,
        )
    except requests.exceptions.ConnectTimeout:
        raise HTTPException(status_code=504, detail=f"OPNsense 연결 시간 초과: {url}")
    except requests.exceptions.ReadTimeout:
        raise HTTPException(status_code=504, detail=f"OPNsense 응답 시간 초과: {url}")
    except requests.exceptions.ConnectionError as e:
        raise HTTPException(status_code=502, detail=f"OPNsense 연결 실패: {str(e)}")
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"요청 중 예외 발생: {str(e)}")

    try:
        data = response.json()
    except ValueError:
        data = {"raw_text": response.text}

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail={
                "message": "OPNsense API 오류",
                "url": url,
                "response": data,
            },
        )
    return data


def safe_block(
    target: Dict[str, Any],
    path: str,
    method: str = "GET",
    json_data: Optional[Dict[str, Any]] = None,
    default: Optional[Any] = None,
):
    try:
        return opnsense_request(target, method, path, json_data=json_data)
    except Exception as e:
        if default is None:
            default = {}
        if isinstance(default, dict):
            return {**default, "error": str(e)}
        return {"data": default, "error": str(e)}


def safe_apply_firewall(target: Dict[str, Any]):
    for path in ["/api/firewall/filter_base/apply", "/api/firewall/filter/apply"]:
        try:
            return opnsense_request(target, "POST", path, json_data={})
        except Exception:
            continue
    return {"warning": "apply endpoint failed or not supported"}


def to_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _flatten_dict(data: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(data, dict):
        for key, value in data.items():
            new_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_dict(value, new_prefix)
    else:
        yield prefix, data


def _to_int(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().replace(",", "")
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(float(text))
    except Exception:
        return 0


def _normalize_key(key: str) -> str:
    return "".join(ch for ch in key.lower() if ch.isalnum())


def _pick_first(flat: Dict[str, Any], candidates: List[str]) -> int:
    normalized_candidates = [_normalize_key(x) for x in candidates]
    for raw_key, raw_value in flat.items():
        nk = _normalize_key(raw_key)
        if nk in normalized_candidates:
            return _to_int(raw_value)
    for raw_key, raw_value in flat.items():
        nk = _normalize_key(raw_key)
        for candidate in normalized_candidates:
            if candidate in nk:
                return _to_int(raw_value)
    return 0


# =========================
# summaries
# =========================
def summarize_system(system_raw: Any) -> Dict[str, Any]:
    if not isinstance(system_raw, dict):
        return {
            "hostname": "-",
            "platform": "-",
            "cpu_arch": "-",
            "uptime": "-",
            "updates": "-",
            "versions": [],
        }
    versions = system_raw.get("versions", [])
    if not isinstance(versions, list):
        versions = []

    firmware_line = versions[0] if len(versions) > 0 else ""
    platform_line = versions[1] if len(versions) > 1 else ""
    ssl_line = versions[2] if len(versions) > 2 else ""

    cpu_arch = "-"
    if isinstance(firmware_line, str) and "-" in firmware_line:
        cpu_arch = firmware_line.split("-")[-1].upper()

    return {
        "hostname": system_raw.get("name", "-"),
        "platform": platform_line or "-",
        "cpu_arch": cpu_arch,
        "uptime": "-",
        "firmware_line": firmware_line or "-",
        "ssl_line": ssl_line or "-",
        "updates": system_raw.get("updates", "-"),
        "versions": versions,
    }


def summarize_memory(memory_raw: Any) -> Dict[str, Any]:
    if not isinstance(memory_raw, dict):
        return {
            "total": 0,
            "used": 0,
            "free": 0,
            "used_percent": 0.0,
            "source": "unavailable",
        }

    vmstat = memory_raw.get("vmstat", {}) if isinstance(memory_raw, dict) else {}
    flat = dict(_flatten_dict(vmstat))

    page_size = _pick_first(flat, [
        "v_page_size", "pagesize", "hw.pagesize", "vm.stats.vm.v_page_size"
    ])
    page_count = _pick_first(flat, [
        "v_page_count", "pagecount", "vm.stats.vm.v_page_count"
    ])
    physmem_bytes = _pick_first(flat, [
        "hw.physmem", "physmem", "realmem"
    ])
    free_count = _pick_first(flat, [
        "v_free_count", "freecount", "vm.stats.vm.v_free_count"
    ])
    inactive_count = _pick_first(flat, [
        "v_inactive_count", "inactivecount", "vm.stats.vm.v_inactive_count"
    ])
    cache_count = _pick_first(flat, [
        "v_cache_count", "cachecount", "vm.stats.vm.v_cache_count"
    ])
    laundry_count = _pick_first(flat, [
        "v_laundry_count", "laundrycount", "vm.stats.vm.v_laundry_count"
    ])

    total = physmem_bytes if physmem_bytes > 0 else (
        page_size * page_count if page_size > 0 and page_count > 0 else 0
    )

    available = 0
    if page_size > 0:
        available_pages = free_count + inactive_count + cache_count + laundry_count
        available = available_pages * page_size

    if total > 0:
        available = max(min(available, total), 0)
        used = max(total - available, 0)
        return {
            "total": int(total),
            "used": int(used),
            "free": int(available),
            "used_percent": round((used / total) * 100, 1) if total > 0 else 0.0,
            "source": "vmstat-system-memory",
        }

    zone_stats = vmstat.get("memory-zone-statistics", {})
    zones = zone_stats.get("zone", [])
    if not isinstance(zones, list) or len(zones) == 0:
        return {
            "total": 0,
            "used": 0,
            "free": 0,
            "used_percent": 0.0,
            "source": "no-zone-data",
        }

    total_bytes = 0
    used_bytes = 0
    free_bytes = 0

    for zone in zones:
        if not isinstance(zone, dict):
            continue
        size = to_int(zone.get("size"))
        used = to_int(zone.get("used"))
        free = to_int(zone.get("free"))
        if size <= 0:
            continue
        used_bytes += size * used
        free_bytes += size * free
        total_bytes += size * (used + free)

    return {
        "total": int(total_bytes),
        "used": int(used_bytes),
        "free": int(free_bytes),
        "used_percent": round((used_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0.0,
        "source": "memory-zone-statistics-fallback",
    }


def summarize_disk(disk_raw: Any) -> Dict[str, Any]:
    devices = (
        disk_raw.get("devices", [])
        if isinstance(disk_raw, dict)
        else disk_raw if isinstance(disk_raw, list) else []
    )
    if not isinstance(devices, list):
        devices = []

    root_device = None
    for device in devices:
        if isinstance(device, dict) and device.get("mountpoint") == "/":
            root_device = device
            break

    if root_device is None and devices:
        root_device = devices[0]

    if not isinstance(root_device, dict):
        return {
            "device": "-",
            "mountpoint": "-",
            "blocks": "0 B",
            "used": "0 B",
            "available": "0 B",
            "used_pct": 0,
        }

    return {
        "device": root_device.get("device", "-"),
        "mountpoint": root_device.get("mountpoint", "-"),
        "blocks": root_device.get("blocks", "0 B"),
        "used": root_device.get("used", "0 B"),
        "available": root_device.get("available", "0 B"),
        "used_pct": root_device.get("used_pct", 0),
    }


# =========================
# elastic helpers
# =========================
def _elastic_url(target: Dict[str, Any]) -> str:
    return str(target.get("elastic_url") or ELASTIC_URL).strip().rstrip("/")


def _elastic_verify_ssl(target: Dict[str, Any]) -> bool:
    if "elastic_verify_ssl" in target:
        return bool(target.get("elastic_verify_ssl", ELASTIC_VERIFY_SSL))
    return ELASTIC_VERIFY_SSL


def _decrypt_optional(token: Any) -> str:
    if not token:
        return ""
    try:
        return decrypt_text(str(token))
    except Exception:
        return ""


def _has_target_elastic_basic_auth(target: Dict[str, Any]) -> bool:
    """
    개별 방화벽에 Elastic username/password가 저장되어 있으면
    글로벌 ELASTIC_API_KEY보다 해당 방화벽의 Basic 인증을 우선한다.

    기존 구현은 firewall별 API key가 비어 있으면 .env의 글로벌 API key를
    먼저 사용해서, 팀 ELK의 username/password가 무시될 수 있었다.
    """
    return bool(
        str(target.get("elastic_username") or "").strip()
        or target.get("elastic_password_enc")
    )


def elastic_headers(target: Dict[str, Any]) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}

    # 1) 방화벽별 API key가 있으면 최우선.
    target_api_key = _decrypt_optional(target.get("elastic_api_key_enc"))
    if target_api_key:
        headers["Authorization"] = f"ApiKey {target_api_key}"
        return headers

    # 2) 방화벽별 Basic 인증이 설정되어 있으면 글로벌 API key를 섞지 않는다.
    if _has_target_elastic_basic_auth(target):
        return headers

    # 3) 개별 인증 설정이 전혀 없을 때만 글로벌 API key fallback.
    if ELASTIC_API_KEY:
        headers["Authorization"] = f"ApiKey {ELASTIC_API_KEY}"

    return headers


def elastic_auth(target: Dict[str, Any]):
    # 방화벽별 API key가 있으면 requests auth는 사용하지 않는다.
    if _decrypt_optional(target.get("elastic_api_key_enc")):
        return None

    # 방화벽별 Basic 인증을 글로벌 인증보다 우선한다.
    target_username = str(target.get("elastic_username") or "").strip()
    target_password = _decrypt_optional(target.get("elastic_password_enc"))
    if target_username or target.get("elastic_password_enc"):
        if target_username and target_password:
            return (target_username, target_password)
        return None

    # 개별 인증이 없고 글로벌 API key가 있으면 Authorization header 사용.
    if ELASTIC_API_KEY:
        return None

    if ELASTIC_USERNAME and ELASTIC_PASSWORD:
        return (ELASTIC_USERNAME, ELASTIC_PASSWORD)

    return None


def ensure_elastic_config(target: Dict[str, Any]):
    url = _elastic_url(target)
    if not url:
        raise HTTPException(status_code=400, detail="이 방화벽의 Elastic URL이 설정되지 않았습니다.")

    headers = elastic_headers(target)
    auth = elastic_auth(target)

    if not headers.get("Authorization") and not auth:
        raise HTTPException(status_code=400, detail="이 방화벽의 Elastic 인증 정보가 없습니다.")

def get_nested(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur = data
    for key in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


# =========================
# Kibana Discover compatible CSV export helpers
# =========================
KIBANA_EXPORT_COLUMNS = [
    "@timestamp",
    "_id",
    "_index",
    "_score",
    "_type",
    "agent.ephemeral_id",
    "agent.hostname",
    "agent.id",
    "agent.name",
    "agent.type",
    "agent.version",
    "ecs.version",
    "host.name",
    "input.type",
    "log.file.path",
    "log.offset",
    "message",
]


def parse_suricata_message(message: Any) -> Dict[str, Any]:
    if not isinstance(message, str) or not message.strip():
        return {}

    try:
        parsed = json.loads(message)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def build_kibana_export_row(hit: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "@timestamp": src.get("@timestamp", ""),
        "_id": hit.get("_id", ""),
        "_index": hit.get("_index", ""),
        "_score": hit.get("_score", ""),
        "_type": hit.get("_type", "_doc"),
        "agent.ephemeral_id": get_nested(src, "agent.ephemeral_id", ""),
        "agent.hostname": get_nested(src, "agent.hostname", ""),
        "agent.id": get_nested(src, "agent.id", ""),
        "agent.name": get_nested(src, "agent.name", ""),
        "agent.type": get_nested(src, "agent.type", ""),
        "agent.version": get_nested(src, "agent.version", ""),
        "ecs.version": get_nested(src, "ecs.version", ""),
        "host.name": get_nested(src, "host.name", ""),
        "input.type": get_nested(src, "input.type", ""),
        "log.file.path": get_nested(src, "log.file.path", ""),
        "log.offset": get_nested(src, "log.offset", ""),
        "message": src.get("message", ""),
    }


def _elastic_field_value(value: Any, default: Any = "") -> Any:
    if value is None:
        return default
    if isinstance(value, list):
        return value[0] if value else default
    return value


def _elastic_fields_to_source(fields: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if not isinstance(fields, dict):
        return result

    for dotted_key, raw_value in fields.items():
        key_text = str(dotted_key)
        if key_text.endswith(".keyword"):
            continue

        value = _elastic_field_value(raw_value, "")
        cur = result
        parts = key_text.split(".")

        for part in parts[:-1]:
            if part not in cur or not isinstance(cur.get(part), dict):
                cur[part] = {}
            cur = cur[part]

        cur[parts[-1]] = value

    return result


def _read_elastic_value(src: Dict[str, Any], path: str, default: Any = "") -> Any:
    value = get_nested(src, path, None)
    if value is None and isinstance(src, dict):
        value = src.get(path, default)
    return _elastic_field_value(value, default)


def parse_opnsense_filterlog_message(message: Any) -> Dict[str, Any]:
    text = str(message or "").strip()
    if not text:
        return {}

    result: Dict[str, Any] = {"message": text}

    header_match = re.search(
        r"^(?:<(?P<pri>\d+)>)?(?P<syslog_time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<program>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<body>.*)$",
        text,
    )

    if header_match:
        result.update({
            "syslog_priority": header_match.group("pri") or "-",
            "syslog_time": header_match.group("syslog_time") or "-",
            "host": header_match.group("host") or "-",
            "program": header_match.group("program") or "-",
            "pid": header_match.group("pid") or "-",
        })
        body = header_match.group("body") or ""
    else:
        body = text

    program = str(result.get("program", "")).lower()

    if "filterlog" in program:
        try:
            parts = next(csv.reader([body]))
        except Exception:
            parts = body.split(",")

        parts = [str(x).strip() for x in parts]

        def p(index: int, default: str = "-") -> str:
            return parts[index] if index < len(parts) and parts[index] != "" else default

        result.update({
            "event_type": "filterlog",
            "event_action": p(6),
            "action": p(6),
            "interface": p(4),
            "reason": p(5),
            "direction": p(7),
            "ip_version": p(8),
            "protocol_id": p(15),
            "protocol": p(16),
            "packet_length": p(17),
            "source_ip": p(18),
            "destination_ip": p(19),
            "source_port": p(20, ""),
            "destination_port": p(21, ""),
            "rule": f"filterlog rule {p(0)}",
            "tracker": p(3),
            "category": "opnsense firewall",
            "severity": "-",
            "raw_parts": parts,
        })
        return result

    if "audit" in program or "authenticate" in body.lower():
        severity = "2" if "could not authenticate" in body.lower() or "failed" in body.lower() else "-"
        result.update({
            "event_type": "auth",
            "event_action": "auth",
            "action": "auth",
            "interface": "WebGui" if "webgui" in body.lower() else "-",
            "protocol": "https" if "webgui" in body.lower() else "-",
            "source_ip": "-",
            "destination_ip": "-",
            "source_port": "",
            "destination_port": "",
            "rule": body or "OPNsense authentication log",
            "category": "opnsense auth",
            "severity": severity,
        })
        return result

    result.update({
        "event_type": program or "opnsense",
        "event_action": program or "opnsense",
        "action": program or "opnsense",
        "interface": "-",
        "protocol": "-",
        "source_ip": "-",
        "destination_ip": "-",
        "source_port": "",
        "destination_port": "",
        "rule": body or text,
        "category": "opnsense syslog",
        "severity": "-",
    })
    return result



def search_firewall_events(
    target: Dict[str, Any],
    log_index: str,
    size: int,
    minutes: int,
    action: str = "",
    interface: str = "",
    query_text: str = "",
    before_timestamp: str = "",
) -> List[Dict[str, Any]]:
    ensure_elastic_config(target)

    must: List[Dict[str, Any]] = []
    filter_conditions: List[Dict[str, Any]] = []

    safe_minutes = max(1, int(minutes or 60))
    before_timestamp = str(before_timestamp or "").strip()
    timestamp_range: Dict[str, Any] = {}
    if safe_minutes < 5256000:
        timestamp_range["gte"] = f"now-{safe_minutes}m"
    if before_timestamp:
        timestamp_range["lte"] = before_timestamp
    elif safe_minutes < 5256000:
        timestamp_range["lte"] = "now"
    if timestamp_range:
        filter_conditions.append({"range": {"@timestamp": timestamp_range}})

    action = (action or "").strip()
    if action:
        must.append({
            "bool": {
                "should": [
                    {"term": {"network.direction.keyword": action}},
                    {"term": {"suricata.eve.event_type.keyword": action}},
                    {"term": {"event.action.keyword": action}},
                    {"term": {"event.type.keyword": action}},
                    {"term": {"type.keyword": action}},
                    {"match_phrase": {"message": action}},
                    {"match_phrase": {"event.original": action}},
                ],
                "minimum_should_match": 1,
            }
        })

    interface = (interface or "").strip()
    if interface:
        must.append({
            "bool": {
                "should": [
                    {"term": {"suricata.eve.in_iface.keyword": interface}},
                    {"term": {"observer.ingress.interface.name.keyword": interface}},
                    {"term": {"observer.egress.interface.name.keyword": interface}},
                    {"match_phrase": {"message": f",{interface},"}},
                    {"match_phrase": {"event.original": f",{interface},"}},
                    {"match_phrase": {"message": interface}},
                    {"match_phrase": {"event.original": interface}},
                ],
                "minimum_should_match": 1,
            }
        })

    query_text = (query_text or "").strip()
    if query_text:
        must.append({
            "multi_match": {
                "query": query_text,
                "fields": [
                    "ml.detected_class",
                    "ml.confidence_percent",
                    "ml.risk_level",
                    "final_risk",
                    "main_result_display",
                    "ml.main_result_display",
                    "ml_result.main_result_display",
                    "final_pred",
                    "source.ip",
                    "destination.ip",
                    "network.transport",
                    "network.direction",
                    "suricata.eve.event_type",
                    "suricata.eve.in_iface",
                    "suricata.eve.alert.signature",
                    "event.dataset",
                    "event.module",
                    "event.type",
                    "event.action",
                    "event.original",
                    "message",
                    "host.name",
                    "type",
                ],
                "lenient": True,
            }
        })

    bool_query: Dict[str, Any] = {}
    if must:
        bool_query["must"] = must
    if filter_conditions:
        bool_query["filter"] = filter_conditions

    body = {
        "size": max(1, min(int(size or 200), 1000)),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": True,
        "fields": [
            "@timestamp",
            "event.original",
            "event.created",
            "event.dataset",
            "event.module",
            "event.type",
            "event.action",
            "message",
            "type",
            "host.name",
            "source.ip",
            "source.port",
            "ml.detected_class",
            "ml.confidence_percent",
            "ml.risk_level",
            "final_risk",
            "destination.ip",
            "destination.port",
            "network.transport",
            "suricata.eve.*",
        ],
        "query": {"bool": bool_query} if bool_query else {"match_all": {}},
    }

    try:
        resp = requests.post(
            f"{_elastic_url(target)}/{log_index}/_search",
            headers=elastic_headers(target),
            auth=elastic_auth(target),
            json=body,
            verify=_elastic_verify_ssl(target),
            timeout=20,
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectTimeout:
        raise HTTPException(
            status_code=504,
            detail=f"Elastic 연결 시간 초과: {_elastic_url(target)}",
        )
    except requests.exceptions.ReadTimeout:
        raise HTTPException(
            status_code=504,
            detail=f"Elastic 응답 시간 초과: {_elastic_url(target)}",
        )
    except requests.exceptions.ConnectionError as e:
        raise HTTPException(status_code=502, detail=f"Elastic 연결 실패: {e}")
    except requests.exceptions.RequestException as e:
        error_text = ""
        try:
            error_text = resp.text
        except Exception:
            error_text = str(e)
        raise HTTPException(status_code=500, detail=f"Elastic 요청 실패: {e} / {error_text}")

    payload = resp.json()
    hits = payload.get("hits", {}).get("hits", [])

    rows: List[Dict[str, Any]] = []

    for index, hit in enumerate(hits):
        source_from_fields = _elastic_fields_to_source(hit.get("fields", {}))
        src = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
        src = {**source_from_fields, **src}

        message_value = (
            _read_elastic_value(src, "message", "")
            or _read_elastic_value(src, "event.original", "")
            or ""
        )
        event_original = _read_elastic_value(src, "event.original", message_value)

        message_json = parse_suricata_message(message_value)
        if not message_json and event_original:
            message_json = parse_suricata_message(event_original)

        opnsense_parsed = parse_opnsense_filterlog_message(event_original or message_value)

        event_type = (
            _read_elastic_value(src, "suricata.eve.event_type", "")
            or _read_elastic_value(src, "event.type", "")
            or _read_elastic_value(src, "event.action", "")
            or message_json.get("event_type")
            or opnsense_parsed.get("event_type")
            or _read_elastic_value(src, "type", "")
            or "-"
        )

        action_value = (
            _read_elastic_value(src, "network.direction", "")
            or _read_elastic_value(src, "event.action", "")
            or message_json.get("event_type")
            or opnsense_parsed.get("action")
            or event_type
            or "-"
        )

        interface_value = (
            _read_elastic_value(src, "suricata.eve.in_iface", "")
            or _read_elastic_value(src, "observer.ingress.interface.name", "")
            or _read_elastic_value(src, "observer.egress.interface.name", "")
            or message_json.get("in_iface")
            or opnsense_parsed.get("interface")
            or "-"
        )

        protocol_value = (
            _read_elastic_value(src, "network.transport", "")
            or _read_elastic_value(src, "network.protocol", "")
            or _read_elastic_value(src, "suricata.eve.proto", "")
            or message_json.get("proto")
            or opnsense_parsed.get("protocol")
            or "-"
        )

        alert_signature_value = _read_elastic_value(src, "suricata.eve.alert.signature", "")
        rule_value = (
            alert_signature_value
            or _read_elastic_value(src, "rule.name", "")
            or get_nested(message_json, "alert.signature")
            or opnsense_parsed.get("rule")
            or event_type
            or "-"
        )

        severity_value = (
            _read_elastic_value(src, "suricata.eve.alert.severity", "")
            or _read_elastic_value(src, "event.severity", "")
            or get_nested(message_json, "alert.severity")
            or opnsense_parsed.get("severity")
            or "-"
        )

        category_value = (
            _read_elastic_value(src, "suricata.eve.alert.category", "")
            or _read_elastic_value(src, "event.category", "")
            or _read_elastic_value(src, "event.dataset", "")
            or get_nested(message_json, "alert.category")
            or opnsense_parsed.get("category")
            or "-"
        )

        host_value = (
            _read_elastic_value(src, "host.name", "")
            or _read_elastic_value(src, "host.hostname", "")
            or opnsense_parsed.get("host")
            or "-"
        )

        timestamp_value = _read_elastic_value(src, "@timestamp", "-")
        ml_detected_class = _read_elastic_value(src, "ml.detected_class", "")
        ml_confidence_percent = _read_elastic_value(src, "ml.confidence_percent", "")
        ml_risk_level = _read_elastic_value(src, "ml.risk_level", "")
        final_risk_value = _read_elastic_value(src, "final_risk", "")
        document_id = hit.get("_id", f"event-{index}")

        rows.append({
            "id": f"{document_id}-{timestamp_value}-{index}",
            "_id": document_id,
            "_index": hit.get("_index", ""),
            "_score": hit.get("_score", ""),
            "timestamp": timestamp_value,
            "event_created": _read_elastic_value(src, "event.created", "-"),
            "event_dataset": _read_elastic_value(src, "event.dataset", opnsense_parsed.get("category", "-")),
            "event_module": _read_elastic_value(src, "event.module", opnsense_parsed.get("program", "-")),
            "event_original": event_original,
            "type": _read_elastic_value(src, "type", "-"),
            "action": action_value,
            "interface": interface_value,
            "direction": opnsense_parsed.get("direction", "-"),
            "reason": opnsense_parsed.get("reason", "-"),
            "protocol": protocol_value,
            "source_ip": _read_elastic_value(src, "source.ip", message_json.get("src_ip", opnsense_parsed.get("source_ip", "-"))),
            "source_port": _read_elastic_value(src, "source.port", message_json.get("src_port", opnsense_parsed.get("source_port", ""))),
            "destination_ip": _read_elastic_value(src, "destination.ip", message_json.get("dest_ip", opnsense_parsed.get("destination_ip", "-"))),
            "destination_port": _read_elastic_value(src, "destination.port", message_json.get("dest_port", opnsense_parsed.get("destination_port", ""))),
            "rule": rule_value,
            "alert_signature": alert_signature_value,
            "severity": severity_value,
            "category": category_value,
            "host": host_value,
            "event_type": event_type,
            # Canonical fields written by the Logstash V32 inference pipeline.
            "ml_detected_class": ml_detected_class,
            "ml_confidence_percent": ml_confidence_percent,
            "ml_risk_level": ml_risk_level,
            "final_risk": final_risk_value,
            "message": message_value or event_original,
            "raw": src,
            "messageJson": message_json,
            "opnsenseParsed": opnsense_parsed,
            "exportRow": build_kibana_export_row(hit, src),
        })

    return rows

# =========================
# basic
# =========================
@app.get("/")
def root():
    return {"ok": True, "message": "Backend is running"}


@app.get("/health")
def health():
    return {"status": "running"}


# =========================
# firewalls
# =========================
@app.get("/api/firewalls")
def list_firewalls():
    return [serialize_firewall(x) for x in load_firewalls()]


@app.post("/api/firewalls")
def create_firewall(body: FirewallCreateBody):
    items = load_firewalls()
    now = int(time.time())

    item = {
        "id": next_firewall_id(items),
        "name": body.name.strip(),
        "host": body.host.strip().rstrip("/"),
        "api_key_enc": encrypt_text(body.api_key.strip()),
        "api_secret_enc": encrypt_text(body.api_secret.strip()),
        "verify_ssl": body.verify_ssl,
        "log_index": body.log_index.strip() or "logs-suricata.eve-*",
        "event_log_index": body.event_log_index.strip(),
        "description": body.description.strip(),
        "elastic_url": body.elastic_url.strip().rstrip("/"),
        "elastic_api_key_enc": encrypt_text(body.elastic_api_key.strip()) if body.elastic_api_key.strip() else "",
        "elastic_username": body.elastic_username.strip(),
        "elastic_password_enc": encrypt_text(body.elastic_password.strip()) if body.elastic_password.strip() else "",
        "elastic_verify_ssl": body.elastic_verify_ssl,
        "created_at": now,
        "updated_at": now,
    }

    items.append(item)
    save_firewalls(items)
    return serialize_firewall(item)


@app.put("/api/firewalls/{firewall_id}")
def update_firewall(firewall_id: int, body: FirewallUpdateBody):
    items = load_firewalls()
    updated = None

    for item in items:
        if int(item.get("id", 0)) != firewall_id:
            continue

        if body.name is not None:
            item["name"] = body.name.strip()
        if body.host is not None:
            item["host"] = body.host.strip().rstrip("/")
        if body.api_key is not None and body.api_key.strip():
            item["api_key_enc"] = encrypt_text(body.api_key.strip())
        if body.api_secret is not None and body.api_secret.strip():
            item["api_secret_enc"] = encrypt_text(body.api_secret.strip())
        if body.verify_ssl is not None:
            item["verify_ssl"] = body.verify_ssl
        if body.log_index is not None:
            item["log_index"] = body.log_index.strip() or "logs-suricata.eve-*"
        if body.event_log_index is not None:
            item["event_log_index"] = body.event_log_index.strip()
        if body.description is not None:
            item["description"] = body.description.strip()
        if body.elastic_url is not None:
            item["elastic_url"] = body.elastic_url.strip().rstrip("/")
        if body.elastic_api_key is not None:
            item["elastic_api_key_enc"] = (
                encrypt_text(body.elastic_api_key.strip())
                if body.elastic_api_key.strip() else ""
            )
        if body.elastic_username is not None:
            item["elastic_username"] = body.elastic_username.strip()
        if body.elastic_password is not None:
            item["elastic_password_enc"] = (
                encrypt_text(body.elastic_password.strip())
                if body.elastic_password.strip() else ""
            )
        if body.elastic_verify_ssl is not None:
            item["elastic_verify_ssl"] = body.elastic_verify_ssl

        item["updated_at"] = int(time.time())
        updated = item
        break

    if updated is None:
        raise HTTPException(status_code=404, detail="방화벽을 찾을 수 없습니다.")

    save_firewalls(items)
    return serialize_firewall(updated)


@app.delete("/api/firewalls/{firewall_id}")
def delete_firewall(firewall_id: int):
    items = load_firewalls()
    next_items = [x for x in items if int(x.get("id", 0)) != firewall_id]

    if len(next_items) == len(items):
        raise HTTPException(status_code=404, detail="방화벽을 찾을 수 없습니다.")

    save_firewalls(next_items)
    return {"ok": True}



def _probe_opnsense(target: Dict[str, Any]) -> Dict[str, Any]:
    host = str(target.get("host", "")).strip().rstrip("/")
    if not host:
        return {"ok": False, "error": "OPNsense host 누락"}

    url = f"{host}/api/core/firmware/status"
    started = time.perf_counter()
    try:
        response = requests.post(
            url,
            auth=(
                decrypt_text(target["api_key_enc"]),
                decrypt_text(target["api_secret_enc"]),
            ),
            json={},
            verify=bool(target.get("verify_ssl", OPNSENSE_VERIFY_SSL)),
            timeout=(4, 8),
        )
        elapsed = round((time.perf_counter() - started) * 1000)
        return {
            "ok": response.ok,
            "url": url,
            "status": response.status_code,
            "elapsed_ms": elapsed,
            "message": "OPNsense reachable" if response.ok else "OPNsense responded with error",
        }
    except requests.exceptions.ConnectTimeout:
        return {"ok": False, "url": url, "error": "connect timeout"}
    except requests.exceptions.ReadTimeout:
        return {"ok": False, "url": url, "error": "read timeout"}
    except requests.exceptions.ConnectionError as exc:
        return {"ok": False, "url": url, "error": f"connection error: {exc}"}
    except Exception as exc:
        return {"ok": False, "url": url, "error": str(exc)}


def _probe_elastic(target: Dict[str, Any]) -> Dict[str, Any]:
    base_url = _elastic_url(target)
    if not base_url:
        return {"ok": False, "error": "Elastic URL 누락"}

    url = f"{base_url}/"
    started = time.perf_counter()
    try:
        response = requests.get(
            url,
            headers=elastic_headers(target),
            auth=elastic_auth(target),
            verify=_elastic_verify_ssl(target),
            timeout=(4, 8),
        )
        elapsed = round((time.perf_counter() - started) * 1000)
        return {
            "ok": response.ok,
            "url": url,
            "status": response.status_code,
            "elapsed_ms": elapsed,
            "message": "Elastic reachable" if response.ok else "Elastic responded with error",
        }
    except requests.exceptions.ConnectTimeout:
        return {"ok": False, "url": url, "error": "connect timeout"}
    except requests.exceptions.ReadTimeout:
        return {"ok": False, "url": url, "error": "read timeout"}
    except requests.exceptions.ConnectionError as exc:
        return {"ok": False, "url": url, "error": f"connection error: {exc}"}
    except Exception as exc:
        return {"ok": False, "url": url, "error": str(exc)}


@app.get("/api/firewalls/{firewall_id}/connectivity")
def firewall_connectivity(firewall_id: int):
    """
    프론트와 무관하게 백엔드 PC 기준으로 OPNsense/Elastic 연결을 각각 검사한다.
    200 응답 자체는 probe 실행 성공을 의미하며, 실제 연결 여부는 각 ok 필드로 확인한다.
    """
    target = get_firewall_or_404(firewall_id)
    return {
        "firewall": serialize_firewall(target),
        "opnsense": _probe_opnsense(target),
        "elastic": _probe_elastic(target),
    }


# =========================
# per-firewall opnsense
# =========================
@app.get("/api/firewalls/{firewall_id}/dashboard")
def dashboard(firewall_id: int):
    target = get_firewall_or_404(firewall_id)

    status_data = safe_block(target, "/api/core/firmware/status", method="POST", json_data={}, default={})
    rules_data = safe_block(target, "/api/firewall/filter/searchRule", method="GET", default={"rows": []})
    system_data = safe_block(target, "/api/diagnostics/system/system_information", method="GET", default={})
    interfaces_data = safe_block(target, "/api/interfaces/overview/export", method="GET", default={})
    services_data = safe_block(target, "/api/core/service/search", method="GET", default={})
    traffic_data = safe_block(target, "/api/diagnostics/interface/get_interface_statistics", method="GET", default={})
    memory_data = safe_block(target, "/api/diagnostics/system/memory", method="GET", default={})
    disk_data = safe_block(target, "/api/diagnostics/system/system_disk", method="GET", default={"devices": []})
    aliases_data = safe_block(target, "/api/firewall/alias_util/aliases", method="GET", default=[])

    return {
        "status": status_data,
        "product": status_data.get("product", {}) if isinstance(status_data, dict) else {},
        "rules": rules_data if isinstance(rules_data, dict) else {"rows": []},
        "system": system_data,
        "system_summary": summarize_system(system_data),
        "interfaces": interfaces_data,
        "services": services_data,
        "traffic": traffic_data,
        "memory": memory_data,
        "memory_summary": summarize_memory(memory_data),
        "disk": disk_data,
        "disk_summary": summarize_disk(disk_data),
        "aliases": aliases_data,
        "firewall": serialize_firewall(target),
    }


@app.get("/api/firewalls/{firewall_id}/rules")
def get_rules(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    return opnsense_request(target, "GET", "/api/firewall/filter/searchRule")


@app.post("/api/firewalls/{firewall_id}/rules")
def add_rule(firewall_id: int, body: RuleCreateBody):
    target = get_firewall_or_404(firewall_id)

    payload = {
        "rule": {
            "enabled": body.enabled,
            "quick": body.quick,
            "action": body.action,
            "interface": body.interface,
            "direction": body.direction,
            "ipprotocol": "inet",
            "protocol": body.protocol,
            "source_net": body.sourceNet,
            "source_port": body.sourcePort,
            "destination_net": body.destinationNet,
            "destination_port": body.destinationPort,
            "description": body.description or "API rule",
            "log": "1" if body.log else "0",
        }
    }

    result = opnsense_request(target, "POST", "/api/firewall/filter/addRule", json_data=payload)
    apply_result = safe_apply_firewall(target)
    return {
        "message": "Rule added successfully",
        "result": result,
        "apply": apply_result,
    }


@app.delete("/api/firewalls/{firewall_id}/rules/{uuid}")
def delete_rule(firewall_id: int, uuid: str):
    target = get_firewall_or_404(firewall_id)
    result = opnsense_request(target, "POST", f"/api/firewall/filter/delRule/{uuid}", json_data={})
    apply_result = safe_apply_firewall(target)
    return {
        "message": "Rule deleted successfully",
        "result": result,
        "apply": apply_result,
    }


@app.get("/api/firewalls/{firewall_id}/aliases")
def list_aliases(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    return opnsense_request(target, "GET", "/api/firewall/alias_util/aliases")


@app.get("/api/firewalls/{firewall_id}/alias/{alias_name}")
def get_alias_entries(firewall_id: int, alias_name: str):
    target = get_firewall_or_404(firewall_id)
    safe_alias = quote(alias_name, safe="")
    return opnsense_request(target, "GET", f"/api/firewall/alias_util/list/{safe_alias}")


@app.post("/api/firewalls/{firewall_id}/alias/{alias_name}/add")
def add_alias_entry(firewall_id: int, alias_name: str, body: AliasAddressBody):
    target = get_firewall_or_404(firewall_id)
    safe_alias = quote(alias_name, safe="")
    return opnsense_request(
        target,
        "POST",
        f"/api/firewall/alias_util/add/{safe_alias}",
        json_data={"address": body.address},
    )


@app.post("/api/firewalls/{firewall_id}/alias/{alias_name}/delete")
def delete_alias_entry(firewall_id: int, alias_name: str, body: AliasAddressBody):
    target = get_firewall_or_404(firewall_id)
    safe_alias = quote(alias_name, safe="")
    return opnsense_request(
        target,
        "POST",
        f"/api/firewall/alias_util/delete/{safe_alias}",
        json_data={"address": body.address},
    )



# =========================
# OPNsense firewall live log helpers
# =========================
def _safe_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value if value.strip() else default
    if isinstance(value, (int, float, bool)):
        return str(value)
    return str(value)


def _join_address(ip: Any, port: Any = "") -> str:
    ip_text = _safe_text(ip, "")
    port_text = _safe_text(port, "")

    if not ip_text and not port_text:
        return "-"

    if port_text and port_text != "-":
        return f"{ip_text}:{port_text}"

    return ip_text or "-"


def _get_any(row: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    for key in keys:
        if key in row and row.get(key) not in [None, ""]:
            return row.get(key)
    return default


def _deep_get(data: Any, path: str, default: Any = None) -> Any:
    cur = data

    for key in path.split("."):
        if not isinstance(cur, dict):
            return default

        cur = cur.get(key)

        if cur is None:
            return default

    return cur


def _looks_like_log_row(row: Any) -> bool:
    if isinstance(row, list):
        return len(row) >= 6

    if not isinstance(row, dict):
        return False

    keys = {str(k).lower() for k in row.keys()}

    log_like_keys = {
        "interface", "if", "iface", "interface_name", "int",
        "dir", "direction", "subdir",
        "time", "timestamp", "datetime", "date", "@timestamp",
        "proto", "protocol", "protoname",
        "src", "source", "src_ip", "source_ip", "src_addr",
        "dst", "destination", "dest", "dst_ip", "dest_ip", "destination_ip", "dst_addr",
        "srcport", "src_port", "source_port",
        "dstport", "dst_port", "dest_port", "destination_port",
        "action", "act", "tracker_action",
        "label", "rule", "descr", "description", "rule_descr",
        "cell", "cells",
    }

    return bool(keys.intersection(log_like_keys))


def _parse_raw_firewall_log_text(raw_text: str) -> List[Dict[str, Any]]:
    """
    JSON이 아니라 텍스트 로그가 반환될 때를 대비한 fallback.
    """
    rows: List[Dict[str, Any]] = []

    for index, line in enumerate(raw_text.splitlines()):
        line = line.strip()

        if not line:
            continue

        if line.startswith("<") or len(line) < 10:
            continue

        rows.append({
            "id": f"raw-log-{index}",
            "interface": "-",
            "direction": "-",
            "time": "-",
            "protocol": "-",
            "source": "-",
            "destination": "-",
            "action": "-",
            "label": line,
            "raw": {"line": line},
        })

    return rows


def _extract_log_rows_from_payload(payload: Any) -> List[Any]:
    """
    OPNsense 방화벽 Live Log 응답 구조를 재귀적으로 탐색한다.
    지원 형태:
    - {"rows": [...]}
    - {"data": {"rows": [...]}}
    - {"data": [...]}
    - {"logs": [...]}, {"items": [...]}, {"records": [...]}
    - [{...}, {...}]
    - {"rows": [{"cell": [...]}]}
    - {"raw_text": "..."}
    """

    if payload is None:
        return []

    if isinstance(payload, list):
        if payload and all(_looks_like_log_row(x) for x in payload[:5]):
            return payload

        result: List[Any] = []
        for item in payload:
            result.extend(_extract_log_rows_from_payload(item))
        return result

    if not isinstance(payload, dict):
        return []

    direct_candidates = [
        payload.get("rows"),
        payload.get("row"),
        payload.get("data"),
        payload.get("logs"),
        payload.get("log"),
        payload.get("items"),
        payload.get("records"),
        payload.get("result"),
    ]

    for candidate in direct_candidates:
        if isinstance(candidate, list) and candidate:
            if all(_looks_like_log_row(x) for x in candidate[:5]):
                return candidate

        if isinstance(candidate, dict):
            nested = _extract_log_rows_from_payload(candidate)
            if nested:
                return nested

    for value in payload.values():
        nested = _extract_log_rows_from_payload(value)
        if nested:
            return nested

    raw_text = payload.get("raw_text")
    if isinstance(raw_text, str) and raw_text.strip():
        return _parse_raw_firewall_log_text(raw_text)

    return []


def normalize_opnsense_log_row(row: Any, index: int = 0) -> Dict[str, Any]:
    """
    프론트 OpnsenseFirewallLogsPage에서 바로 쓸 수 있는 형태로 정규화한다.
    OPNsense firewall log raw의 실제 시간 필드인 __timestamp__까지 처리한다.
    반환 필드:
    interface, direction, time, protocol, source, destination, action, label, raw
    """

    if isinstance(row, dict) and isinstance(row.get("cell"), list):
        row = {**row, "_cell_values": row.get("cell")}

    if isinstance(row, dict) and isinstance(row.get("cells"), list):
        row = {**row, "_cell_values": row.get("cells")}

    # 배열 형태
    if isinstance(row, list):
        cells = row

        # 시간이 포함된 배열: [interface, direction, time, protocol, source, destination, action, label]
        if len(cells) >= 8:
            direction_text = _safe_text(cells[1])
            if direction_text.lower() in ["in", "inbound"]:
                direction_text = "수신"
            elif direction_text.lower() in ["out", "outbound"]:
                direction_text = "송신"

            return {
                "id": f"log-{index}",
                "interface": _safe_text(cells[0]),
                "direction": direction_text,
                "time": _safe_text(cells[2]),
                "protocol": _safe_text(cells[3]),
                "source": _safe_text(cells[4]),
                "destination": _safe_text(cells[5]),
                "action": _safe_text(cells[6]).lower(),
                "label": _safe_text(cells[7]),
                "raw": {"cells": cells},
            }

        # 시간이 없는 배열: [interface, direction, protocol, source, destination, action, label]
        direction_text = _safe_text(cells[1] if len(cells) > 1 else "-")
        if direction_text.lower() in ["in", "inbound"]:
            direction_text = "수신"
        elif direction_text.lower() in ["out", "outbound"]:
            direction_text = "송신"

        return {
            "id": f"log-{index}",
            "interface": _safe_text(cells[0] if len(cells) > 0 else "-"),
            "direction": direction_text,
            "time": "-",
            "protocol": _safe_text(cells[2] if len(cells) > 2 else "-"),
            "source": _safe_text(cells[3] if len(cells) > 3 else "-"),
            "destination": _safe_text(cells[4] if len(cells) > 4 else "-"),
            "action": _safe_text(cells[5] if len(cells) > 5 else "-").lower(),
            "label": _safe_text(cells[6] if len(cells) > 6 else "-"),
            "raw": {"cells": cells},
        }

    if not isinstance(row, dict):
        return {
            "id": f"log-{index}",
            "interface": "-",
            "direction": "-",
            "time": "-",
            "protocol": "-",
            "source": "-",
            "destination": "-",
            "action": "-",
            "label": _safe_text(row),
            "raw": row,
        }

    # cell/cells 배열이 dict 안에 있는 형태
    cell_values = row.get("_cell_values")
    if isinstance(cell_values, list) and len(cell_values) >= 6:
        external_time = _get_any(row, [
            "time",
            "timestamp",
            "datetime",
            "date",
            "@timestamp",
            "__timestamp__",
            "__timestamp",
            "created",
            "created_at",
            "ts",
            "t",
        ], "")

        if len(cell_values) >= 8:
            interface_value = cell_values[0]
            direction_value = cell_values[1]
            time_cell = cell_values[2]
            protocol_value = cell_values[3]
            source_value = cell_values[4]
            destination_value = cell_values[5]
            action_value = cell_values[6]
            label_value = cell_values[7]
        else:
            interface_value = cell_values[0] if len(cell_values) > 0 else "-"
            direction_value = cell_values[1] if len(cell_values) > 1 else "-"
            time_cell = external_time or "-"
            protocol_value = cell_values[2] if len(cell_values) > 2 else "-"
            source_value = cell_values[3] if len(cell_values) > 3 else "-"
            destination_value = cell_values[4] if len(cell_values) > 4 else "-"
            action_value = cell_values[5] if len(cell_values) > 5 else "-"
            label_value = cell_values[6] if len(cell_values) > 6 else "-"

        direction_text = _safe_text(direction_value)
        if direction_text.lower() in ["in", "inbound"]:
            direction_text = "수신"
        elif direction_text.lower() in ["out", "outbound"]:
            direction_text = "송신"

        return {
            "id": _safe_text(
                row.get("id")
                or row.get("uuid")
                or row.get("__uuid")
                or row.get("__digest__")
                or f"log-{index}"
            ),
            "interface": _safe_text(interface_value),
            "direction": direction_text,
            "time": _safe_text(time_cell or external_time or "-"),
            "protocol": _safe_text(protocol_value),
            "source": _safe_text(source_value),
            "destination": _safe_text(destination_value),
            "action": _safe_text(action_value).lower(),
            "label": _safe_text(label_value),
            "raw": row,
        }

    interface = _get_any(row, [
        "interface",
        "if",
        "iface",
        "interface_name",
        "int",
    ], "-")

    direction = _get_any(row, [
        "direction",
        "dir",
        "subdir",
    ], "-")

    direction_text = _safe_text(direction)
    if direction_text.lower() in ["in", "inbound"]:
        direction_text = "수신"
    elif direction_text.lower() in ["out", "outbound"]:
        direction_text = "송신"

    # 실제 OPNsense raw는 __timestamp__를 사용한다.
    time_value = _get_any(row, [
        "time",
        "timestamp",
        "datetime",
        "date",
        "@timestamp",
        "__timestamp__",
        "__timestamp",
        "created",
        "created_at",
        "updated",
        "updated_at",
        "ts",
        "t",
        "time_iso",
        "local_time",
        "event_time",
    ], "-")

    protocol = _get_any(row, [
        "proto",
        "protocol",
        "protoname",
    ], "-")

    source_ip = _get_any(row, [
        "src",
        "source",
        "src_ip",
        "source_ip",
        "src_addr",
    ], None)

    source_port = _get_any(row, [
        "srcport",
        "src_port",
        "source_port",
    ], "")

    destination_ip = _get_any(row, [
        "dst",
        "destination",
        "dest",
        "dst_ip",
        "dest_ip",
        "destination_ip",
        "dst_addr",
    ], None)

    destination_port = _get_any(row, [
        "dstport",
        "dst_port",
        "dest_port",
        "destination_port",
    ], "")

    action = _get_any(row, [
        "action",
        "act",
        "tracker_action",
    ], "-")

    label = _get_any(row, [
        "label",
        "rule",
        "descr",
        "description",
        "rule_descr",
    ], "-")

    return {
        "id": _safe_text(
            row.get("id")
            or row.get("uuid")
            or row.get("__uuid")
            or row.get("__digest__")
            or f"log-{index}"
        ),
        "interface": _safe_text(interface),
        "direction": direction_text,
        "time": _safe_text(time_value),
        "protocol": _safe_text(protocol),
        "source": _join_address(source_ip, source_port),
        "destination": _join_address(destination_ip, destination_port),
        "action": _safe_text(action).lower(),
        "label": _safe_text(label),
        "raw": row,
    }

def _opn_log_row_to_search_text(row: Dict[str, Any]) -> str:
    return " ".join([
        _safe_text(row.get("interface"), ""),
        _safe_text(row.get("direction"), ""),
        _safe_text(row.get("time"), ""),
        _safe_text(row.get("protocol"), ""),
        _safe_text(row.get("source"), ""),
        _safe_text(row.get("destination"), ""),
        _safe_text(row.get("action"), ""),
        _safe_text(row.get("label"), ""),
    ]).lower()


def _opn_log_match_operator(value: str, needle: str, operator: str) -> bool:
    value = (value or "").lower()
    needle = (needle or "").lower()
    operator = (operator or "contains").lower()

    if not needle:
        return True
    if operator == "equals":
        return value == needle
    if operator == "startsWith" or operator == "starts_with":
        return value.startswith(needle)
    if operator == "endsWith" or operator == "ends_with":
        return value.endswith(needle)
    if operator == "notContains" or operator == "not_contains":
        return needle not in value
    return needle in value


def _opn_log_apply_filters(rows: List[Dict[str, Any]], filters: OpnsenseLogFilter) -> List[Dict[str, Any]]:
    search_text = (filters.search or "").strip().lower()
    field = (filters.field or "any").strip()
    operator = (filters.operator or "contains").strip()
    only_important = bool(filters.onlyImportant)

    # frontend can send filterValue inside search; for compatibility we use search as the keyword.
    result: List[Dict[str, Any]] = []

    for row in rows:
        action = _safe_text(row.get("action"), "").lower()
        if only_important and action not in {"block", "deny", "drop", "reject"}:
            continue

        if search_text:
            if field and field != "any":
                field_map = {
                    "interface": "interface",
                    "direction": "direction",
                    "time": "time",
                    "protocol": "protocol",
                    "source": "source",
                    "destination": "destination",
                    "action": "action",
                    "label": "label",
                    "rule": "label",
                }
                target_key = field_map.get(field, field)
                target_value = _safe_text(row.get(target_key), "")
                if not _opn_log_match_operator(target_value, search_text, operator):
                    continue
            else:
                if search_text not in _opn_log_row_to_search_text(row):
                    continue

        result.append(row)

    return result




_OPN_VIEW_CACHE_LOCK = threading.Lock()
# One progressive archive per firewall.  A selected 7-day/30-day range no longer
# forces a synchronous page-by-page rescan.  The request returns the newest page
# immediately and older OPNsense pages are backfilled in a daemon thread.
_OPN_VIEW_CACHE: Dict[int, Dict[str, Any]] = {}
_OPN_LATEST_REFRESH_SECONDS = 4
_OPN_BACKFILL_PAGE_SIZE = 1000
_OPN_INITIAL_ROWS = 100
_OPN_ARCHIVE_MAX_ROWS = 200000


def _log_timestamp_ms(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        numeric_value = float(value)
        return int(numeric_value * 1000 if numeric_value < 1e12 else numeric_value)
    raw = str(value).strip()
    if not raw or raw == "-":
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", raw):
        numeric_value = float(raw)
        return int(numeric_value * 1000 if numeric_value < 1e12 else numeric_value)
    normalized = raw.replace(" ", "T")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
        # OPNsense live-log ISO strings without an offset are UTC in the
        # installations used by this dashboard.
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    except ValueError:
        return None


def _native_row_identity(row: Dict[str, Any]) -> str:
    raw = row.get("raw") if isinstance(row, dict) else None
    return json.dumps([
        row.get("time"), row.get("source"), row.get("destination"),
        row.get("action"), row.get("protocol"), row.get("label"), raw,
    ], ensure_ascii=False, sort_keys=True, default=str)


def _fetch_opnsense_page(target: Dict[str, Any], page: int, page_size: int) -> List[Dict[str, Any]]:
    data = opnsense_request(
        target=target,
        method="POST",
        path="/api/diagnostics/firewall/log",
        json_data={"current": page, "rowCount": page_size, "searchPhrase": "", "sort": {}},
    )
    raw_rows = _extract_log_rows_from_payload(data)
    return [normalize_opnsense_log_row(raw_row, (page - 1) * page_size + index) for index, raw_row in enumerate(raw_rows)]


def _fetch_opnsense_recent_snapshot(target: Dict[str, Any], limit: int = 100) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Fetch the newest OPNsense firewall log rows with API compatibility fallbacks.

    Some OPNsense versions return an HTTP 200 but an empty payload for the
    Bootgrid POST form while the GET live-log form returns rows normally.
    The overview page already tolerated this; the lightweight serverView path
    must do the same or it can incorrectly report 0 rows.
    """
    safe_limit = max(1, min(int(limit or 100), 1000))
    attempts: List[Dict[str, Any]] = []

    def normalize_rows(raw_rows: List[Any]) -> List[Dict[str, Any]]:
        rows = [normalize_opnsense_log_row(raw, index) for index, raw in enumerate(raw_rows)]
        return [
            row for row in rows
            if not (
                row.get("interface") == "-"
                and row.get("time") == "-"
                and row.get("source") == "-"
                and row.get("destination") == "-"
                and row.get("label") == "-"
            )
        ]

    # Preferred form on newer installations.
    try:
        path = "/api/diagnostics/firewall/log"
        data = opnsense_request(
            target=target,
            method="POST",
            path=path,
            json_data={"current": 1, "rowCount": safe_limit, "searchPhrase": "", "sort": {}},
        )
        raw_rows = _extract_log_rows_from_payload(data)
        rows = normalize_rows(raw_rows)
        attempts.append({
            "method": "POST",
            "path": path,
            "ok": True,
            "found_rows": len(raw_rows),
            "usable_rows": len(rows),
            "response_type": type(data).__name__,
            "response_keys": list(data.keys()) if isinstance(data, dict) else [],
        })
        if rows:
            return rows[:safe_limit], attempts
    except HTTPException as exc:
        attempts.append({"method": "POST", "path": "/api/diagnostics/firewall/log", "ok": False, "error": exc.detail})
    except Exception as exc:
        attempts.append({"method": "POST", "path": "/api/diagnostics/firewall/log", "ok": False, "error": str(exc)})

    # Compatibility form used successfully by older/current OPNsense builds.
    for path in (
        f"/api/diagnostics/firewall/log?limit={safe_limit}",
        "/api/diagnostics/firewall/log",
    ):
        try:
            data = opnsense_request(target=target, method="GET", path=path, json_data=None)
            raw_rows = _extract_log_rows_from_payload(data)
            rows = normalize_rows(raw_rows)
            attempts.append({
                "method": "GET",
                "path": path,
                "ok": True,
                "found_rows": len(raw_rows),
                "usable_rows": len(rows),
                "response_type": type(data).__name__,
                "response_keys": list(data.keys()) if isinstance(data, dict) else [],
            })
            if rows:
                return rows[:safe_limit], attempts
        except HTTPException as exc:
            attempts.append({"method": "GET", "path": path, "ok": False, "error": exc.detail})
        except Exception as exc:
            attempts.append({"method": "GET", "path": path, "ok": False, "error": str(exc)})

    return [], attempts


def _new_opn_archive_entry(target: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "target_host": str(target.get("host", "")),
        "rows": [],
        "seen": set(),
        "scan_page": 1,
        "scan_complete": False,
        "loading": False,
        "requested_cutoff_ms": int(time.time() * 1000) - 60 * 60 * 1000,
        "last_latest_refresh": 0.0,
        "last_backfill_at": 0.0,
        "pages_loaded": 0,
        "error": "",
    }


def _opn_entry_merge_rows(entry: Dict[str, Any], rows: List[Dict[str, Any]], newest: bool = False) -> int:
    """Merge rows while keeping the archive newest-first and deduplicated."""
    seen = entry.setdefault("seen", set())
    accepted: List[Dict[str, Any]] = []
    for row in rows:
        if (
            row.get("interface") == "-" and row.get("time") == "-"
            and row.get("source") == "-" and row.get("destination") == "-"
            and row.get("label") == "-"
        ):
            continue
        identity = _native_row_identity(row)
        if identity in seen:
            continue
        seen.add(identity)
        accepted.append(row)

    if not accepted:
        return 0

    accepted.sort(key=lambda row: _log_timestamp_ms(row.get("time")) or 0, reverse=True)
    current = entry.setdefault("rows", [])
    if newest:
        # Latest page may overlap the archive.  Sort only the small newly merged
        # head plus current rows so real-time additions appear immediately.
        entry["rows"] = sorted(
            accepted + current,
            key=lambda row: _log_timestamp_ms(row.get("time")) or 0,
            reverse=True,
        )[:_OPN_ARCHIVE_MAX_ROWS]
    else:
        # Backfill pages are newest -> oldest, so appending avoids repeatedly
        # sorting tens of thousands of rows.
        current.extend(accepted)
        if len(current) > _OPN_ARCHIVE_MAX_ROWS:
            del current[_OPN_ARCHIVE_MAX_ROWS:]
    return len(accepted)


def _opn_oldest_ms(entry: Dict[str, Any]) -> Optional[int]:
    rows = entry.get("rows") or []
    for row in reversed(rows):
        value = _log_timestamp_ms(row.get("time"))
        if value is not None:
            return value
    return None


def _opn_requested_range_complete(entry: Dict[str, Any]) -> bool:
    if entry.get("scan_complete"):
        return True
    cutoff = int(entry.get("requested_cutoff_ms") or 0)
    oldest = _opn_oldest_ms(entry)
    return oldest is not None and oldest <= cutoff


def _opn_backfill_worker(firewall_id: int, target: Dict[str, Any]) -> None:
    """Progressively extend one shared archive without blocking API responses."""
    try:
        while True:
            with _OPN_VIEW_CACHE_LOCK:
                entry = _OPN_VIEW_CACHE.get(firewall_id)
                if not entry:
                    return
                if _opn_requested_range_complete(entry) or len(entry.get("rows") or []) >= _OPN_ARCHIVE_MAX_ROWS:
                    entry["loading"] = False
                    return
                page = max(1, int(entry.get("scan_page") or 1))

            try:
                page_rows = _fetch_opnsense_page(target, page, _OPN_BACKFILL_PAGE_SIZE)
            except Exception as exc:
                with _OPN_VIEW_CACHE_LOCK:
                    entry = _OPN_VIEW_CACHE.get(firewall_id)
                    if entry:
                        entry["loading"] = False
                        entry["error"] = str(exc)
                return

            with _OPN_VIEW_CACHE_LOCK:
                entry = _OPN_VIEW_CACHE.get(firewall_id)
                if not entry:
                    return
                if not page_rows:
                    entry["scan_complete"] = True
                    entry["loading"] = False
                    entry["last_backfill_at"] = time.time()
                    return

                added = _opn_entry_merge_rows(entry, page_rows, newest=(page == 1))
                entry["scan_page"] = page + 1
                entry["pages_loaded"] = int(entry.get("pages_loaded") or 0) + 1
                entry["last_backfill_at"] = time.time()
                entry["error"] = ""

                page_times = [
                    value for row in page_rows
                    if (value := _log_timestamp_ms(row.get("time"))) is not None
                ]
                if len(page_rows) < _OPN_BACKFILL_PAGE_SIZE:
                    entry["scan_complete"] = True
                # If an OPNsense endpoint unexpectedly repeats a page, avoid
                # spinning forever.  The next range request can restart via
                # forceRefresh if needed.
                if added == 0 and page > 1:
                    entry["scan_complete"] = True

                if _opn_requested_range_complete(entry) or entry.get("scan_complete"):
                    entry["loading"] = False
                    return

            # Yield between OPNsense requests so dashboard/control API traffic
            # remains responsive while a long archive is being backfilled.
            time.sleep(0.04)
    finally:
        with _OPN_VIEW_CACHE_LOCK:
            entry = _OPN_VIEW_CACHE.get(firewall_id)
            if entry:
                entry["loading"] = False


def _ensure_opn_backfill(firewall_id: int, target: Dict[str, Any], cutoff_ms: int) -> None:
    should_start = False
    with _OPN_VIEW_CACHE_LOCK:
        entry = _OPN_VIEW_CACHE.get(firewall_id)
        if not entry:
            return
        current_cutoff = int(entry.get("requested_cutoff_ms") or cutoff_ms)
        # Smaller timestamp means the user asked for an older/wider range.
        entry["requested_cutoff_ms"] = min(current_cutoff, cutoff_ms)
        if not entry.get("loading") and not _opn_requested_range_complete(entry):
            entry["loading"] = True
            should_start = True

    if should_start:
        threading.Thread(
            target=_opn_backfill_worker,
            args=(firewall_id, dict(target)),
            daemon=True,
            name=f"opn-backfill-{firewall_id}",
        ).start()


def _opnsense_cached_archive(
    firewall_id: int,
    target: Dict[str, Any],
    minutes: int,
    force: bool = False,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return immediately from a shared progressive archive.

    Only the newest 100 OPNsense rows are fetched synchronously.  Older pages
    are loaded in the background until the widest range requested by the user
    is covered.  Switching 1h -> 7d -> 30d therefore extends the same cache
    instead of rescanning from page 1 for every range.
    """
    safe_minutes = max(1, min(int(minutes or 60), 5256000))
    all_time = safe_minutes >= 5256000
    now = time.time()
    cutoff_ms = 0 if all_time else int(now * 1000) - safe_minutes * 60 * 1000

    with _OPN_VIEW_CACHE_LOCK:
        entry = _OPN_VIEW_CACHE.get(firewall_id)
        host_changed = bool(entry and entry.get("target_host") != str(target.get("host", "")))
        if force or host_changed:
            _OPN_VIEW_CACHE.pop(firewall_id, None)
            entry = None
        if entry is None:
            entry = _new_opn_archive_entry(target)
            if all_time:
                entry["requested_cutoff_ms"] = 0
            else:
                entry["requested_cutoff_ms"] = cutoff_ms
            _OPN_VIEW_CACHE[firewall_id] = entry
        last_latest_refresh = float(entry.get("last_latest_refresh") or 0)

    # One small synchronous request gives the page useful data immediately.
    if now - last_latest_refresh >= _OPN_LATEST_REFRESH_SECONDS:
        try:
            latest = _fetch_opnsense_page(target, 1, _OPN_INITIAL_ROWS)
            with _OPN_VIEW_CACHE_LOCK:
                entry = _OPN_VIEW_CACHE.get(firewall_id)
                if entry:
                    _opn_entry_merge_rows(entry, latest, newest=True)
                    entry["last_latest_refresh"] = now
                    entry["error"] = ""
        except Exception as exc:
            with _OPN_VIEW_CACHE_LOCK:
                entry = _OPN_VIEW_CACHE.get(firewall_id)
                if entry:
                    entry["error"] = str(exc)

    _ensure_opn_backfill(firewall_id, target, cutoff_ms)

    with _OPN_VIEW_CACHE_LOCK:
        entry = _OPN_VIEW_CACHE.get(firewall_id) or _new_opn_archive_entry(target)
        rows = list(entry.get("rows") or [])
        oldest = _opn_oldest_ms(entry)
        meta = {
            "loading": bool(entry.get("loading")),
            "complete": bool(_opn_requested_range_complete(entry)),
            "scan_complete": bool(entry.get("scan_complete")),
            "pages_loaded": int(entry.get("pages_loaded") or 0),
            "cached_rows": len(rows),
            "oldest_ms": oldest,
            "error": str(entry.get("error") or ""),
        }
    return rows, meta


def _native_histogram(rows: List[Dict[str, Any]], minutes: int) -> Dict[str, Any]:
    timestamps = [value for row in rows if (value := _log_timestamp_ms(row.get("time"))) is not None]
    safe_minutes = max(1, min(int(minutes or 60), 5256000))
    now_ms = int(time.time() * 1000)
    if safe_minutes >= 5256000 and timestamps:
        start_ms = min(timestamps)
        end_ms = max(timestamps) + 1
    else:
        end_ms = now_ms
        start_ms = now_ms - safe_minutes * 60 * 1000

    span = max(60_000, end_ms - start_ms)
    candidates = [
        30_000, 60_000, 120_000, 300_000, 600_000, 900_000, 1_800_000,
        3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000,
        172_800_000, 604_800_000, 2_592_000_000,
    ]
    target_interval = max(1, span // 30)
    interval = next((candidate for candidate in candidates if candidate >= target_interval), candidates[-1])
    start_ms = (start_ms // interval) * interval
    end_ms = ((end_ms + interval - 1) // interval) * interval
    buckets = {start: 0 for start in range(start_ms, end_ms, interval)}
    for timestamp in timestamps:
        if timestamp < start_ms or timestamp >= end_ms:
            continue
        key = (timestamp // interval) * interval
        if key in buckets:
            buckets[key] += 1
    return {
        "interval_ms": interval,
        "buckets": [{"start": start, "count": count} for start, count in buckets.items()],
    }


def _rows_for_minutes(archive: List[Dict[str, Any]], minutes: int) -> List[Dict[str, Any]]:
    """Slice a newest-first archive without scanning rows older than needed."""
    safe_minutes = max(1, min(int(minutes or 60), 5256000))
    if safe_minutes >= 5256000:
        return list(archive)
    cutoff = int(time.time() * 1000) - safe_minutes * 60 * 1000
    result: List[Dict[str, Any]] = []
    for row in archive:
        value = _log_timestamp_ms(row.get("time"))
        if value is not None and value < cutoff:
            break
        result.append(row)
    return result


def _opnsense_server_view(firewall_id: int, target: Dict[str, Any], filters: OpnsenseLogFilter) -> Dict[str, Any]:
    """Lightweight real-time OPNsense view.

    OPNsense's live-log API is optimized for recent rows, not long historical
    aggregation.  Keep this endpoint intentionally focused on the newest
    snapshot so the 5-second refresh remains responsive.  Historical analysis
    belongs in Elasticsearch; this view never starts the progressive archive
    backfill worker.
    """
    # Read exactly one recent snapshot in one OPNsense request.  This keeps
    # the live view fast and predictable even on slower appliances.
    fetch_size = 100
    latest_rows, fetch_attempts = _fetch_opnsense_recent_snapshot(target, fetch_size)

    minutes = max(1, min(int(filters.minutes or 60), 5256000))
    if minutes < 5256000:
        cutoff_ms = int(time.time() * 1000) - minutes * 60 * 1000
        range_rows = [
            row for row in latest_rows
            if (value := _log_timestamp_ms(row.get("time"))) is not None and value >= cutoff_ms
        ]
    else:
        range_rows = list(latest_rows)

    filtered = _opn_log_apply_filters(range_rows, filters)

    if filters.fromMs is not None or filters.toMs is not None:
        from_ms = int(filters.fromMs) if filters.fromMs is not None else None
        to_ms = int(filters.toMs) if filters.toMs is not None else None
        filtered = [
            row for row in filtered
            if (value := _log_timestamp_ms(row.get("time"))) is not None
            and (from_ms is None or value >= from_ms)
            and (to_ms is None or value < to_ms)
        ]

    def includes(value: Any, needle: str) -> bool:
        needle = str(needle or "").strip().lower()
        return not needle or needle in _safe_text(value, "").lower()

    filtered = [
        row for row in filtered
        if includes(row.get("protocol"), filters.protocol or "")
        and includes(row.get("source"), filters.source or "")
        and includes(row.get("destination"), filters.destination or "")
        and includes(row.get("interface"), filters.interface or "")
        and includes(row.get("action"), filters.action or "")
    ]
    filtered.sort(key=lambda row: _log_timestamp_ms(row.get("time")) or 0, reverse=True)

    page_size = max(20, min(int(filters.pageSize or filters.tableSize or 100), 100))
    page_rows = filtered[:page_size]
    histogram = _native_histogram(filtered, minutes) if filters.includeHistogram else None

    return {
        "firewall": serialize_firewall(target),
        "source": "/api/diagnostics/firewall/log",
        "server_view": True,
        "live_snapshot": True,
        "rows": page_rows,
        "total": len(filtered),
        "page": 1,
        "page_size": page_size,
        "has_more": False,
        "histogram": histogram,
        "archive_cached_rows": 0,
        "archive_loading": False,
        "archive_complete": True,
        "archive_scan_complete": True,
        "archive_pages_loaded": 0,
        "archive_oldest_ms": None,
        "archive_error": "",
        "range_minutes": minutes,
        "fetch_method": next((a.get("method") for a in reversed(fetch_attempts) if a.get("usable_rows", 0) > 0), None),
        "fetch_attempts": fetch_attempts,
        "message": None if page_rows else "OPNsense live-log API가 200을 반환했지만 로그 행이 비어 있습니다.",
    }

@app.post("/api/firewalls/{firewall_id}/opnsense-logs")
def get_opnsense_firewall_logs(firewall_id: int, filters: OpnsenseLogFilter):
    target = get_firewall_or_404(firewall_id)
    if filters.serverView:
        return _opnsense_server_view(firewall_id, target, filters)

    search_phrase = (filters.search or "").strip()
    fetch_all = bool(filters.fetchAll)
    # OPNsense's diagnostics/firewall/log endpoint is Bootgrid-style: current
    # is the page number and rowCount is the page size.  Keep each request
    # reasonably small, but walk every available page when fetchAll=True.
    page_size = max(50, min(int(filters.pageSize or filters.historySize or 500), 1000))
    max_rows = max(page_size, min(int(filters.maxRows or 50000), 200000))
    if not fetch_all:
        requested = filters.historySize or filters.tableSize or 100
        page_size = max(1, min(int(requested), 1000))
        max_rows = page_size

    attempts: List[Dict[str, Any]] = []

    def row_identity(row: Dict[str, Any]) -> str:
        raw = row.get("raw") if isinstance(row, dict) else None
        return json.dumps([
            row.get("time"), row.get("source"), row.get("destination"),
            row.get("action"), row.get("protocol"), row.get("label"), raw,
        ], ensure_ascii=False, sort_keys=True, default=str)

    # Prefer the POST form because it supports explicit pagination.
    # Stop if OPNsense returns fewer rows, an empty page, or a page that adds
    # no new identities (some older versions ignore `current`).
    collected: List[Dict[str, Any]] = []
    seen: set[str] = set()
    page = 1
    # Do not assume OPNsense honors the requested rowCount exactly; several
    # versions cap each page internally.  Keep walking until an empty/repeated
    # page rather than stopping just because a page is smaller than page_size.
    max_pages = 1000

    while page <= max_pages and len(collected) < max_rows:
        path = "/api/diagnostics/firewall/log"
        try:
            data = opnsense_request(
                target=target,
                method="POST",
                path=path,
                json_data={
                    "current": page,
                    "rowCount": page_size,
                    "searchPhrase": search_phrase,
                    "sort": {},
                },
            )
            raw_rows = _extract_log_rows_from_payload(data)
            attempts.append({
                "method": "POST",
                "path": path,
                "page": page,
                "ok": True,
                "found_rows": len(raw_rows),
                "requested_limit": page_size,
                "response_type": type(data).__name__,
                "response_keys": list(data.keys()) if isinstance(data, dict) else [],
            })

            if not raw_rows:
                break

            new_rows = 0
            for index, raw_row in enumerate(raw_rows):
                normalized = normalize_opnsense_log_row(raw_row, (page - 1) * page_size + index)
                if (
                    normalized.get("interface") == "-"
                    and normalized.get("time") == "-"
                    and normalized.get("source") == "-"
                    and normalized.get("destination") == "-"
                    and normalized.get("label") == "-"
                ):
                    continue
                identity = row_identity(normalized)
                if identity in seen:
                    continue
                seen.add(identity)
                collected.append(normalized)
                new_rows += 1
                if len(collected) >= max_rows:
                    break

            if not fetch_all:
                break
            if new_rows == 0:
                break
            page += 1

        except HTTPException as exc:
            attempts.append({
                "method": "POST", "path": path, "page": page,
                "ok": False, "error": exc.detail,
            })
            # If the paginated POST endpoint is unavailable, fall back to the
            # one-shot GET form below.
            collected = []
            seen = set()
            break
        except Exception as exc:
            attempts.append({
                "method": "POST", "path": path, "page": page,
                "ok": False, "error": str(exc),
            })
            collected = []
            seen = set()
            break

    # Compatibility fallback for installations that expose only the GET form.
    if not collected:
        get_limit = max_rows if fetch_all else page_size
        get_limit = max(1, min(get_limit, 50000))
        path = f"/api/diagnostics/firewall/log?limit={get_limit}"
        try:
            data = opnsense_request(target=target, method="GET", path=path, json_data=None)
            raw_rows = _extract_log_rows_from_payload(data)
            attempts.append({
                "method": "GET", "path": path, "ok": True,
                "found_rows": len(raw_rows), "requested_limit": get_limit,
                "response_type": type(data).__name__,
                "response_keys": list(data.keys()) if isinstance(data, dict) else [],
            })
            for index, raw_row in enumerate(raw_rows[:max_rows]):
                normalized = normalize_opnsense_log_row(raw_row, index)
                if (
                    normalized.get("interface") == "-"
                    and normalized.get("time") == "-"
                    and normalized.get("source") == "-"
                    and normalized.get("destination") == "-"
                    and normalized.get("label") == "-"
                ):
                    continue
                identity = row_identity(normalized)
                if identity in seen:
                    continue
                seen.add(identity)
                collected.append(normalized)
        except HTTPException as exc:
            attempts.append({"method": "GET", "path": path, "ok": False, "error": exc.detail})
        except Exception as exc:
            attempts.append({"method": "GET", "path": path, "ok": False, "error": str(exc)})

    filtered_rows = _opn_log_apply_filters(collected, filters)

    # fetchAll deliberately returns the full retained set.  The live-refresh
    # path still limits rows, which keeps the 5-second poll inexpensive.
    if fetch_all:
        limited_rows = filtered_rows
    else:
        visible_limit = max(1, min(int(filters.tableSize or 100), 1000))
        limited_rows = filtered_rows[:visible_limit]

    return {
        "firewall": serialize_firewall(target),
        "source": "/api/diagnostics/firewall/log",
        "method": "POST" if collected else None,
        "total": len(filtered_rows),
        "returned": len(limited_rows),
        "requested_limit": page_size,
        "fetch_all": fetch_all,
        "pages_scanned": max(1, page if collected else 0),
        "truncated": fetch_all and len(collected) >= max_rows,
        "rows": limited_rows,
        "attempts": attempts,
        "message": None if limited_rows else "OPNsense에서 현재 보관 중인 방화벽 로그를 찾지 못했습니다.",
    }

@app.post("/api/firewalls/{firewall_id}/event-logs")
def get_event_logs(firewall_id: int, body: EventLogsQueryBody):
    target = get_firewall_or_404(firewall_id)
    event_index = str(target.get("event_log_index") or "").strip()
    if not event_index:
        raise HTTPException(
            status_code=409,
            detail="방화벽 이벤트 인덱스가 설정되지 않았습니다. 방화벽 관리에서 OPNsense filterlog 전용 인덱스를 설정하세요.",
        )
    rows = search_firewall_archive_events(
        target=target,
        log_index=event_index,
        size=max(1, min(body.size, 1000)),
        minutes=max(1, min(body.minutes, 5256000)),
        action=body.action.strip(),
        interface=body.interface.strip(),
        protocol=body.protocol.strip(),
        source_ip=body.source.strip(),
        destination_ip=body.destination.strip(),
        query_text=body.query.strip(),
    )
    return {
        "rows": rows,
        "firewall": serialize_firewall(target),
        "exportColumns": KIBANA_EXPORT_COLUMNS,
        "source": "ELK",
        "index": event_index,
    }
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from fastapi import HTTPException




# ============================================================
# Interface rules API - single optimized version
# ============================================================
class InterfaceRuleCreate(BaseModel):
    interface: str = "lan"
    description: str = ""
    action: str = "pass"
    direction: str = "in"
    protocol: str = "TCP"
    sourceNet: str = "any"
    sourcePort: str = ""
    destinationNet: str = "any"
    destinationPort: str = ""
    log: bool = False
    enabled: str = "1"
    quick: str = "1"


class InterfaceRuleUpdate(BaseModel):
    interface: Optional[str] = None
    description: Optional[str] = None
    action: Optional[str] = None
    direction: Optional[str] = None
    protocol: Optional[str] = None
    sourceNet: Optional[str] = None
    sourcePort: Optional[str] = None
    destinationNet: Optional[str] = None
    destinationPort: Optional[str] = None
    log: Optional[bool] = None
    enabled: Optional[str] = None
    quick: Optional[str] = None


def _ir_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value if value.strip() else default
    if isinstance(value, (int, float, bool)):
        return str(value)
    return str(value)


def _ir_extract_rows(data: Any) -> List[Any]:
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []

    for key in ["rows", "row", "data", "rules", "items", "records", "result", "results"]:
        value = data.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested = _ir_extract_rows(value)
            if nested:
                return nested

    rows: List[Any] = []
    for key, value in data.items():
        if isinstance(value, dict) and any(
            k in value
            for k in ["uuid", "rule", "action", "interface", "descr", "description", "protocol", "source", "destination"]
        ):
            if "uuid" not in value and isinstance(key, str):
                value = {"uuid": key, **value}
            rows.append(value)
    return rows


def _ir_normalize_interface_key(value: Any) -> str:
    return _ir_text(value, "").strip().lower()


def _ir_normalize_interface_row(row: Any, index: int = 0) -> Dict[str, Any]:
    if not isinstance(row, dict):
        text = _ir_text(row, f"if-{index}")
        return {
            "id": text,
            "key": text.lower(),
            "name": text.upper(),
            "device": text,
            "status": "-",
            "ipaddr": "-",
            "macaddr": "-",
            "raw": row,
        }

    key = (
        row.get("identifier")
        or row.get("key")
        or row.get("name")
        or row.get("if")
        or row.get("interface")
        or row.get("device")
        or f"if-{index}"
    )
    name = row.get("descr") or row.get("description") or row.get("name") or key

    return {
        "id": _ir_text(key, f"if-{index}"),
        "key": _ir_normalize_interface_key(key),
        "name": _ir_text(name, _ir_text(key, f"IF{index}")).upper(),
        "device": _ir_text(row.get("device") or row.get("if") or row.get("interface") or "-"),
        "status": _ir_text(row.get("status") or row.get("link_state") or row.get("media") or "-"),
        "ipaddr": _ir_text(row.get("ipaddr") or row.get("ipv4") or row.get("addr") or "-"),
        "macaddr": _ir_text(row.get("macaddr") or row.get("mac") or "-"),
        "raw": row,
    }


def _ir_extract_interfaces(data: Any) -> List[Dict[str, Any]]:
    rows = _ir_extract_rows(data)
    if not rows and isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                rows.append({"identifier": key, **value})

    seen = set()
    result = []
    for index, row in enumerate(rows):
        item = _ir_normalize_interface_row(row, index)
        key = item.get("key")
        if key and key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _ir_unwrap_rule(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    if isinstance(row.get("rule"), dict):
        rule = {**row.get("rule")}
        if row.get("uuid") and not rule.get("uuid"):
            rule["uuid"] = row.get("uuid")
        return rule
    return row


def _ir_normalize_rule_row(row: Any, index: int = 0, source_name: str = "automation") -> Dict[str, Any]:
    rule = _ir_unwrap_rule(row)
    if not rule:
        return {
            "uuid": f"rule-{index}",
            "enabled": "1",
            "quick": "1",
            "interface": "-",
            "direction": "-",
            "action": "-",
            "protocol": "-",
            "sourceNet": "-",
            "sourcePort": "",
            "destinationNet": "-",
            "destinationPort": "",
            "description": _ir_text(row),
            "log": False,
            "kind": "unknown",
            "readonly": True,
            "raw": row,
        }

    source = rule.get("source") if isinstance(rule.get("source"), dict) else {}
    destination = rule.get("destination") if isinstance(rule.get("destination"), dict) else {}
    interface = rule.get("interface") or rule.get("if") or rule.get("iface") or "-"
    if isinstance(interface, list):
        interface = ",".join([_ir_text(x, "") for x in interface if _ir_text(x, "")])

    return {
        "uuid": _ir_text(rule.get("uuid") or rule.get("id") or rule.get("__uuid") or f"rule-{index}"),
        "enabled": _ir_text(rule.get("enabled"), "1"),
        "quick": _ir_text(rule.get("quick"), "1"),
        "interface": _ir_normalize_interface_key(interface) or "-",
        "direction": _ir_text(rule.get("direction") or rule.get("dir") or "in"),
        "action": _ir_text(rule.get("action") or "pass").lower(),
        "protocol": _ir_text(rule.get("protocol") or rule.get("proto") or "any"),
        "sourceNet": _ir_text(source.get("network") or source.get("address") or rule.get("sourceNet") or rule.get("source_net") or rule.get("src") or "any"),
        "sourcePort": _ir_text(source.get("port") or rule.get("sourcePort") or rule.get("source_port") or rule.get("srcport") or "", ""),
        "destinationNet": _ir_text(destination.get("network") or destination.get("address") or rule.get("destinationNet") or rule.get("destination_net") or rule.get("dst") or "any"),
        "destinationPort": _ir_text(destination.get("port") or rule.get("destinationPort") or rule.get("destination_port") or rule.get("dstport") or "", ""),
        "description": _ir_text(rule.get("description") or rule.get("descr") or rule.get("label") or "", ""),
        "log": str(rule.get("log") or "0").lower() in ["1", "true", "yes", "on"],
        "kind": "automation",
        "readonly": False,
        "sourceName": source_name,
        "raw": row,
    }


def _ir_build_rule_payload(rule: InterfaceRuleCreate | InterfaceRuleUpdate) -> Dict[str, Any]:
    def pick(name: str, default: Any = "") -> Any:
        value = getattr(rule, name, None)
        return default if value is None else value

    description = pick("description", "")
    return {
        "rule": {
            "enabled": str(pick("enabled", "1")),
            "quick": str(pick("quick", "1")),
            "interface": pick("interface", "lan"),
            "direction": pick("direction", "in"),
            "action": pick("action", "pass"),
            "protocol": pick("protocol", "TCP"),
            "source": {
                "network": pick("sourceNet", "any") or "any",
                "port": pick("sourcePort", "") or "",
            },
            "destination": {
                "network": pick("destinationNet", "any") or "any",
                "port": pick("destinationPort", "") or "",
            },
            "log": "1" if bool(pick("log", False)) else "0",
            "description": description,
            "descr": description,
        }
    }


def _ir_request(target: Dict[str, Any], method: str, path: str, json_data: Optional[Dict[str, Any]] = None) -> Any:
    return opnsense_request(target=target, method=method, path=path, json_data=json_data)


@app.get("/api/firewalls/{firewall_id}/interfaces")
def get_firewall_interfaces(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    candidates = [
        ("GET", "/api/interfaces/overview/interfaces_info", None),
        ("GET", "/api/interfaces/overview/interfacesInfo", None),
        ("GET", "/api/diagnostics/interface/getInterfaceNames", None),
        ("GET", "/api/diagnostics/interface/getInterfaceStatistics", None),
    ]
    attempts = []
    for method, path, body in candidates:
        try:
            data = _ir_request(target, method, path, body)
            interfaces = _ir_extract_interfaces(data)
            attempts.append({"method": method, "path": path, "ok": True, "count": len(interfaces)})
            if interfaces:
                return {"firewall": serialize_firewall(target), "source": path, "interfaces": interfaces, "attempts": attempts}
        except Exception as e:
            attempts.append({"method": method, "path": path, "ok": False, "error": str(e)})

    return {
        "firewall": serialize_firewall(target),
        "source": None,
        "interfaces": [
            {"id": "lan", "key": "lan", "name": "LAN", "device": "em1", "status": "-", "ipaddr": "-", "macaddr": "-", "raw": {}},
            {"id": "wan", "key": "wan", "name": "WAN", "device": "em0", "status": "-", "ipaddr": "-", "macaddr": "-", "raw": {}},
        ],
        "attempts": attempts,
        "message": "인터페이스 API 응답을 찾지 못해 기본 LAN/WAN을 사용합니다.",
    }


@app.get("/api/firewalls/{firewall_id}/interface-rules")
def get_interface_rules(firewall_id: int, interface: Optional[str] = None):
    target = get_firewall_or_404(firewall_id)
    candidates = [
        ("GET", "/api/firewall/filter/searchRule", None),
        ("POST", "/api/firewall/filter/searchRule", {"current": 1, "rowCount": 9999, "searchPhrase": ""}),
        ("GET", "/api/firewall/filter/search_rule", None),
        ("POST", "/api/firewall/filter/search_rule", {"current": 1, "rowCount": 9999, "searchPhrase": ""}),
    ]
    attempts = []
    for method, path, body in candidates:
        try:
            data = _ir_request(target, method, path, body)
            rows = _ir_extract_rows(data)
            rules = [_ir_normalize_rule_row(row, index) for index, row in enumerate(rows)]
            if interface:
                want = interface.lower()
                rules = [
                    rule for rule in rules
                    if str(rule.get("interface", "")).lower() == want
                    or want in str(rule.get("interface", "")).lower().split(",")
                ]
            attempts.append({"method": method, "path": path, "ok": True, "count": len(rules)})
            if rows:
                return {"firewall": serialize_firewall(target), "source": path, "interface": interface, "rows": rules, "attempts": attempts}
        except Exception as e:
            attempts.append({"method": method, "path": path, "ok": False, "error": str(e)})

    return {"firewall": serialize_firewall(target), "source": None, "interface": interface, "rows": [], "attempts": attempts}


@app.post("/api/firewalls/{firewall_id}/interface-rules")
def add_interface_rule(firewall_id: int, rule: InterfaceRuleCreate):
    target = get_firewall_or_404(firewall_id)
    payload = _ir_build_rule_payload(rule)
    attempts = []
    last_error = None
    for path in ["/api/firewall/filter/addRule", "/api/firewall/filter/add_rule"]:
        try:
            data = _ir_request(target, "POST", path, payload)
            return {"ok": True, "firewall": serialize_firewall(target), "source": path, "result": data}
        except Exception as e:
            last_error = str(e)
            attempts.append({"method": "POST", "path": path, "ok": False, "error": last_error})
    raise HTTPException(status_code=502, detail={"message": f"룰 추가 실패: {last_error}", "attempts": attempts})


@app.put("/api/firewalls/{firewall_id}/interface-rules/{uuid}")
def update_interface_rule(firewall_id: int, uuid: str, rule: InterfaceRuleUpdate):
    target = get_firewall_or_404(firewall_id)
    payload = _ir_build_rule_payload(rule)
    attempts = []
    last_error = None
    for method, path in [
        ("POST", f"/api/firewall/filter/setRule/{uuid}"),
        ("POST", f"/api/firewall/filter/set_rule/{uuid}"),
        ("PUT", f"/api/firewall/filter/setRule/{uuid}"),
    ]:
        try:
            data = _ir_request(target, method, path, payload)
            return {"ok": True, "firewall": serialize_firewall(target), "source": path, "uuid": uuid, "result": data}
        except Exception as e:
            last_error = str(e)
            attempts.append({"method": method, "path": path, "ok": False, "error": last_error})
    raise HTTPException(status_code=502, detail={"message": f"룰 수정 실패: {last_error}", "attempts": attempts})


@app.delete("/api/firewalls/{firewall_id}/interface-rules/{uuid}")
def delete_interface_rule(firewall_id: int, uuid: str):
    target = get_firewall_or_404(firewall_id)
    attempts = []
    last_error = None
    for method, path, body in [
        ("POST", f"/api/firewall/filter/delRule/{uuid}", {}),
        ("POST", f"/api/firewall/filter/del_rule/{uuid}", {}),
        ("DELETE", f"/api/firewall/filter/delRule/{uuid}", None),
    ]:
        try:
            data = _ir_request(target, method, path, body)
            return {"ok": True, "firewall": serialize_firewall(target), "source": path, "uuid": uuid, "result": data}
        except Exception as e:
            last_error = str(e)
            attempts.append({"method": method, "path": path, "ok": False, "error": last_error})
    raise HTTPException(status_code=502, detail={"message": f"룰 삭제 실패: {last_error}", "attempts": attempts})


@app.post("/api/firewalls/{firewall_id}/interface-rules/apply")
def apply_interface_rules(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    attempts = []
    last_error = None
    for path in ["/api/firewall/filter/apply", "/api/firewall/filter_base/apply"]:
        try:
            data = _ir_request(target, "POST", path, {})
            return {"ok": True, "firewall": serialize_firewall(target), "source": path, "result": data}
        except Exception as e:
            last_error = str(e)
            attempts.append({"method": "POST", "path": path, "ok": False, "error": last_error})
    raise HTTPException(status_code=502, detail={"message": f"룰 적용 실패: {last_error}", "attempts": attempts})


# ============================================================
# OPNsense WebGUI legacy/autogenerated rule parser - optimized
# ============================================================
def _legacy_get_attr(target: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(target, dict) and target.get(name) not in [None, ""]:
            return target.get(name)
        if hasattr(target, name) and getattr(target, name) not in [None, ""]:
            return getattr(target, name)
    return default


def _legacy_clean_text(value: str) -> str:
    if value is None:
        return ""
    text = html.unescape(str(value))
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _legacy_base_url(target: Any) -> str:
    host = _legacy_get_attr(target, "host", "url", "base_url", "opnsense_host")
    if not host:
        raise HTTPException(status_code=400, detail="OPNsense host 정보가 없습니다.")

    host = str(host).strip().rstrip("/")
    if not host.startswith("http://") and not host.startswith("https://"):
        host = "https://" + host
    return host


def _legacy_verify_ssl(target: Any) -> bool:
    value = _legacy_get_attr(target, "verify_ssl", "ssl_verify", default=False)
    if isinstance(value, bool):
        return value
    return str(value).lower() in ["1", "true", "yes", "on"]


def _legacy_web_credentials(target: Any) -> tuple[str, str]:
    username = _legacy_get_attr(target, "web_username", "gui_username", default=None) or os.getenv("OPNSENSE_WEB_USERNAME")
    password = _legacy_get_attr(target, "web_password", "gui_password", default=None) or os.getenv("OPNSENSE_WEB_PASSWORD")

    if not username or not password:
        raise HTTPException(
            status_code=400,
            detail="WebGUI 로그인 정보가 없습니다. .env에 OPNSENSE_WEB_USERNAME, OPNSENSE_WEB_PASSWORD를 추가하세요.",
        )
    return str(username), str(password)


def _legacy_find_csrf(form: BeautifulSoup) -> tuple[Optional[str], Optional[str]]:
    for inp in form.find_all("input", {"type": "hidden"}):
        name = inp.get("name")
        value = inp.get("value")
        if name and value:
            return name, value
    return None, None


def _legacy_login_session(target: Any) -> requests.Session:
    base_url = _legacy_base_url(target)
    verify_ssl = _legacy_verify_ssl(target)
    username, password = _legacy_web_credentials(target)

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = verify_ssl
    session.headers.update({
        "User-Agent": "Mozilla/5.0 OPNsense-Manager/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    first = session.get(urljoin(base_url + "/", "/firewall_rules.php?if=lan"), timeout=15, allow_redirects=True)
    first.raise_for_status()

    soup = BeautifulSoup(first.text, "html.parser")
    form = soup.find("form", {"id": "iform"}) or soup.find("form")
    if not form:
        return session

    csrf_name, csrf_value = _legacy_find_csrf(form)
    payload = {"usernamefld": username, "passwordfld": password, "login": "1"}
    if csrf_name and csrf_value:
        payload[csrf_name] = csrf_value

    headers = {"X-CSRFToken": csrf_value} if csrf_value else {}
    post_url = urljoin(first.url, form.get("action") or first.url)
    second = session.post(post_url, data=payload, headers=headers, timeout=15, allow_redirects=True)
    second.raise_for_status()

    if "page-login" in second.text or "usernamefld" in second.text or "passwordfld" in second.text:
        raise HTTPException(status_code=401, detail="OPNsense WebGUI 로그인 실패. username/password를 확인하세요.")
    return session


def _legacy_drop_noise_text(text: str) -> str:
    text = _legacy_clean_text(text)
    noise_words = {"없음", "none", "no", "n/a", "-", "조회", "전용", "조회전용", "수정", "삭제", "복제", "검사", "inspect", "edit", "delete", "clone"}
    parts = text.split()
    while parts and parts[0].strip().lower() in noise_words:
        parts.pop(0)
    while parts and parts[-1].strip().lower() in noise_words:
        parts.pop()
    cleaned = " ".join(parts)
    cleaned = re.sub(r"^(없음\s*)+", "", cleaned)
    cleaned = re.sub(r"(\s*없음)+$", "", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def _legacy_cell_text(cell: BeautifulSoup) -> str:
    cloned = BeautifulSoup(str(cell), "html.parser")
    for tag in cloned.find_all(["button", "a", "i"]):
        tag.decompose()
    for tag in cloned.find_all(["span"]):
        classes = " ".join(tag.get("class") or []).lower()
        title = (tag.get("title") or tag.get("data-original-title") or "").lower()
        aria = (tag.get("aria-label") or "").lower()
        text = _legacy_clean_text(tag.get_text(" ", strip=True))
        if (
            "fa-" in classes or "glyphicon" in classes or "icon" in classes or "btn" in classes
            or any(word in title for word in ["inspect", "edit", "delete", "clone"])
            or any(word in aria for word in ["inspect", "edit", "delete", "clone"])
            or text in ["", " ", "✓", "×"]
        ):
            tag.decompose()
    return _legacy_drop_noise_text(cloned.get_text(" ", strip=True))


def _legacy_extract_row_text_cells(row: BeautifulSoup) -> List[str]:
    cells = []
    for cell in row.find_all(["td", "th"], recursive=False):
        text = _legacy_cell_text(cell)
        if text:
            cells.append(text)
    return cells


def _legacy_guess_kind(text: str, classes: List[str]) -> str:
    lower = text.lower()
    class_text = " ".join(classes).lower()
    if (
        "automatically generated" in lower or "automatic" in lower or "auto-generated" in lower
        or "system" in lower or "default deny" in lower or "ipv6 rfc4890" in lower
        or "sshlockout" in lower or "virusprot" in lower or "anti-lockout" in lower
        or "autogenerated" in class_text
    ):
        return "automatic"
    return "legacy"


def _legacy_guess_enabled(text: str, classes: List[str]) -> str:
    lower = text.lower()
    class_text = " ".join(classes).lower()
    if "disabled" in lower or "disabled" in class_text or "text-muted" in class_text:
        return "0"
    return "1"


def _legacy_guess_action(text: str) -> str:
    lower = text.lower()
    if re.search(r"\bblock\b", lower) or "deny" in lower:
        return "block"
    if re.search(r"\breject\b", lower):
        return "reject"
    if re.search(r"\bpass\b", lower) or re.search(r"\ballow\b", lower):
        return "pass"
    if re.search(r"\bmatch\b", lower):
        return "match"
    return "-"


def _legacy_guess_direction(text: str) -> str:
    lower = text.lower()
    if re.search(r"\bin\b", lower) or "inbound" in lower or "수신" in lower:
        return "in"
    if re.search(r"\bout\b", lower) or "outbound" in lower or "송신" in lower:
        return "out"
    return "-"


def _legacy_guess_protocol(text: str) -> str:
    lower = text.lower()
    candidates = [
        "ipv4+6 tcp/udp", "ipv4+6 tcp", "ipv4+6 udp", "ipv4+6 icmp", "ipv4+6 *",
        "ipv4 tcp/udp", "ipv4 tcp", "ipv4 udp", "ipv4 icmp", "ipv4 *",
        "ipv6 tcp/udp", "ipv6 tcp", "ipv6 udp", "ipv6 icmp", "ipv6 ipv6-icmp", "ipv6 *",
        "tcp/udp", "tcp", "udp", "icmp", "ipv6-icmp", "*",
    ]
    for item in candidates:
        if item in lower:
            return item.upper()
    return "-"


def _legacy_is_noise_cell(value: str) -> bool:
    text = _legacy_drop_noise_text(value).strip()
    return text.lower() in ["", "없음", "none", "no", "n/a", "-", "조회 전용", "조회전용"]


def _legacy_find_protocol_index(cells: List[str]) -> tuple[int, str]:
    protocol_patterns = [
        r"^ipv4\+6\s+tcp/udp$", r"^ipv4\+6\s+tcp$", r"^ipv4\+6\s+udp$", r"^ipv4\+6\s+icmp$", r"^ipv4\+6\s+\*$",
        r"^ipv4\s+tcp/udp$", r"^ipv4\s+tcp$", r"^ipv4\s+udp$", r"^ipv4\s+icmp$", r"^ipv4\s+\*$",
        r"^ipv6\s+tcp/udp$", r"^ipv6\s+tcp$", r"^ipv6\s+udp$", r"^ipv6\s+icmp$", r"^ipv6\s+ipv6-icmp$", r"^ipv6\s+\*$",
        r"^tcp/udp$", r"^tcp$", r"^udp$", r"^icmp$", r"^ipv6-icmp$", r"^\*$",
    ]
    for index, cell in enumerate(cells):
        normalized = _legacy_clean_text(cell).lower()
        for pattern in protocol_patterns:
            if re.match(pattern, normalized):
                return index, cell
    return -1, "-"


def _legacy_normalize_cells_to_rule(cells: List[str], row_text: str, interface_key: str, sequence: int, classes: List[str]) -> Dict[str, Any]:
    clean_cells = [_legacy_drop_noise_text(cell) for cell in cells]
    clean_cells = [cell for cell in clean_cells if cell and not _legacy_is_noise_cell(cell)]

    protocol_index, protocol = _legacy_find_protocol_index(clean_cells)
    if protocol_index == -1:
        protocol = _legacy_guess_protocol(row_text)

    source_net = "-"
    source_port = ""
    destination_net = "-"
    destination_port = ""
    description = ""

    if protocol_index >= 0:
        after = clean_cells[protocol_index + 1 :]
        if len(after) >= 1:
            source_net = after[0]
        if len(after) >= 2:
            source_port = "" if _legacy_is_noise_cell(after[1]) else after[1]
        if len(after) >= 3:
            destination_net = after[2]
        if len(after) >= 4:
            destination_port = "" if _legacy_is_noise_cell(after[3]) else after[3]
        tail = [_legacy_drop_noise_text(item) for item in after[4:]]
        tail = [item for item in tail if item and not _legacy_is_noise_cell(item)]
        if tail:
            description = tail[-1]

    if not description:
        candidates = []
        for cell in clean_cells:
            if cell in [protocol, source_net, source_port, destination_net, destination_port] or _legacy_is_noise_cell(cell):
                continue
            candidates.append(cell)
        description = candidates[-1] if candidates else row_text

    if _legacy_is_noise_cell(source_net):
        source_net = "*"
    if _legacy_is_noise_cell(destination_net):
        destination_net = "*"

    return {
        "uuid": f"legacy-{interface_key}-{sequence}",
        "interface": interface_key,
        "kind": _legacy_guess_kind(row_text, classes),
        "readonly": True,
        "enabled": _legacy_guess_enabled(row_text, classes),
        "direction": _legacy_guess_direction(row_text),
        "action": _legacy_guess_action(row_text),
        "protocol": protocol,
        "sourceNet": source_net,
        "sourcePort": source_port,
        "destinationNet": destination_net,
        "destinationPort": destination_port,
        "description": _legacy_drop_noise_text(description),
        "log": "log" in row_text.lower(),
        "rawText": row_text,
        "rawCells": clean_cells,
        "sourceName": "webgui/firewall_rules.php",
    }


def _legacy_parse_rule_table(html_text: str, interface_key: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html_text, "html.parser")
    if soup.find("body", class_="page-login") or soup.find("input", {"id": "usernamefld"}):
        raise HTTPException(status_code=401, detail="WebGUI 로그인 페이지가 반환되었습니다.")

    tables = soup.find_all("table")
    candidate_tables = []
    for table in tables:
        table_text = _legacy_clean_text(table.get_text(" ", strip=True)).lower()
        if any(keyword in table_text for keyword in ["pass", "block", "reject", "default deny", "firewall", "rule", "allow"]):
            candidate_tables.append(table)
    if not candidate_tables:
        candidate_tables = tables

    parsed_rows = []
    sequence = 0
    for table in candidate_tables:
        for row in table.find_all("tr"):
            classes = row.get("class") or []
            cells = _legacy_extract_row_text_cells(row)
            row_text = _legacy_clean_text(" ".join(cells))
            if not row_text:
                continue
            lower = row_text.lower()

            if "protocol" in lower and ("source" in lower or "출발" in lower) and ("destination" in lower or "목적" in lower) and len(cells) <= 14:
                continue

            is_group = (
                len(cells) == 1
                and any(keyword in lower for keyword in ["automatic", "automatically", "generated", "자동", "생성", "rule", "규칙"])
                and not any(keyword in lower for keyword in ["pass", "block", "reject", "allow"])
            )
            if is_group:
                sequence += 1
                parsed_rows.append({
                    "uuid": f"legacy-group-{interface_key}-{sequence}",
                    "interface": interface_key,
                    "kind": "group",
                    "readonly": True,
                    "enabled": "1",
                    "direction": "-",
                    "action": "-",
                    "protocol": "-",
                    "sourceNet": "-",
                    "sourcePort": "",
                    "destinationNet": "-",
                    "destinationPort": "",
                    "description": row_text,
                    "log": False,
                    "rawText": row_text,
                    "rawCells": cells,
                    "sourceName": "webgui/firewall_rules.php",
                })
                continue

            if lower in ["add", "delete", "apply", "save", "cancel", "추가", "삭제", "적용"]:
                continue

            if not any(keyword in lower for keyword in ["pass", "block", "reject", "allow", "deny", "match", "tcp", "udp", "icmp", "ipv4", "ipv6", "*"]):
                continue

            sequence += 1
            parsed_rows.append(_legacy_normalize_cells_to_rule(cells, row_text, interface_key, sequence, classes))

    unique = []
    seen = set()
    for item in parsed_rows:
        key = (item.get("rawText"), item.get("kind"), item.get("interface"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    return {"rows": unique, "tableCount": len(tables), "candidateTableCount": len(candidate_tables)}


@app.get("/api/firewalls/{firewall_id}/legacy-interface-rules")
def get_legacy_interface_rules(firewall_id: int, interface: str = "lan"):
    target = get_firewall_or_404(firewall_id)
    base_url = _legacy_base_url(target)
    interface_key = (interface or "lan").strip().lower()

    session = _legacy_login_session(target)
    page_url = urljoin(base_url + "/", f"/firewall_rules.php?if={interface_key}")
    response = session.get(page_url, timeout=15, allow_redirects=True)
    response.raise_for_status()
    parsed = _legacy_parse_rule_table(response.text, interface_key)

    return {
        "firewall": serialize_firewall(target),
        "source": f"/firewall_rules.php?if={interface_key}",
        "interface": interface_key,
        "rows": parsed["rows"],
        "tableCount": parsed["tableCount"],
        "candidateTableCount": parsed["candidateTableCount"],
        "message": "WebGUI HTML 파싱 결과입니다. 자동 생성/레거시 룰은 조회 전용입니다.",
    }


# Stored ELK results + explicit manual response only.
import ipaddress
from threading import Lock
MANUAL_BLOCK_LOCK = Lock()
MANUAL_BLOCK_FILE = BASE_DIR / "manual_blocks.json"

class ManualBlockBody(BaseModel):
    source_ip: str
    force: bool = False


def _load_manual_block_history() -> List[Dict[str, Any]]:
    try:
        if not MANUAL_BLOCK_FILE.exists():
            return []
        data = json.loads(MANUAL_BLOCK_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError, json.JSONDecodeError):
        return []


def _save_manual_block_history(history: List[Dict[str, Any]]) -> None:
    temp = MANUAL_BLOCK_FILE.with_suffix('.tmp')
    temp.write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(MANUAL_BLOCK_FILE)


def _current_manual_blocks(firewall_id: int) -> List[Dict[str, Any]]:
    latest: Dict[str, Dict[str, Any]] = {}
    for item in _load_manual_block_history():
        if not isinstance(item, dict) or int(item.get("firewall_id", -1)) != firewall_id:
            continue
        ip = str(item.get("ip") or "").strip()
        if not ip:
            continue
        latest[ip] = item

    rows = []
    for ip, item in latest.items():
        action = str(item.get("action") or "block").lower()
        if action != "block":
            continue
        rows.append({
            "ip": ip,
            "alias": item.get("alias") or os.getenv("SECURITY_BLOCK_ALIAS", "blocked_attackers"),
            "alert_id": item.get("alert_id") or "",
            "created_at": item.get("created_at"),
            "status": "blocked",
        })

    rows.sort(key=lambda row: int(row.get("created_at") or 0), reverse=True)
    return rows


def _manual_service(target):
    return ManualResponse(opnsense_request, target,
        os.getenv("SECURITY_BLOCK_ALIAS", "blocked_attackers").strip() or "blocked_attackers")


def _protected_manual_addresses():
    path = BASE_DIR / "manual_response_config.json"
    config = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    entries = config.get("protected_addresses", [])
    if not isinstance(entries, list):
        raise ResponseError("protected_addresses 설정은 IP/CIDR 목록이어야 합니다.")
    entries = entries + [x.strip() for x in os.getenv("SECURITY_PROTECTED_IPS", "").split(",") if x.strip()]
    for entry in entries:
        ipaddress.ip_network(str(entry), strict=False)
    return entries


def _manual_audit(firewall_id, ip, action, service, result, alert_id=""):
    record = {"firewall_id": firewall_id, "ip": ip, "alias": service.alias,
              "action": action, "alert_id": alert_id, "created_at": int(time.time())}
    try:
        history = _load_manual_block_history()
        history.append(record)
        _save_manual_block_history(history)
    except OSError:
        result["audit_warning"] = "방화벽 적용은 완료됐지만 로컬 이력 저장에 실패했습니다."
    return {**record, **result}


@app.get("/api/firewalls/{firewall_id}/manual-blocks")
def list_manual_blocks(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    try:
        with MANUAL_BLOCK_LOCK:
            service = _manual_service(target)
            _, config = service.alias_config()
            configured = contents(config.get("content", "")) if config else []
            runtime = service.table() if config else set()
            rules_ok = service.check_rules() if config else False
            history = {row["ip"]: row for row in _current_manual_blocks(firewall_id)}
            rows = []
            for raw in configured:
                try:
                    ip = str(ipaddress.ip_address(raw))
                except ValueError:
                    raise ResponseError("차단 Alias에 단일 IP 이외의 항목이 있습니다.")
                active = config.get("enabled") == "1" and rules_ok and service.member(ip, runtime)
                rows.append({**history.get(ip, {}), "ip": ip, "alias": service.alias,
                             "status": "blocked" if active else "not_applied"})
            rows.sort(key=lambda r: int(r.get("created_at") or 0), reverse=True)
            return {"rows": rows, "count": sum(r["status"] == "blocked" for r in rows),
                    "alias": service.alias, "verified": True}
    except ResponseError as exc:
        raise HTTPException(502, exc.detail)


@app.delete("/api/firewalls/{firewall_id}/manual-blocks/{ip_address}")
def unblock_manual_ip(firewall_id: int, ip_address: str):
    target = get_firewall_or_404(firewall_id)
    try:
        ip = str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        raise HTTPException(400, "유효한 IP 주소가 아닙니다.")
    try:
        with MANUAL_BLOCK_LOCK:
            service = _manual_service(target)
            result = service.change(ip, False)
            record = _manual_audit(firewall_id, ip, "unblock", service, result)
        return {**record, "message": f"{ip} 수동 차단을 해제했습니다."}
    except ResponseError as exc:
        raise HTTPException(502, exc.detail)


def _encode_page_cursor(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_page_cursor(value: str) -> Dict[str, Any]:
    value = str(value or "").strip()
    if not value:
        return {}
    try:
        padded = value + "=" * (-len(value) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        raise HTTPException(status_code=400, detail="잘못된 로그 페이지 커서입니다.")


def _security_event_query(
    minutes: int,
    query_text: str = "",
    attack_type: str = "",
    risk: str = "",
    source_ip: str = "",
    destination_ip: str = "",
    result: str = "attack",
    from_ms: Optional[int] = None,
    to_ms: Optional[int] = None,
) -> Dict[str, Any]:
    must: List[Dict[str, Any]] = []
    filters: List[Dict[str, Any]] = []
    must_not: List[Dict[str, Any]] = []

    if from_ms is not None or to_ms is not None:
        time_range: Dict[str, Any] = {}
        if from_ms is not None:
            time_range["gte"] = int(from_ms)
        if to_ms is not None:
            time_range["lt"] = int(to_ms)
        time_range["format"] = "epoch_millis"
        filters.append({"range": {"@timestamp": time_range}})
    else:
        safe_minutes = max(1, min(int(minutes or 60), 5256000))
        if safe_minutes < 5256000:
            filters.append({"range": {"@timestamp": {"gte": f"now-{safe_minutes}m", "lte": "now"}}})

    result = str(result or "all").strip().lower()
    if result == "attack":
        filters.append({
            "bool": {
                "should": [
                    {
                        "bool": {
                            "filter": [{"exists": {"field": "ml.detected_class"}}],
                            "must_not": [
                                {"terms": {"ml.detected_class.keyword": ["normal", "Normal", "benign", "Benign"]}}
                            ],
                        }
                    },
                    {
                        "bool": {
                            "filter": [{"exists": {"field": "suricata.eve.alert.signature"}}],
                            "must_not": [{"exists": {"field": "ml.detected_class"}}],
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        })
    elif result == "normal":
        filters.append({
            "bool": {
                "should": [
                    {"terms": {"ml.detected_class.keyword": ["normal", "Normal", "benign", "Benign"]}},
                    {"match_phrase": {"ml.detected_class": "Normal"}},
                    {"match_phrase": {"ml.detected_class": "Benign"}},
                ],
                "minimum_should_match": 1,
            }
        })
    elif result == "unanalyzed":
        must_not.append({"exists": {"field": "ml.detected_class"}})

    query_text = str(query_text or "").strip()
    if query_text:
        must.append({
            "multi_match": {
                "query": query_text,
                "fields": [
                    "ml.detected_class^3",
                    "final_risk^2",
                    "source.ip^2",
                    "destination.ip^2",
                    "suricata.eve.alert.signature^3",
                    "message",
                    "event.original",
                ],
                "lenient": True,
            }
        })

    attack_type = str(attack_type or "").strip()
    if attack_type:
        filters.append({
            "bool": {
                "should": [
                    {"wildcard": {"ml.detected_class.keyword": {"value": f"*{attack_type}*", "case_insensitive": True}}},
                    {"match_phrase": {"ml.detected_class": attack_type}},
                ],
                "minimum_should_match": 1,
            }
        })

    risk = str(risk or "").strip()
    if risk:
        filters.append({
            "bool": {
                "should": [
                    {"term": {"final_risk.keyword": risk}},
                    {"term": {"final_risk": risk}},
                ],
                "minimum_should_match": 1,
            }
        })

    source_ip = str(source_ip or "").strip()
    if source_ip:
        filters.append({"bool": {"should": [
            {"term": {"source.ip": source_ip}},
            {"match_phrase": {"event.original": source_ip}},
            {"match_phrase": {"message": source_ip}},
        ], "minimum_should_match": 1}})
    destination_ip = str(destination_ip or "").strip()
    if destination_ip:
        filters.append({"bool": {"should": [
            {"term": {"destination.ip": destination_ip}},
            {"match_phrase": {"event.original": destination_ip}},
            {"match_phrase": {"message": destination_ip}},
        ], "minimum_should_match": 1}})

    bool_query: Dict[str, Any] = {}
    if must:
        bool_query["must"] = must
    if filters:
        bool_query["filter"] = filters
    if must_not:
        bool_query["must_not"] = must_not
    return {"bool": bool_query} if bool_query else {"match_all": {}}


def _security_hit_to_row(hit: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    src = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
    timestamp_value = _read_elastic_value(src, "@timestamp", "-")
    document_id = hit.get("_id", f"event-{index}")
    row = {
        "id": f"{document_id}-{timestamp_value}-{index}",
        "_id": document_id,
        "_index": hit.get("_index", ""),
        "timestamp": timestamp_value,
        "source_ip": _read_elastic_value(src, "source.ip", "-"),
        "destination_ip": _read_elastic_value(src, "destination.ip", "-"),
        "alert_signature": _read_elastic_value(src, "suricata.eve.alert.signature", ""),
        "rule": _read_elastic_value(src, "suricata.eve.alert.signature", "-") or "-",
        "event_type": _read_elastic_value(src, "suricata.eve.event_type", "alert"),
        "ml_detected_class": _read_elastic_value(src, "ml.detected_class", ""),
        "ml_confidence_percent": _read_elastic_value(src, "ml.confidence_percent", ""),
        "ml_risk_level": _read_elastic_value(src, "ml.risk_level", ""),
        "final_risk": _read_elastic_value(src, "final_risk", ""),
        # Keep the page payload compact: only the fields required by the live
        # attack table and its detail panel are returned.
        "raw": src,
    }
    return decorate(row)


def _elastic_post_json(target: Dict[str, Any], url: str, body: Optional[Dict[str, Any]] = None, timeout: int = 20) -> Dict[str, Any]:
    try:
        response = requests.post(
            url,
            headers=elastic_headers(target),
            auth=elastic_auth(target),
            json=body,
            verify=_elastic_verify_ssl(target),
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else {}
    except requests.exceptions.ConnectTimeout:
        raise HTTPException(status_code=504, detail=f"Elastic 연결 시간 초과: {_elastic_url(target)}")
    except requests.exceptions.ReadTimeout:
        raise HTTPException(status_code=504, detail=f"Elastic 응답 시간 초과: {_elastic_url(target)}")
    except requests.exceptions.ConnectionError as exc:
        raise HTTPException(status_code=502, detail=f"Elastic 연결 실패: {exc}")
    except requests.exceptions.RequestException as exc:
        detail = ""
        try:
            detail = response.text
        except Exception:
            detail = str(exc)
        raise HTTPException(status_code=500, detail=f"Elastic 요청 실패: {exc} / {detail}")


@app.get("/api/firewalls/{firewall_id}/security-alerts/page")
def get_security_alert_page(
    firewall_id: int,
    minutes: int = 60,
    size: int = 100,
    query: str = "",
    attack_type: str = "",
    risk: str = "",
    source: str = "",
    destination: str = "",
    result: str = "attack",
    cursor: str = "",
    include_histogram: bool = True,
    from_ms: Optional[int] = None,
    to_ms: Optional[int] = None,
):
    """Efficient Elasticsearch-backed log view.

    The selected range (for example 7 days) always applies to the complete
    Elasticsearch result set.  Only one 100-row page is transferred to the
    browser, while ``hits.total`` and the date histogram are calculated across
    the entire filtered range.  ``next_cursor`` walks the same 7-day result set
    backwards without loading it all into React memory.
    """
    target = get_firewall_or_404(firewall_id)
    ensure_elastic_config(target)
    page_size = max(20, min(int(size or 100), 250))
    log_index = str(target.get("log_index") or "logs-suricata.eve-*").strip()
    decoded = _decode_page_cursor(cursor)
    pit_id = str(decoded.get("pit") or "")
    search_after = decoded.get("sort") if isinstance(decoded.get("sort"), list) else None

    if not pit_id:
        safe_index = quote(log_index, safe="*,-_.")
        pit_payload = _elastic_post_json(
            target,
            f"{_elastic_url(target)}/{safe_index}/_pit?keep_alive=10m",
            body=None,
            timeout=10,
        )
        pit_id = str(pit_payload.get("id") or "")
        if not pit_id:
            raise HTTPException(status_code=502, detail="Elasticsearch PIT 생성에 실패했습니다.")

    base_query = _security_event_query(
        minutes=minutes,
        query_text=query,
        attack_type=attack_type,
        risk=risk,
        source_ip=source,
        destination_ip=destination,
        result=result,
        from_ms=from_ms,
        to_ms=to_ms,
    )
    body: Dict[str, Any] = {
        "size": page_size,
        "track_total_hits": True,
        "pit": {"id": pit_id, "keep_alive": "10m"},
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
            {"_shard_doc": "desc"},
        ],
        "_source": [
            "@timestamp",
            "type",
            "source.ip",
            "destination.ip",
            "suricata.eve.event_type",
            "suricata.eve.alert.signature",
            "ml.detected_class",
            "ml.confidence_percent",
            "ml.risk_level",
            "final_risk",
            # Legacy fallbacks remain cheap and keep old indexed rows readable.
            "main_result_display",
            "ml_prediction",
            "ml_confidence",
        ],
        "query": base_query,
    }
    if search_after:
        body["search_after"] = search_after
    if include_histogram:
        body["aggs"] = {
            "timeline": {
                "auto_date_histogram": {
                    "field": "@timestamp",
                    "buckets": 30,
                    "minimum_interval": "minute",
                }
            }
        }

    payload = _elastic_post_json(target, f"{_elastic_url(target)}/_search", body=body, timeout=25)
    current_pit = str(payload.get("pit_id") or pit_id)
    hits_block = payload.get("hits") if isinstance(payload.get("hits"), dict) else {}
    hits = hits_block.get("hits") if isinstance(hits_block.get("hits"), list) else []
    total_value = hits_block.get("total", 0)
    total = int(total_value.get("value", 0) if isinstance(total_value, dict) else total_value or 0)
    rows = [_security_hit_to_row(hit, index) for index, hit in enumerate(hits)]

    next_cursor = ""
    if len(hits) >= page_size and hits and isinstance(hits[-1].get("sort"), list):
        next_cursor = _encode_page_cursor({"pit": current_pit, "sort": hits[-1]["sort"]})

    histogram = None
    if include_histogram:
        timeline = payload.get("aggregations", {}).get("timeline", {})
        buckets = timeline.get("buckets") if isinstance(timeline.get("buckets"), list) else []
        interval = str(timeline.get("interval") or "")
        histogram = {
            "interval": interval,
            "buckets": [
                {"start": int(bucket.get("key", 0)), "count": int(bucket.get("doc_count", 0))}
                for bucket in buckets
            ],
        }

    return {
        "rows": rows,
        "total": total,
        "page_size": page_size,
        "page_count": len(rows),
        "next_cursor": next_cursor,
        "has_more": bool(next_cursor),
        "histogram": histogram,
        "source": "ELK",
        "range_minutes": max(1, min(int(minutes or 60), 5256000)),
    }


def _archive_event_query(
    minutes: int = 60,
    query_text: str = "",
    action: str = "",
    interface: str = "",
    protocol: str = "",
    source_ip: str = "",
    destination_ip: str = "",
    from_ms: Optional[int] = None,
    to_ms: Optional[int] = None,
) -> Dict[str, Any]:
    filters: List[Dict[str, Any]] = []
    must: List[Dict[str, Any]] = []
    if from_ms is not None or to_ms is not None:
        bounds: Dict[str, Any] = {"format": "epoch_millis"}
        if from_ms is not None:
            bounds["gte"] = int(from_ms)
        if to_ms is not None:
            bounds["lt"] = int(to_ms)
        filters.append({"range": {"@timestamp": bounds}})
    else:
        safe_minutes = max(1, min(int(minutes or 60), 5256000))
        if safe_minutes < 5256000:
            filters.append({"range": {"@timestamp": {"gte": f"now-{safe_minutes}m", "lte": "now"}}})

    query_text = str(query_text or "").strip()
    if query_text:
        must.append({"multi_match": {"query": query_text, "fields": [
            "source.ip^2", "destination.ip^2", "source.port", "destination.port",
            "network.transport", "network.protocol", "network.direction",
            "suricata.eve.event_type", "suricata.eve.in_iface",
            "suricata.eve.alert.signature^3", "suricata.eve.alert.category",
            "event.action^3", "event.type", "event.category", "event.dataset",
            "opnsense.firewall.action^3", "opnsense.firewall.interface", "opnsense.firewall.reason",
            "rule.id", "rule.name",
            "message^2", "event.original^2", "host.name", "type"
        ], "lenient": True}})

    action = str(action or "").strip()
    if action:
        filters.append({"bool": {"should": [
            {"term": {"event.action.keyword": action.lower()}},
            {"term": {"event.action": action.lower()}},
            {"term": {"opnsense.firewall.action.keyword": action.lower()}},
            {"term": {"opnsense.firewall.action": action.lower()}},
            {"match_phrase": {"event.original": action}},
            {"match_phrase": {"message": action}}
        ], "minimum_should_match": 1}})

    interface = str(interface or "").strip()
    if interface:
        filters.append({"bool": {"should": [
            {"term": {"opnsense.firewall.interface.keyword": interface}},
            {"term": {"opnsense.firewall.interface": interface}},
            {"term": {"suricata.eve.in_iface.keyword": interface}},
            {"term": {"observer.ingress.interface.name.keyword": interface}},
            {"term": {"observer.egress.interface.name.keyword": interface}},
            {"match_phrase": {"event.original": interface}},
            {"match_phrase": {"message": interface}}
        ], "minimum_should_match": 1}})

    protocol = str(protocol or "").strip()
    if protocol:
        filters.append({"bool": {"should": [
            {"term": {"opnsense.firewall.protocol.keyword": protocol.lower()}},
            {"term": {"opnsense.firewall.protocol": protocol.lower()}},
            {"term": {"network.transport.keyword": protocol.lower()}},
            {"term": {"network.transport": protocol.lower()}},
            {"term": {"network.protocol.keyword": protocol.lower()}},
            {"term": {"suricata.eve.proto.keyword": protocol.upper()}},
            {"match_phrase": {"event.original": protocol}}
        ], "minimum_should_match": 1}})

    source_ip = str(source_ip or "").strip()
    if source_ip:
        filters.append({"bool": {"should": [
            {"term": {"source.ip": source_ip}},
            {"match_phrase": {"event.original": source_ip}},
            {"match_phrase": {"message": source_ip}},
        ], "minimum_should_match": 1}})
    destination_ip = str(destination_ip or "").strip()
    if destination_ip:
        filters.append({"bool": {"should": [
            {"term": {"destination.ip": destination_ip}},
            {"match_phrase": {"event.original": destination_ip}},
            {"match_phrase": {"message": destination_ip}},
        ], "minimum_should_match": 1}})

    bool_query: Dict[str, Any] = {}
    if must:
        bool_query["must"] = must
    if filters:
        bool_query["filter"] = filters
    return {"bool": bool_query} if bool_query else {"match_all": {}}


def _archive_event_hit_to_row(hit: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    """Normalize an Elasticsearch-backed OPNsense firewall/filterlog event.

    The archive page is intentionally firewall-centric.  Suricata/ML fields are
    not promoted into the table because they describe IDS analysis rather than
    the pf firewall decision (pass/block).
    """
    src = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
    message_value = _read_elastic_value(src, "message", "") or _read_elastic_value(src, "event.original", "") or ""
    event_original = _read_elastic_value(src, "event.original", message_value)
    opnsense_parsed = parse_opnsense_filterlog_message(event_original or message_value)

    action_value = (
        _read_elastic_value(src, "event.action", "")
        or _read_elastic_value(src, "opnsense.firewall.action", "")
        or _read_elastic_value(src, "action", "")
        or opnsense_parsed.get("action")
        or "-"
    )
    action_value = str(action_value).lower() if action_value not in (None, "") else "-"
    interface_value = (
        _read_elastic_value(src, "opnsense.firewall.interface", "")
        or _read_elastic_value(src, "observer.ingress.interface.name", "")
        or _read_elastic_value(src, "observer.egress.interface.name", "")
        or _read_elastic_value(src, "interface.name", "")
        or opnsense_parsed.get("interface")
        or "-"
    )
    direction_value = (
        _read_elastic_value(src, "network.direction", "")
        or _read_elastic_value(src, "opnsense.firewall.direction", "")
        or opnsense_parsed.get("direction")
        or "-"
    )
    protocol_value = (
        _read_elastic_value(src, "network.transport", "")
        or _read_elastic_value(src, "network.protocol", "")
        or _read_elastic_value(src, "opnsense.firewall.protocol", "")
        or opnsense_parsed.get("protocol")
        or "-"
    )
    rule_id = (
        _read_elastic_value(src, "rule.id", "")
        or _read_elastic_value(src, "opnsense.firewall.rule_id", "")
        or opnsense_parsed.get("tracker")
        or ""
    )
    rule_value = (
        _read_elastic_value(src, "rule.name", "")
        or _read_elastic_value(src, "rule.description", "")
        or _read_elastic_value(src, "opnsense.firewall.rule", "")
        or opnsense_parsed.get("rule")
        or (f"filterlog rule {rule_id}" if rule_id else "-")
    )
    timestamp_value = _read_elastic_value(src, "@timestamp", "-")
    document_id = hit.get("_id", f"event-{index}")
    source_ip = _read_elastic_value(src, "source.ip", opnsense_parsed.get("source_ip", "-"))
    source_port = _read_elastic_value(src, "source.port", opnsense_parsed.get("source_port", ""))
    destination_ip = _read_elastic_value(src, "destination.ip", opnsense_parsed.get("destination_ip", "-"))
    destination_port = _read_elastic_value(src, "destination.port", opnsense_parsed.get("destination_port", ""))
    reason = _read_elastic_value(src, "opnsense.firewall.reason", opnsense_parsed.get("reason", "-"))
    tracker = _read_elastic_value(src, "opnsense.firewall.tracker", opnsense_parsed.get("tracker", "-"))

    return {
        "id": f"{document_id}-{timestamp_value}-{index}",
        "_id": document_id,
        "_index": hit.get("_index", ""),
        "timestamp": timestamp_value,
        "event_type": "filterlog",
        "action": action_value,
        "interface": interface_value,
        "direction": direction_value,
        "protocol": str(protocol_value).lower() if protocol_value not in (None, "") else "-",
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "rule": rule_value,
        "rule_id": rule_id,
        "reason": reason,
        "tracker": tracker,
        "severity": "-",
        "category": "OPNsense firewall",
        "host": _read_elastic_value(src, "host.name", opnsense_parsed.get("host", "-")),
        "message": message_value or event_original,
        "raw": src,
    }


def search_firewall_archive_events(
    target: Dict[str, Any],
    log_index: str,
    size: int = 300,
    minutes: int = 1440,
    action: str = "",
    interface: str = "",
    protocol: str = "",
    source_ip: str = "",
    destination_ip: str = "",
    query_text: str = "",
) -> List[Dict[str, Any]]:
    """Small non-cursor query used by the index/SQL helper pages."""
    safe_index = quote(log_index, safe="*,-_.")
    body: Dict[str, Any] = {
        "size": max(1, min(int(size or 300), 1000)),
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "_source": [
            "@timestamp", "type", "message", "event.*", "host.*", "source.*",
            "destination.*", "network.*", "observer.*", "rule.*", "opnsense.*", "interface.*"
        ],
        "query": _archive_event_query(
            minutes=minutes, query_text=query_text, action=action, interface=interface,
            protocol=protocol, source_ip=source_ip, destination_ip=destination_ip,
        ),
    }
    payload = _elastic_post_json(target, f"{_elastic_url(target)}/{safe_index}/_search", body=body, timeout=20)
    hits = payload.get("hits", {}).get("hits", []) if isinstance(payload.get("hits"), dict) else []
    return [_archive_event_hit_to_row(hit, index) for index, hit in enumerate(hits)]


@app.get("/api/firewalls/{firewall_id}/event-logs/page")
def get_event_log_archive_page(
    firewall_id: int, minutes: int = 60, size: int = 100, query: str = "",
    action: str = "", interface: str = "", protocol: str = "", source: str = "",
    destination: str = "", cursor: str = "", include_histogram: bool = True,
    from_ms: Optional[int] = None, to_ms: Optional[int] = None,
):
    """Long-term firewall-event view backed only by Elasticsearch."""
    target = get_firewall_or_404(firewall_id)
    ensure_elastic_config(target)
    page_size = max(20, min(int(size or 100), 250))
    log_index = str(target.get("event_log_index") or "").strip()
    if not log_index:
        raise HTTPException(
            status_code=409,
            detail="방화벽 이벤트 인덱스가 설정되지 않았습니다. 방화벽 관리에서 OPNsense filterlog 전용 인덱스(예: opnsense-firewall-*)를 설정하세요.",
        )
    decoded = _decode_page_cursor(cursor)
    pit_id = str(decoded.get("pit") or "")
    search_after = decoded.get("sort") if isinstance(decoded.get("sort"), list) else None
    if not pit_id:
        safe_index = quote(log_index, safe="*,-_.")
        pit_payload = _elastic_post_json(target, f"{_elastic_url(target)}/{safe_index}/_pit?keep_alive=10m", body=None, timeout=10)
        pit_id = str(pit_payload.get("id") or "")
        if not pit_id:
            raise HTTPException(status_code=502, detail="Elasticsearch PIT 생성에 실패했습니다.")

    body: Dict[str, Any] = {
        "size": page_size, "track_total_hits": True,
        "pit": {"id": pit_id, "keep_alive": "10m"},
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}, {"_shard_doc": "desc"}],
        "_source": ["@timestamp", "type", "message", "event.*", "host.*", "source.*", "destination.*", "network.*", "observer.*", "rule.*", "opnsense.*", "interface.*"],
        "query": _archive_event_query(minutes, query, action, interface, protocol, source, destination, from_ms, to_ms),
    }
    if search_after:
        body["search_after"] = search_after
    if include_histogram:
        body["aggs"] = {"timeline": {"auto_date_histogram": {"field": "@timestamp", "buckets": 30, "minimum_interval": "minute"}}}

    payload = _elastic_post_json(target, f"{_elastic_url(target)}/_search", body=body, timeout=25)
    current_pit = str(payload.get("pit_id") or pit_id)
    hits_block = payload.get("hits") if isinstance(payload.get("hits"), dict) else {}
    hits = hits_block.get("hits") if isinstance(hits_block.get("hits"), list) else []
    total_value = hits_block.get("total", 0)
    total = int(total_value.get("value", 0) if isinstance(total_value, dict) else total_value or 0)
    rows = [_archive_event_hit_to_row(hit, index) for index, hit in enumerate(hits)]
    next_cursor = ""
    if len(hits) >= page_size and hits and isinstance(hits[-1].get("sort"), list):
        next_cursor = _encode_page_cursor({"pit": current_pit, "sort": hits[-1]["sort"]})
    histogram = None
    if include_histogram:
        timeline = payload.get("aggregations", {}).get("timeline", {})
        buckets = timeline.get("buckets") if isinstance(timeline.get("buckets"), list) else []
        histogram = {"interval": str(timeline.get("interval") or ""), "buckets": [{"start": int(bucket.get("key", 0)), "count": int(bucket.get("doc_count", 0))} for bucket in buckets]}
    firewall_actions = {"pass", "block", "deny", "drop", "reject", "allow", "accept"}
    has_firewall_action = any(str(row.get("action") or "").lower() in firewall_actions for row in rows)
    schema_warning = ""
    if total > 0 and rows and not has_firewall_action:
        schema_warning = (
            f"현재 이벤트 인덱스({log_index})에 OPNsense firewall action(pass/block) 정보가 없습니다. "
            "Suricata 공격 인덱스가 아니라 OPNsense filterlog 전용 인덱스를 연결하세요."
        )
    return {"rows": rows, "total": total, "page_size": page_size, "page_count": len(rows), "next_cursor": next_cursor,
            "has_more": bool(next_cursor), "histogram": histogram, "source": "ELK", "view": "firewall_event_archive",
            "index": log_index, "schema_warning": schema_warning,
            "range_minutes": max(1, min(int(minutes or 60), 5256000))}

@app.get("/api/firewalls/{firewall_id}/security-alerts")
def get_security_alerts(
    firewall_id: int,
    minutes: int = 60,
    size: int = 500,
    query: str = "",
    include_all_events: bool = False,
    before: str = "",
):
    """Return one ELK page. ``size`` is a per-page limit, not a total history limit.

    Pass ``before`` with the ``next_before`` value from the previous response to
    keep walking backwards through the selected time range. Pages intentionally
    overlap at the boundary timestamp; clients should de-duplicate by row id.
    This avoids the old behaviour where an attack disappeared permanently once
    more than 1,000 newer raw events arrived.
    """
    target = get_firewall_or_404(firewall_id)
    page_size = max(1, min(size, 1000))
    page_rows = search_firewall_events(
        target=target,
        log_index=target.get("log_index", "logs-suricata.eve-*"),
        size=page_size,
        minutes=max(1, min(minutes, 5256000)),
        query_text=query,
        before_timestamp=before,
    )
    decorated = list({r["id"]: r for r in map(decorate, page_rows)}.values())
    scanned = len(decorated)
    rows = decorated if include_all_events else [row for row in decorated if is_attack(row)]

    next_before = ""
    if page_rows:
        next_before = str(page_rows[-1].get("timestamp") or "")

    return {
        "rows": rows,
        "scanned": scanned,
        "source": "ELK",
        "firewall": serialize_firewall(target),
        "page_size": page_size,
        "next_before": next_before,
        "has_more": bool(next_before and len(page_rows) >= page_size),
    }


@app.post("/api/firewalls/{firewall_id}/security-alerts/{alert_id}/block")
def manual_block(firewall_id: int, alert_id: str, body: ManualBlockBody, request: Request):
    target = get_firewall_or_404(firewall_id)
    try:
        service = _manual_service(target)
        protected = _protected_manual_addresses()
        # Include globally configured ELK when this target inherits it.
        effective_target = {**target, "elastic_url": _elastic_url(target)}
        service.target = effective_target
        ip = service.validate_address(body.source_ip, body.force, protected,
                                      request.client.host if request.client else None)
    except (ResponseError, ValueError, OSError) as exc:
        raise HTTPException(400, getattr(exc, "detail", str(exc)))
    try:
        with MANUAL_BLOCK_LOCK:
            result = service.change(ip, True)
            record = _manual_audit(firewall_id, ip, "block", service, result, alert_id)
        return {**record, "message": f"{ip} 차단 규칙과 Alias 테이블 적용을 확인했습니다."}
    except ResponseError as exc:
        raise HTTPException(502, exc.detail)


# ============================================================
# V32-FINAL ML -> Elasticsearch enrichment pipeline
# ============================================================
_ML_PIPELINE_STATE_LOCK = threading.Lock()
_ML_PIPELINE_STATE: Dict[str, Any] = {
    "running": False,
    "thread_alive": False,
    "started_at": None,
    "last_cycle_at": None,
    "last_error": "",
    "firewalls": {},
}
_ML_PIPELINE_STOP = threading.Event()
_ML_PIPELINE_THREAD: Optional[threading.Thread] = None


def _ml_state_snapshot() -> Dict[str, Any]:
    with _ML_PIPELINE_STATE_LOCK:
        return json.loads(json.dumps(_ML_PIPELINE_STATE, ensure_ascii=False, default=str))


def _ml_update_state(**kwargs) -> None:
    with _ML_PIPELINE_STATE_LOCK:
        _ML_PIPELINE_STATE.update(kwargs)


def _ml_update_firewall_state(firewall_id: int, payload: Dict[str, Any]) -> None:
    with _ML_PIPELINE_STATE_LOCK:
        fw_state = _ML_PIPELINE_STATE.setdefault("firewalls", {})
        fw_state[str(firewall_id)] = payload


def _run_ml_pipeline_for_target(
    target: Dict[str, Any],
    *,
    batch_size: int,
    lookback_minutes: int,
    force: bool = False,
) -> Dict[str, Any]:
    ensure_elastic_config(target)
    config = ml_pipeline_config()
    result = run_pipeline_batch(
        target=target,
        base_url=_elastic_url(target),
        log_index=str(target.get("log_index") or "logs-suricata.eve-*"),
        headers=elastic_headers(target),
        auth=elastic_auth(target),
        verify_ssl=_elastic_verify_ssl(target),
        batch_size=max(1, min(int(batch_size), 500)),
        lookback_minutes=max(1, min(int(lookback_minutes), 5256000)),
        force=bool(force),
        mark_skipped=bool(config.get("mark_skipped", True)),
    )
    result["completed_at"] = int(time.time())
    _ml_update_firewall_state(int(target.get("id", 0)), result)
    return result


def _ml_pipeline_worker() -> None:
    config = ml_pipeline_config()
    _ml_update_state(
        running=True,
        thread_alive=True,
        started_at=int(time.time()),
        last_error="",
    )
    try:
        while not _ML_PIPELINE_STOP.is_set():
            config = ml_pipeline_config()
            if not config.get("enabled", True):
                _ML_PIPELINE_STOP.wait(max(1, int(config.get("interval_seconds", 5))))
                continue

            for target in load_firewalls():
                if _ML_PIPELINE_STOP.is_set():
                    break
                try:
                    if not _elastic_url(target):
                        continue
                    _run_ml_pipeline_for_target(
                        target,
                        batch_size=int(config.get("batch_size", 100)),
                        lookback_minutes=int(config.get("lookback_minutes", 180)),
                        force=False,
                    )
                except Exception as exc:
                    error_text = f"{type(exc).__name__}: {exc}"
                    _ml_update_firewall_state(
                        int(target.get("id", 0)),
                        {
                            "firewall_id": target.get("id"),
                            "firewall_name": target.get("name"),
                            "error": error_text,
                            "completed_at": int(time.time()),
                        },
                    )
                    _ml_update_state(last_error=error_text)

            _ml_update_state(last_cycle_at=int(time.time()))
            _ML_PIPELINE_STOP.wait(max(1, int(config.get("interval_seconds", 5))))
    finally:
        _ml_update_state(running=False, thread_alive=False)


@app.on_event("startup")
def start_ml_pipeline_worker():
    global _ML_PIPELINE_THREAD
    config = ml_pipeline_config()
    if not config.get("enabled", True):
        _ml_update_state(running=False, thread_alive=False)
        return
    if _ML_PIPELINE_THREAD is not None and _ML_PIPELINE_THREAD.is_alive():
        return

    status = ml_model_status(load_model=True)
    if not status.get("ready"):
        _ml_update_state(
            running=False,
            thread_alive=False,
            last_error=status.get("load_error") or "V32 model not ready",
        )
        return

    _ML_PIPELINE_STOP.clear()
    _ML_PIPELINE_THREAD = threading.Thread(
        target=_ml_pipeline_worker,
        name="v32-elk-ml-pipeline",
        daemon=True,
    )
    _ML_PIPELINE_THREAD.start()


@app.on_event("shutdown")
def stop_ml_pipeline_worker():
    _ML_PIPELINE_STOP.set()


@app.get("/api/ml/model-status")
def get_ml_model_status():
    return {
        "model": ml_model_status(load_model=True),
        "pipeline": ml_pipeline_config(),
        "worker": _ml_state_snapshot(),
    }


@app.post("/api/ml/predict")
def predict_ml_payload(body: MlPredictBody):
    row: Dict[str, Any] = {"raw": {"payload": body.payload}}
    if body.flow:
        row["raw"]["flow"] = body.flow
    result = ml_predict_event(row)
    if not result.get("available"):
        raise HTTPException(status_code=422, detail=result)
    return result


@app.get("/api/firewalls/{firewall_id}/ml-pipeline/status")
def get_firewall_ml_pipeline_status(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    state = _ml_state_snapshot()
    return {
        "firewall": serialize_firewall(target),
        "model": ml_model_status(load_model=False),
        "config": ml_pipeline_config(),
        "worker": {
            "running": state.get("running", False),
            "thread_alive": state.get("thread_alive", False),
            "last_cycle_at": state.get("last_cycle_at"),
            "last_error": state.get("last_error", ""),
        },
        "last_result": state.get("firewalls", {}).get(str(firewall_id), {}),
    }


@app.get("/api/firewalls/{firewall_id}/ml-pipeline/diagnostics")
def get_firewall_ml_pipeline_diagnostics(firewall_id: int, lookback_minutes: int = 180):
    target = get_firewall_or_404(firewall_id)
    ensure_elastic_config(target)
    try:
        return pipeline_diagnostics(
            base_url=_elastic_url(target),
            log_index=str(target.get("log_index") or "logs-suricata.eve-*"),
            headers=elastic_headers(target),
            auth=elastic_auth(target),
            verify_ssl=_elastic_verify_ssl(target),
            lookback_minutes=max(1, min(int(lookback_minutes), 5256000)),
        )
    except requests.exceptions.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"ML pipeline 진단 실패: {exc}")


@app.post("/api/firewalls/{firewall_id}/ml-pipeline/run")
def run_firewall_ml_pipeline(firewall_id: int, body: MlPipelineRunBody):
    target = get_firewall_or_404(firewall_id)
    try:
        return _run_ml_pipeline_for_target(
            target,
            batch_size=body.batch_size,
            lookback_minutes=body.lookback_minutes,
            force=body.force,
        )
    except requests.exceptions.ConnectTimeout:
        raise HTTPException(status_code=504, detail=f"Elastic ML pipeline 연결 시간 초과: {_elastic_url(target)}")
    except requests.exceptions.ReadTimeout:
        raise HTTPException(status_code=504, detail=f"Elastic ML pipeline 응답 시간 초과: {_elastic_url(target)}")
    except requests.exceptions.RequestException as exc:
        response_text = ""
        try:
            response_text = exc.response.text[:1000] if exc.response is not None else ""
        except Exception:
            pass
        raise HTTPException(status_code=502, detail=f"Elastic ML pipeline 요청 실패: {exc} {response_text}".strip())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"ML pipeline 실행 실패: {type(exc).__name__}: {exc}")


# Attack research uses exactly the same detection page API/index/filter as Live.
class AttackSearchBody(BaseModel):
    minutes: int = Field(default=60, ge=1, le=10080)
    result: str = 'attack'
    query: str = ''
    sql: str = Field(default='SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100', max_length=10000)


@app.post('/api/firewalls/{firewall_id}/security-alerts/search')
def search_attack_logs(firewall_id: int, body: AttackSearchBody):
    import sqlite3
    try:
        from .attack_search import search_rows
    except ImportError:
        from attack_search import search_rows
    if body.result not in {'attack', 'all', 'normal'}:
        raise HTTPException(400, '결과 필터가 올바르지 않습니다.')
    rows, cursor, total, more = [], '', 0, False
    # Fixed time bounds keep all fetched pages in the same search interval.
    until = int(time.time() * 1000)
    for _ in range(20):
        page = get_security_alert_page(firewall_id=firewall_id, minutes=body.minutes,
            size=250, query=body.query, result=body.result, cursor=cursor,
            include_histogram=False, from_ms=until-body.minutes*60000, to_ms=until)
        rows.extend(page.get('rows', []))
        total = page.get('total', 0)
        more = bool(page.get('has_more'))
        cursor = page.get('next_cursor', '')
        if not more or not cursor: break
    try:
        result = search_rows(rows, body.sql)
    except (sqlite3.Error, ValueError) as exc:
        raise HTTPException(400, f'SQL 검색 오류: {exc}')
    return {**result, 'scanned': len(rows), 'total': total, 'source_truncated': more,
            'source': 'ELK', 'minutes': body.minutes, 'index': get_firewall_or_404(firewall_id).get('log_index', '')}


@app.get('/api/firewalls/{firewall_id}/automatic-blocks')
def list_automatic_blocks(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    alias = os.getenv(f'SECURITY_AUTO_BLOCK_ALIAS_{firewall_id}', os.getenv('SECURITY_AUTO_BLOCK_ALIAS', '')).strip()
    manual_alias = os.getenv('SECURITY_BLOCK_ALIAS', 'blocked_attackers').strip() or 'blocked_attackers'
    if not alias:
        return {'rows': [], 'available': False, 'message': '자동 차단 전용 Alias가 연결되지 않았습니다. 자동 차단 엔진에서 사용하는 Alias를 설정하세요.'}
    if alias == manual_alias:
        raise HTTPException(400, '수동·자동 차단 Alias가 같으면 차단 유형을 구분할 수 없습니다. 자동 전용 Alias를 지정하세요.')
    try:
        with MANUAL_BLOCK_LOCK:
            service = ManualResponse(opnsense_request, target, alias)
            _, config = service.alias_config()
            if not config:
                return {'rows': [], 'alias': alias, 'available': False, 'message': '설정한 자동 차단 Alias가 OPNsense에 없습니다.'}
            entries = service.table()
            editable = config.get('type') == 'host' and config.get('enabled') == '1'
            configured = set()
            for entry in contents(config.get('content', '')):
                try: configured.add(str(ipaddress.ip_address(entry)))
                except ValueError: editable = False
            rows = []
            for entry in sorted(entries):
                network = ipaddress.ip_network(entry)
                ip = str(network.network_address) if network.prefixlen == network.max_prefixlen else entry
                rows.append({'ip': ip, 'alias': alias, 'status': 'table_present',
                             'can_remove': editable and ip in configured})
            return {'rows': rows, 'alias': alias, 'available': True, 'editable': editable,
                    'message': '자동 차단 전용 Alias의 실제 테이블입니다. 자동화 규칙 적용 여부와 차단 시각은 이 API에서 검증하지 않습니다.'}
    except ResponseError as exc:
        raise HTTPException(502, exc.detail)



def _automatic_edit_service(firewall_id):
    target = get_firewall_or_404(firewall_id)
    alias = os.getenv(f'SECURITY_AUTO_BLOCK_ALIAS_{firewall_id}', os.getenv('SECURITY_AUTO_BLOCK_ALIAS', '')).strip()
    manual = os.getenv('SECURITY_BLOCK_ALIAS', 'blocked_attackers').strip() or 'blocked_attackers'
    if not alias or alias == manual:
        raise HTTPException(400, '별도의 자동 차단 Alias를 먼저 연결하세요.')
    service = ManualResponse(opnsense_request, {**target, 'elastic_url': _elastic_url(target)}, alias)
    _, config = service.alias_config()
    if not config:
        raise HTTPException(409, '연결된 자동 차단 Alias가 없습니다.')
    if config.get('type') != 'host' or config.get('enabled') != '1':
        raise HTTPException(409, '직접 추가·해제는 활성화된 Host 유형 Alias에서 지원합니다.')
    return service


@app.post('/api/firewalls/{firewall_id}/automatic-blocks')
def add_automatic_block(firewall_id: int, body: ManualBlockBody, request: Request):
    try:
        with MANUAL_BLOCK_LOCK:
            service = _automatic_edit_service(firewall_id)
            try:
                ip = service.validate_address(body.source_ip, body.force, _protected_manual_addresses(),
                    request.client.host if request.client else None)
            except (ResponseError, ValueError, OSError) as exc:
                raise HTTPException(400, getattr(exc, 'detail', str(exc)))
            result = service.change(ip, True)
        return {**result, 'ip': ip, 'alias': service.alias,
                'message': f'{ip}를 자동 차단 Alias에 추가하고 차단 규칙 적용을 확인했습니다.'}
    except ResponseError as exc:
        raise HTTPException(502, exc.detail)


@app.delete('/api/firewalls/{firewall_id}/automatic-blocks/{ip_address}')
def remove_automatic_block(firewall_id: int, ip_address: str):
    try:
        ip = str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        raise HTTPException(400, '해제할 단일 IP 주소가 올바르지 않습니다.')
    try:
        with MANUAL_BLOCK_LOCK:
            service = _automatic_edit_service(firewall_id)
            result = service.change(ip, False)
        return {**result, 'ip': ip, 'alias': service.alias,
                'message': f'{ip}를 자동 차단 Alias에서 해제했습니다.',
                'engine_notice': '자동 차단 엔진이 다시 탐지하면 재등록할 수 있습니다.'}
    except ResponseError as exc:
        raise HTTPException(502, exc.detail)
