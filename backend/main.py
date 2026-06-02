import json
import os
import re
import html
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urljoin

import requests
import urllib3
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    query: str = ""


class OpnsenseLogFilter(BaseModel):
    search: Optional[str] = ""
    field: Optional[str] = "any"
    operator: Optional[str] = "contains"
    tableSize: Optional[int] = 25
    historySize: Optional[int] = 300
    resolveHostnames: Optional[bool] = False
    onlyImportant: Optional[bool] = False


class AliasAddressBody(BaseModel):
    address: str


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
            timeout=OPNSENSE_TIMEOUT,
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


def elastic_headers(target: Dict[str, Any]) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}

    api_key_enc = target.get("elastic_api_key_enc")
    api_key = ""
    if api_key_enc:
        try:
            api_key = decrypt_text(api_key_enc)
        except Exception:
            api_key = ""

    if not api_key:
        api_key = ELASTIC_API_KEY

    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    return headers


def elastic_auth(target: Dict[str, Any]):
    headers = elastic_headers(target)
    if headers.get("Authorization"):
        return None

    username = str(target.get("elastic_username") or ELASTIC_USERNAME).strip()
    password_enc = target.get("elastic_password_enc")
    password = ""

    if password_enc:
        try:
            password = decrypt_text(password_enc)
        except Exception:
            password = ""

    if not password:
        password = ELASTIC_PASSWORD

    if username and password:
        return (username, password)

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

def search_firewall_events(
    target: Dict[str, Any],
    log_index: str,
    size: int,
    minutes: int,
    action: str = "",
    interface: str = "",
    query_text: str = "",
) -> List[Dict[str, Any]]:
    ensure_elastic_config(target)

    must: List[Dict[str, Any]] = []

    if action:
        must.append({
            "bool": {
                "should": [
                    {"term": {"network.direction.keyword": action}},
                    {"term": {"suricata.eve.event_type.keyword": action}},
                    {"term": {"event.action.keyword": action}},
                ],
                "minimum_should_match": 1,
            }
        })

    if interface:
        must.append({
            "bool": {
                "should": [
                    {"term": {"suricata.eve.in_iface.keyword": interface}},
                    {"term": {"observer.ingress.interface.name.keyword": interface}},
                    {"term": {"observer.egress.interface.name.keyword": interface}},
                ],
                "minimum_should_match": 1,
            }
        })

    if query_text:
        must.append({
            "multi_match": {
                "query": query_text,
                "fields": [
                    "source.ip",
                    "destination.ip",
                    "network.transport",
                    "network.direction",
                    "suricata.eve.event_type",
                    "suricata.eve.app_proto",
                    "suricata.eve.in_iface",
                    "suricata.eve.alert.signature",
                    "suricata.eve.alert.category",
                    "event.dataset",
                    "event.original",
                    "message",
                    "host.name",
                    "host.hostname",
                ],
            }
        })

    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
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
        raise HTTPException(status_code=504, detail="Elastic 연결 시간 초과")
    except requests.exceptions.ReadTimeout:
        raise HTTPException(status_code=504, detail="Elastic 응답 시간 초과")
    except requests.exceptions.ConnectionError as e:
        raise HTTPException(status_code=502, detail=f"Elastic 연결 실패: {e}")
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Elastic 요청 실패: {e}")

    payload = resp.json()
    hits = payload.get("hits", {}).get("hits", [])

    rows: List[Dict[str, Any]] = []

    for hit in hits:
        src = hit.get("_source", {})
        message_json = parse_suricata_message(src.get("message", ""))

        event_type = (
            get_nested(src, "suricata.eve.event_type")
            or get_nested(src, "event.type")
            or message_json.get("event_type")
            or "-"
        )

        action_value = (
            get_nested(src, "network.direction")
            or get_nested(src, "event.action")
            or message_json.get("event_type")
            or event_type
            or "-"
        )

        interface_value = (
            get_nested(src, "suricata.eve.in_iface")
            or get_nested(src, "observer.ingress.interface.name")
            or get_nested(src, "observer.egress.interface.name")
            or message_json.get("in_iface")
            or "-"
        )

        protocol_value = (
            get_nested(src, "network.transport")
            or get_nested(src, "network.protocol")
            or get_nested(src, "suricata.eve.proto")
            or message_json.get("proto")
            or "-"
        )

        rule_value = (
            get_nested(src, "suricata.eve.alert.signature")
            or get_nested(src, "rule.name")
            or get_nested(message_json, "alert.signature")
            or event_type
            or "-"
        )

        severity_value = (
            get_nested(src, "suricata.eve.alert.severity")
            or get_nested(src, "event.severity")
            or get_nested(message_json, "alert.severity")
            or "-"
        )

        category_value = (
            get_nested(src, "suricata.eve.alert.category")
            or get_nested(src, "event.category")
            or get_nested(src, "event.dataset")
            or get_nested(message_json, "alert.category")
            or "-"
        )

        host_value = (
            get_nested(src, "host.name")
            or get_nested(src, "host.hostname")
            or "-"
        )

        rows.append({
            "id": hit.get("_id"),
            "timestamp": src.get("@timestamp", "-"),
            "action": action_value,
            "interface": interface_value,
            "protocol": protocol_value,
            "source_ip": get_nested(src, "source.ip", message_json.get("src_ip", "-")),
            "source_port": get_nested(src, "source.port", message_json.get("src_port", "-")),
            "destination_ip": get_nested(src, "destination.ip", message_json.get("dest_ip", "-")),
            "destination_port": get_nested(src, "destination.port", message_json.get("dest_port", "-")),
            "rule": rule_value,
            "severity": severity_value,
            "category": category_value,
            "host": host_value,
            "event_type": event_type,
            "raw": src,
            "messageJson": message_json,
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


@app.post("/api/firewalls/{firewall_id}/opnsense-logs")
def get_opnsense_firewall_logs(firewall_id: int, filters: OpnsenseLogFilter):
    target = get_firewall_or_404(firewall_id)

    # 팀 프로젝트 장비처럼 로그가 많은 환경에서 브라우저 렉을 막기 위해 서버 단에서 강제 제한한다.
    requested = filters.historySize or filters.tableSize or 100
    row_count = max(1, min(int(requested), 300))
    search_phrase = (filters.search or "").strip()

    # OPNsense API에도 검색어를 넘기되, 최종 필터는 백엔드에서 한 번 더 수행한다.
    candidate_requests = [
        {
            "method": "POST",
            "path": "/api/diagnostics/firewall/log",
            "json": {
                "current": 1,
                "rowCount": row_count,
                "searchPhrase": search_phrase,
                "sort": {},
            },
        },
        {
            "method": "POST",
            "path": "/api/diagnostics/firewall/log/",
            "json": {
                "current": 1,
                "rowCount": row_count,
                "searchPhrase": search_phrase,
                "sort": {},
            },
        },
        {
            "method": "GET",
            "path": f"/api/diagnostics/firewall/log?limit={row_count}",
            "json": None,
        },
    ]

    attempts: List[Dict[str, Any]] = []

    for request_info in candidate_requests:
        method = request_info["method"]
        path = request_info["path"]

        try:
            data = opnsense_request(
                target=target,
                method=method,
                path=path,
                json_data=request_info.get("json"),
            )

            raw_rows = _extract_log_rows_from_payload(data)

            attempts.append({
                "method": method,
                "path": path,
                "ok": True,
                "found_rows": len(raw_rows),
                "requested_limit": row_count,
                "response_type": type(data).__name__,
                "response_keys": list(data.keys()) if isinstance(data, dict) else [],
            })

            if not raw_rows:
                continue

            normalized_rows: List[Dict[str, Any]] = []
            for index, row in enumerate(raw_rows[:row_count]):
                normalized = normalize_opnsense_log_row(row, index)
                if (
                    normalized.get("interface") == "-"
                    and normalized.get("time") == "-"
                    and normalized.get("source") == "-"
                    and normalized.get("destination") == "-"
                    and normalized.get("label") == "-"
                ):
                    continue
                normalized_rows.append(normalized)

            filtered_rows = _opn_log_apply_filters(normalized_rows, filters)
            visible_limit = max(1, min(int(filters.tableSize or 25), 100))
            limited_rows = filtered_rows[:visible_limit]

            return {
                "firewall": serialize_firewall(target),
                "source": path,
                "method": method,
                "total": len(filtered_rows),
                "returned": len(limited_rows),
                "requested_limit": row_count,
                "rows": limited_rows,
                "attempts": attempts,
            }

        except HTTPException as e:
            attempts.append({
                "method": method,
                "path": path,
                "ok": False,
                "error": e.detail,
            })
            continue

        except Exception as e:
            attempts.append({
                "method": method,
                "path": path,
                "ok": False,
                "error": str(e),
            })
            continue

    return {
        "firewall": serialize_firewall(target),
        "source": None,
        "method": None,
        "total": 0,
        "returned": 0,
        "requested_limit": row_count,
        "rows": [],
        "attempts": attempts,
        "message": "OPNsense API 요청은 성공했지만 로그 row를 찾지 못했습니다. attempts를 확인하세요.",
    }

@app.post("/api/firewalls/{firewall_id}/event-logs")
def get_event_logs(firewall_id: int, body: EventLogsQueryBody):
    target = get_firewall_or_404(firewall_id)
    rows = search_firewall_events(
        target=target,
        log_index=target.get("log_index", "logs-suricata.eve-*"),
        size=max(1, min(body.size, 200)),
        minutes=max(1, min(body.minutes, 24 * 60)),
        action=body.action.strip(),
        interface=body.interface.strip(),
        query_text=body.query.strip(),
    )
    return {"rows": rows, "firewall": serialize_firewall(target), "exportColumns": KIBANA_EXPORT_COLUMNS}
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
