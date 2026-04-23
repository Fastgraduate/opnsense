
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urlparse

import requests
import urllib3
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
load_dotenv(BASE_DIR / ".env")


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


APP_ENCRYPTION_KEY = os.getenv("APP_ENCRYPTION_KEY", "").strip()
PORT = int(os.getenv("PORT", "8000"))
DEFAULT_TIMEOUT = int(os.getenv("OPNSENSE_TIMEOUT", "20"))
DEFAULT_VERIFY_SSL = parse_bool(os.getenv("OPNSENSE_VERIFY_SSL"), default=False)

if not APP_ENCRYPTION_KEY:
    raise RuntimeError("APP_ENCRYPTION_KEY 환경변수가 필요합니다.")

fernet = Fernet(APP_ENCRYPTION_KEY.encode() if not APP_ENCRYPTION_KEY.startswith("gAAAA") and len(APP_ENCRYPTION_KEY) != 44 else APP_ENCRYPTION_KEY.encode())
STORE_PATH = DATA_DIR / "firewalls.json.enc"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="OPNsense Multi-Firewall Backend")
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


class AliasAddressBody(BaseModel):
    address: str


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


class FirewallCreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=200)
    apiKey: str = Field(min_length=1, max_length=300)
    apiSecret: str = Field(min_length=1, max_length=300)
    verifySsl: bool = False
    timeout: int = Field(default=DEFAULT_TIMEOUT, ge=3, le=60)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        host = value.strip().rstrip("/")
        parsed = urlparse(host)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("host는 http(s)://host 형태여야 합니다.")
        return host


class FirewallUpdateBody(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    host: Optional[str] = Field(default=None, min_length=1, max_length=200)
    apiKey: Optional[str] = Field(default=None, min_length=1, max_length=300)
    apiSecret: Optional[str] = Field(default=None, min_length=1, max_length=300)
    verifySsl: Optional[bool] = None
    timeout: Optional[int] = Field(default=None, ge=3, le=60)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        host = value.strip().rstrip("/")
        parsed = urlparse(host)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("host는 http(s)://host 형태여야 합니다.")
        return host


def encrypt_json(data: Any) -> bytes:
    raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    return fernet.encrypt(raw)


def decrypt_json(blob: bytes) -> Any:
    try:
        raw = fernet.decrypt(blob)
        return json.loads(raw.decode("utf-8"))
    except InvalidToken as e:
        raise RuntimeError("firewalls 저장소 복호화 실패: APP_ENCRYPTION_KEY 확인 필요") from e


def load_store() -> Dict[str, Any]:
    if not STORE_PATH.exists():
        data = {"selected_firewall_id": None, "firewalls": []}
        save_store(data)
        return data

    data = decrypt_json(STORE_PATH.read_bytes())
    if not isinstance(data, dict):
        data = {"selected_firewall_id": None, "firewalls": []}
    data.setdefault("selected_firewall_id", None)
    data.setdefault("firewalls", [])
    return data


def save_store(data: Dict[str, Any]) -> None:
    STORE_PATH.write_bytes(encrypt_json(data))


def mask_secret(text: str, keep: int = 4) -> str:
    if not text:
        return ""
    if len(text) <= keep:
        return "*" * len(text)
    return "*" * (len(text) - keep) + text[-keep:]


def public_firewall(fw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": fw["id"],
        "name": fw["name"],
        "host": fw["host"],
        "verifySsl": fw.get("verifySsl", False),
        "timeout": fw.get("timeout", DEFAULT_TIMEOUT),
        "apiKeyMasked": mask_secret(fw.get("apiKey", "")),
        "apiSecretMasked": mask_secret(fw.get("apiSecret", "")),
        "createdAt": fw.get("createdAt"),
        "updatedAt": fw.get("updatedAt"),
    }


def get_firewall_or_404(firewall_id: int) -> Dict[str, Any]:
    store = load_store()
    for fw in store["firewalls"]:
        if fw["id"] == firewall_id:
            return fw
    raise HTTPException(status_code=404, detail="방화벽을 찾을 수 없습니다.")


def get_selected_firewall_or_404() -> Dict[str, Any]:
    store = load_store()
    selected_id = store.get("selected_firewall_id")
    if not selected_id:
        raise HTTPException(status_code=400, detail="선택된 방화벽이 없습니다.")
    for fw in store["firewalls"]:
        if fw["id"] == selected_id:
            return fw
    raise HTTPException(status_code=404, detail="선택된 방화벽을 찾을 수 없습니다.")


def opnsense_request_for_target(
    target: Dict[str, Any],
    method: str,
    path: str,
    json_data: Optional[Dict[str, Any]] = None,
) -> Any:
    url = f"{target['host']}{path}"
    headers: Dict[str, str] = {}
    if json_data is not None:
        headers["Content-Type"] = "application/json"

    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            auth=(target["apiKey"], target["apiSecret"]),
            json=json_data,
            verify=bool(target.get("verifySsl", False)),
            timeout=int(target.get("timeout", DEFAULT_TIMEOUT)),
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
            detail={"message": "OPNsense API 오류", "url": url, "response": data},
        )

    return data


def safe_apply_firewall(target: Dict[str, Any]) -> Dict[str, Any]:
    paths = ["/api/firewall/filter_base/apply", "/api/firewall/filter/apply"]
    for path in paths:
        try:
            return opnsense_request_for_target(target, "POST", path, json_data={})
        except Exception:
            continue
    return {"warning": "apply endpoint failed or not supported"}


def safe_block(
    target: Dict[str, Any],
    path: str,
    method: str = "GET",
    json_data: Optional[Dict[str, Any]] = None,
    default: Optional[Any] = None,
):
    try:
        return opnsense_request_for_target(target, method, path, json_data=json_data)
    except Exception as e:
        if default is None:
            default = {}
        if isinstance(default, dict):
            return {**default, "error": str(e)}
        return {"data": default, "error": str(e)}


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

    page_size = _pick_first(flat, ["v_page_size", "pagesize", "hw.pagesize", "vm.stats.vm.v_page_size"])
    page_count = _pick_first(flat, ["v_page_count", "pagecount", "vm.stats.vm.v_page_count"])
    physmem_bytes = _pick_first(flat, ["hw.physmem", "physmem", "realmem"])
    free_count = _pick_first(flat, ["v_free_count", "freecount", "vm.stats.vm.v_free_count"])
    inactive_count = _pick_first(flat, ["v_inactive_count", "inactivecount", "vm.stats.vm.v_inactive_count"])
    cache_count = _pick_first(flat, ["v_cache_count", "cachecount", "vm.stats.vm.v_cache_count"])
    laundry_count = _pick_first(flat, ["v_laundry_count", "laundrycount", "vm.stats.vm.v_laundry_count"])

    total = physmem_bytes if physmem_bytes > 0 else (page_size * page_count if page_size and page_count else 0)
    available = 0
    if page_size > 0:
        available = (free_count + inactive_count + cache_count + laundry_count) * page_size

    if total > 0:
        available = max(0, min(available, total))
        used = max(total - available, 0)
        used_percent = round((used / total) * 100, 1) if total > 0 else 0.0
        return {
            "total": int(total),
            "used": int(used),
            "free": int(available),
            "used_percent": used_percent,
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
        used_zone_bytes = size * used
        free_zone_bytes = size * free
        used_bytes += used_zone_bytes
        free_bytes += free_zone_bytes
        total_bytes += used_zone_bytes + free_zone_bytes

    used_percent = round((used_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0.0
    return {
        "total": int(total_bytes),
        "used": int(used_bytes),
        "free": int(free_bytes),
        "used_percent": used_percent,
        "source": "memory-zone-statistics-fallback",
    }


def summarize_disk(disk_raw: Any) -> Dict[str, Any]:
    devices = []
    if isinstance(disk_raw, dict):
        devices = disk_raw.get("devices", [])
    elif isinstance(disk_raw, list):
        devices = disk_raw

    if not isinstance(devices, list):
        devices = []

    root_device = None
    for device in devices:
        if isinstance(device, dict) and device.get("mountpoint") == "/":
            root_device = device
            break

    if root_device is None and len(devices) > 0:
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


@app.get("/")
def root():
    return {"ok": True, "message": "Backend is running"}


@app.get("/health")
def health():
    return {"status": "running"}


@app.get("/api/test")
def api_test():
    return {"message": "backend api works"}


@app.get("/api/firewalls")
def list_firewalls():
    store = load_store()
    return {
        "selectedFirewallId": store.get("selected_firewall_id"),
        "items": [public_firewall(fw) for fw in store["firewalls"]],
    }


@app.post("/api/firewalls")
def create_firewall(body: FirewallCreateBody):
    store = load_store()
    next_id = max([fw["id"] for fw in store["firewalls"]], default=0) + 1
    now = int(time.time())
    firewall = {
        "id": next_id,
        "name": body.name.strip(),
        "host": body.host.strip().rstrip("/"),
        "apiKey": body.apiKey.strip(),
        "apiSecret": body.apiSecret.strip(),
        "verifySsl": body.verifySsl,
        "timeout": body.timeout,
        "createdAt": now,
        "updatedAt": now,
    }
    store["firewalls"].append(firewall)
    if not store.get("selected_firewall_id"):
        store["selected_firewall_id"] = next_id
    save_store(store)
    return {"message": "방화벽이 등록되었습니다.", "item": public_firewall(firewall)}


@app.put("/api/firewalls/{firewall_id}")
def update_firewall(firewall_id: int, body: FirewallUpdateBody):
    store = load_store()
    target = None
    for fw in store["firewalls"]:
        if fw["id"] == firewall_id:
            target = fw
            break
    if target is None:
        raise HTTPException(status_code=404, detail="방화벽을 찾을 수 없습니다.")

    if body.name is not None:
        target["name"] = body.name.strip()
    if body.host is not None:
        target["host"] = body.host.strip().rstrip("/")
    if body.apiKey is not None:
        target["apiKey"] = body.apiKey.strip()
    if body.apiSecret is not None:
        target["apiSecret"] = body.apiSecret.strip()
    if body.verifySsl is not None:
        target["verifySsl"] = body.verifySsl
    if body.timeout is not None:
        target["timeout"] = body.timeout
    target["updatedAt"] = int(time.time())

    save_store(store)
    return {"message": "방화벽 정보가 수정되었습니다.", "item": public_firewall(target)}


@app.delete("/api/firewalls/{firewall_id}")
def delete_firewall(firewall_id: int):
    store = load_store()
    remaining = [fw for fw in store["firewalls"] if fw["id"] != firewall_id]
    if len(remaining) == len(store["firewalls"]):
        raise HTTPException(status_code=404, detail="방화벽을 찾을 수 없습니다.")
    store["firewalls"] = remaining
    if store.get("selected_firewall_id") == firewall_id:
        store["selected_firewall_id"] = remaining[0]["id"] if remaining else None
    save_store(store)
    return {"message": "방화벽이 삭제되었습니다.", "selectedFirewallId": store.get("selected_firewall_id")}


@app.post("/api/firewalls/{firewall_id}/select")
def select_firewall(firewall_id: int):
    store = load_store()
    for fw in store["firewalls"]:
        if fw["id"] == firewall_id:
            store["selected_firewall_id"] = firewall_id
            save_store(store)
            return {"message": "선택된 방화벽이 변경되었습니다.", "selectedFirewallId": firewall_id}
    raise HTTPException(status_code=404, detail="방화벽을 찾을 수 없습니다.")


@app.post("/api/firewalls/{firewall_id}/test")
def test_firewall(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    data = opnsense_request_for_target(target, "POST", "/api/core/firmware/status", json_data={})
    return {"message": "연결 성공", "product": data.get("product", {}) if isinstance(data, dict) else {}}


@app.get("/api/opnsense/ping")
def opnsense_ping():
    fw = get_selected_firewall_or_404()
    return {
        "configured": True,
        "selectedFirewallId": fw["id"],
        "host": fw["host"],
        "verifySsl": fw.get("verifySsl", False),
        "timeout": fw.get("timeout", DEFAULT_TIMEOUT),
    }


@app.get("/api/opnsense/dashboard/{firewall_id}")
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
        "firewall": public_firewall(target),
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
    }


@app.get("/api/opnsense/rules/{firewall_id}")
def get_rules(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    return opnsense_request_for_target(target, "GET", "/api/firewall/filter/searchRule")


@app.post("/api/opnsense/rules/{firewall_id}")
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
    result = opnsense_request_for_target(target, "POST", "/api/firewall/filter/addRule", json_data=payload)
    apply_result = safe_apply_firewall(target)
    return {"message": "Rule added successfully", "result": result, "apply": apply_result}


@app.delete("/api/opnsense/rules/{firewall_id}/{uuid}")
def delete_rule(firewall_id: int, uuid: str):
    target = get_firewall_or_404(firewall_id)
    result = opnsense_request_for_target(target, "POST", f"/api/firewall/filter/delRule/{uuid}", json_data={})
    apply_result = safe_apply_firewall(target)
    return {"message": "Rule deleted successfully", "result": result, "apply": apply_result}


@app.get("/api/opnsense/aliases/{firewall_id}")
def list_aliases(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    return opnsense_request_for_target(target, "GET", "/api/firewall/alias_util/aliases")


@app.get("/api/opnsense/alias/{firewall_id}/{alias_name}")
def get_alias_entries(firewall_id: int, alias_name: str):
    target = get_firewall_or_404(firewall_id)
    safe_alias = quote(alias_name, safe="")
    return opnsense_request_for_target(target, "GET", f"/api/firewall/alias_util/list/{safe_alias}")


@app.post("/api/opnsense/alias/{firewall_id}/{alias_name}/add")
def add_alias_entry(firewall_id: int, alias_name: str, body: AliasAddressBody):
    target = get_firewall_or_404(firewall_id)
    safe_alias = quote(alias_name, safe="")
    return opnsense_request_for_target(
        target, "POST", f"/api/firewall/alias_util/add/{safe_alias}", json_data={"address": body.address}
    )


@app.post("/api/opnsense/alias/{firewall_id}/{alias_name}/delete")
def delete_alias_entry(firewall_id: int, alias_name: str, body: AliasAddressBody):
    target = get_firewall_or_404(firewall_id)
    safe_alias = quote(alias_name, safe="")
    return opnsense_request_for_target(
        target, "POST", f"/api/firewall/alias_util/delete/{safe_alias}", json_data={"address": body.address}
    )


@app.get("/api/opnsense/debug/all/{firewall_id}")
def debug_all(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    system_raw = safe_block(target, "/api/diagnostics/system/system_information", "GET", default={})
    memory_raw = safe_block(target, "/api/diagnostics/system/memory", "GET", default={})
    disk_raw = safe_block(target, "/api/diagnostics/system/system_disk", "GET", default={})
    traffic_raw = safe_block(target, "/api/diagnostics/interface/get_interface_statistics", "GET", default={})
    return {
        "system": system_raw,
        "system_summary": summarize_system(system_raw),
        "memory": memory_raw,
        "memory_summary": summarize_memory(memory_raw),
        "disk": disk_raw,
        "disk_summary": summarize_disk(disk_raw),
        "traffic": traffic_raw,
    }
