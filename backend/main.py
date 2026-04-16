import os
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests
import urllib3
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# =========================
# .env 로드
# =========================
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# =========================
# 환경변수 파싱
# =========================
def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


OPNSENSE_HOST = os.getenv("OPNSENSE_HOST", "").strip().rstrip("/")
OPNSENSE_API_KEY = os.getenv("OPNSENSE_API_KEY", "").strip()
OPNSENSE_API_SECRET = os.getenv("OPNSENSE_API_SECRET", "").strip()
OPNSENSE_VERIFY_SSL = parse_bool(os.getenv("OPNSENSE_VERIFY_SSL"), default=False)
OPNSENSE_TIMEOUT = int(os.getenv("OPNSENSE_TIMEOUT", "20"))
PORT = int(os.getenv("PORT", "8000"))

if not OPNSENSE_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================
# FastAPI 앱
# =========================
app = FastAPI(title="OPNsense Dashboard Backend")

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


# =========================
# 공통 함수
# =========================
def ensure_env() -> None:
    missing = []

    if not OPNSENSE_HOST:
        missing.append("OPNSENSE_HOST")
    if not OPNSENSE_API_KEY:
        missing.append("OPNSENSE_API_KEY")
    if not OPNSENSE_API_SECRET:
        missing.append("OPNSENSE_API_SECRET")

    if missing:
        raise HTTPException(
            status_code=500,
            detail=f"환경변수 누락: {', '.join(missing)}",
        )


def opnsense_request(
    method: str,
    path: str,
    json_data: Optional[Dict[str, Any]] = None,
) -> Any:
    ensure_env()

    url = f"{OPNSENSE_HOST}{path}"
    headers: Dict[str, str] = {}

    if json_data is not None:
        headers["Content-Type"] = "application/json"

    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            auth=(OPNSENSE_API_KEY, OPNSENSE_API_SECRET),
            json=json_data,
            verify=OPNSENSE_VERIFY_SSL,
            timeout=OPNSENSE_TIMEOUT,
            headers=headers,
        )
    except requests.exceptions.ConnectTimeout:
        raise HTTPException(
            status_code=504,
            detail=f"OPNsense 연결 시간 초과: {url}",
        )
    except requests.exceptions.ReadTimeout:
        raise HTTPException(
            status_code=504,
            detail=f"OPNsense 응답 시간 초과: {url}",
        )
    except requests.exceptions.ConnectionError as e:
        raise HTTPException(
            status_code=502,
            detail=f"OPNsense 연결 실패: {str(e)}",
        )
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"요청 중 예외 발생: {str(e)}",
        )

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


def safe_apply_firewall():
    paths = [
        "/api/firewall/filter_base/apply",
        "/api/firewall/filter/apply",
    ]

    for path in paths:
        try:
            return opnsense_request("POST", path, json_data={})
        except Exception:
            continue
    return {"warning": "apply endpoint failed or not supported"}


def safe_block(
    path: str,
    method: str = "GET",
    json_data: Optional[Dict[str, Any]] = None,
    default: Optional[Any] = None,
):
    try:
        return opnsense_request(method, path, json_data=json_data)
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


# =========================
# 요약 가공 함수
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
    """
    현재 네 응답은 total/used/free 요약이 아니라
    vmstat -> memory-zone-statistics -> zone[] 구조라서
    zone size * used/free 를 합산한 요약값으로 변환
    """
    if not isinstance(memory_raw, dict):
        return {
            "total": 0,
            "used": 0,
            "free": 0,
            "used_percent": 0,
            "source": "unavailable",
        }

    vmstat = memory_raw.get("vmstat", {})
    zone_stats = vmstat.get("memory-zone-statistics", {})
    zones = zone_stats.get("zone", [])

    if not isinstance(zones, list) or len(zones) == 0:
        return {
            "total": 0,
            "used": 0,
            "free": 0,
            "used_percent": 0,
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

    used_percent = 0
    if total_bytes > 0:
        used_percent = round((used_bytes / total_bytes) * 100, 1)

    return {
        "total": total_bytes,
        "used": used_bytes,
        "free": free_bytes,
        "used_percent": used_percent,
        "source": "memory-zone-statistics",
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
        if not isinstance(device, dict):
            continue
        if device.get("mountpoint") == "/":
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


# =========================
# 기본 API
# =========================
@app.get("/")
def root():
    return {"ok": True, "message": "Backend is running"}


@app.get("/health")
def health():
    return {"status": "running"}


@app.get("/api/test")
def api_test():
    return {"message": "backend api works"}


@app.get("/api/opnsense/ping")
def opnsense_ping():
    return {
        "configured": bool(OPNSENSE_HOST and OPNSENSE_API_KEY and OPNSENSE_API_SECRET),
        "host": OPNSENSE_HOST,
        "verify_ssl": OPNSENSE_VERIFY_SSL,
        "timeout": OPNSENSE_TIMEOUT,
    }


# =========================
# 상태
# =========================
@app.get("/api/opnsense/firmware/status")
def firmware_status():
    return opnsense_request("POST", "/api/core/firmware/status", json_data={})


@app.get("/api/opnsense/status")
def frontend_status_alias():
    return opnsense_request("POST", "/api/core/firmware/status", json_data={})


# =========================
# Alias 조회 / 추가 / 삭제
# =========================
@app.get("/api/opnsense/aliases")
def list_aliases():
    return opnsense_request("GET", "/api/firewall/alias_util/aliases")


@app.get("/api/opnsense/alias/{alias_name}")
def get_alias_entries(alias_name: str):
    safe_alias = quote(alias_name, safe="")
    return opnsense_request("GET", f"/api/firewall/alias_util/list/{safe_alias}")


@app.post("/api/opnsense/alias/{alias_name}/add")
def add_alias_entry(alias_name: str, body: AliasAddressBody):
    safe_alias = quote(alias_name, safe="")
    return opnsense_request(
        "POST",
        f"/api/firewall/alias_util/add/{safe_alias}",
        json_data={"address": body.address},
    )


@app.post("/api/opnsense/alias/{alias_name}/delete")
def delete_alias_entry(alias_name: str, body: AliasAddressBody):
    safe_alias = quote(alias_name, safe="")
    return opnsense_request(
        "POST",
        f"/api/firewall/alias_util/delete/{safe_alias}",
        json_data={"address": body.address},
    )


# =========================
# 방화벽 룰 조회 / 추가 / 삭제
# =========================
@app.get("/api/opnsense/rules")
def get_rules():
    return opnsense_request("GET", "/api/firewall/filter/searchRule")


@app.post("/api/opnsense/rules")
def add_rule(body: RuleCreateBody):
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

    result = opnsense_request("POST", "/api/firewall/filter/addRule", json_data=payload)
    apply_result = safe_apply_firewall()

    return {
        "message": "Rule added successfully",
        "result": result,
        "apply": apply_result,
    }


@app.delete("/api/opnsense/rules/{uuid}")
def delete_rule(uuid: str):
    result = opnsense_request("POST", f"/api/firewall/filter/delRule/{uuid}", json_data={})
    apply_result = safe_apply_firewall()

    return {
        "message": "Rule deleted successfully",
        "result": result,
        "apply": apply_result,
    }


# =========================
# 시스템 / 인터페이스 / 서비스 / 트래픽 / 메모리 / 디스크
# =========================
@app.get("/api/opnsense/system")
def system_information():
    return opnsense_request("GET", "/api/diagnostics/system/system_information")


@app.get("/api/opnsense/interfaces")
def interfaces_information():
    return opnsense_request("GET", "/api/interfaces/overview/export")


@app.get("/api/opnsense/services")
def services_information():
    return opnsense_request("GET", "/api/core/service/search")


@app.get("/api/opnsense/traffic")
def traffic_information():
    return opnsense_request("GET", "/api/diagnostics/interface/get_interface_statistics")


@app.get("/api/opnsense/memory")
def memory_information():
    return opnsense_request("GET", "/api/diagnostics/system/memory")


@app.get("/api/opnsense/disk")
def disk_information():
    return opnsense_request("GET", "/api/diagnostics/system/system_disk")


@app.get("/api/opnsense/debug/all")
def debug_all():
    system_raw = safe_block("/api/diagnostics/system/system_information", "GET", default={})
    memory_raw = safe_block("/api/diagnostics/system/memory", "GET", default={})
    disk_raw = safe_block("/api/diagnostics/system/system_disk", "GET", default={})
    traffic_raw = safe_block("/api/diagnostics/interface/get_interface_statistics", "GET", default={})

    return {
        "system": system_raw,
        "system_summary": summarize_system(system_raw),
        "memory": memory_raw,
        "memory_summary": summarize_memory(memory_raw),
        "disk": disk_raw,
        "disk_summary": summarize_disk(disk_raw),
        "traffic": traffic_raw,
    }


# =========================
# 통합 대시보드 API
# =========================
@app.get("/api/opnsense/dashboard")
def dashboard():
    status_data = safe_block(
        "/api/core/firmware/status",
        method="POST",
        json_data={},
        default={},
    )

    rules_data = safe_block(
        "/api/firewall/filter/searchRule",
        method="GET",
        default={"rows": []},
    )

    system_data = safe_block(
        "/api/diagnostics/system/system_information",
        method="GET",
        default={},
    )

    interfaces_data = safe_block(
        "/api/interfaces/overview/export",
        method="GET",
        default={},
    )

    services_data = safe_block(
        "/api/core/service/search",
        method="GET",
        default={},
    )

    traffic_data = safe_block(
        "/api/diagnostics/interface/get_interface_statistics",
        method="GET",
        default={},
    )

    memory_data = safe_block(
        "/api/diagnostics/system/memory",
        method="GET",
        default={},
    )

    disk_data = safe_block(
        "/api/diagnostics/system/system_disk",
        method="GET",
        default={"devices": []},
    )

    aliases_data = safe_block(
        "/api/firewall/alias_util/aliases",
        method="GET",
        default=[],
    )

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
    }