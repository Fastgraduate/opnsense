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
OPNSENSE_TIMEOUT = int(os.getenv("OPNSENSE_TIMEOUT", "10"))
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
    """
    apply 엔드포인트는 환경/버전에 따라 다를 수 있어서
    실패해도 전체 요청을 죽이지 않도록 처리
    """
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
# OPNsense 상태 확인
# =========================
@app.get("/api/opnsense/firmware/status")
def firmware_status():
    # 네 환경 기준 POST + {} 가 맞았던 케이스 반영
    return opnsense_request("POST", "/api/core/firmware/status", json_data={})


@app.get("/api/opnsense/status")
def frontend_status_alias():
    # 프론트 호환용 별칭
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
# 시스템 / 인터페이스 / 서비스 / 트래픽
# =========================
@app.get("/api/opnsense/system")
def system_information():
    return opnsense_request("GET", "/api/diagnostics/system/systemInformation")


@app.get("/api/opnsense/interfaces")
def interfaces_information():
    return opnsense_request("GET", "/api/interfaces/overview/export")


@app.get("/api/opnsense/services")
def services_information():
    return opnsense_request("GET", "/api/core/service/search")


@app.get("/api/opnsense/traffic")
def traffic_information():
    return opnsense_request("GET", "/api/diagnostics/interface/getInterfaceTraffic")


# =========================
# 통합 대시보드 API
# =========================
@app.get("/api/opnsense/dashboard")
def dashboard():
    result: Dict[str, Any] = {}

    try:
        result["status"] = opnsense_request(
            "POST",
            "/api/core/firmware/status",
            json_data={},
        )
    except Exception as e:
        result["status"] = {"error": str(e)}

    try:
        result["rules"] = opnsense_request("GET", "/api/firewall/filter/searchRule")
    except Exception as e:
        result["rules"] = {"rows": [], "error": str(e)}

    try:
        result["system"] = opnsense_request("GET", "/api/diagnostics/system/systemInformation")
    except Exception as e:
        result["system"] = {"error": str(e)}

    try:
        result["interfaces"] = opnsense_request("GET", "/api/interfaces/overview/export")
    except Exception as e:
        result["interfaces"] = {"error": str(e)}

    try:
        result["services"] = opnsense_request("GET", "/api/core/service/search")
    except Exception as e:
        result["services"] = {"error": str(e)}

    try:
        result["traffic"] = opnsense_request("GET", "/api/diagnostics/interface/getInterfaceTraffic")
    except Exception as e:
        result["traffic"] = {"error": str(e)}

    try:
        result["aliases"] = opnsense_request("GET", "/api/firewall/alias_util/aliases")
    except Exception as e:
        result["aliases"] = {"error": str(e)}

    return result