import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import requests
import urllib3
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'y', 'on'}


APP_ENCRYPTION_KEY = os.getenv('APP_ENCRYPTION_KEY', '').strip()
OPNSENSE_TIMEOUT = int(os.getenv('OPNSENSE_TIMEOUT', '20'))
ELASTIC_URL = os.getenv('ELASTIC_URL', '').strip().rstrip('/')
ELASTIC_API_KEY = os.getenv('ELASTIC_API_KEY', '').strip()
ELASTIC_USERNAME = os.getenv('ELASTIC_USERNAME', '').strip()
ELASTIC_PASSWORD = os.getenv('ELASTIC_PASSWORD', '').strip()
ELASTIC_VERIFY_SSL = parse_bool(os.getenv('ELASTIC_VERIFY_SSL'), default=False)

if not ELASTIC_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FIREWALLS_FILE = BASE_DIR / 'firewalls.json'

app = FastAPI(title='Multi Firewall Dashboard Backend')
app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


class FirewallCreateBody(BaseModel):
    name: str = Field(min_length=1)
    host: str = Field(min_length=1)
    api_key: str = Field(min_length=1)
    api_secret: str = Field(min_length=1)
    verify_ssl: bool = False
    log_index: str = 'logs-suricata.eve-*'
    description: str = ''


class FirewallUpdateBody(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    verify_ssl: Optional[bool] = None
    log_index: Optional[str] = None
    description: Optional[str] = None


class RuleCreateBody(BaseModel):
    description: str = ''
    action: str = 'pass'
    interface: str = 'lan'
    direction: str = 'in'
    protocol: str = 'TCP'
    sourceNet: str = 'any'
    sourcePort: str = ''
    destinationNet: str = 'any'
    destinationPort: str = ''
    enabled: str = '1'
    quick: str = '1'
    log: bool = False


class EventLogsQueryBody(BaseModel):
    size: int = 50
    minutes: int = 60
    action: str = ''
    interface: str = ''
    query: str = ''


# ---------- security / storage ----------

def ensure_encryption_key() -> Fernet:
    if not APP_ENCRYPTION_KEY:
        raise HTTPException(status_code=500, detail='APP_ENCRYPTION_KEY 누락')
    try:
        return Fernet(APP_ENCRYPTION_KEY.encode())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'APP_ENCRYPTION_KEY 오류: {exc}')


def encrypt_text(text: str) -> str:
    return ensure_encryption_key().encrypt(text.encode()).decode()


def decrypt_text(token: str) -> str:
    return ensure_encryption_key().decrypt(token.encode()).decode()


def load_firewalls() -> List[Dict[str, Any]]:
    if not FIREWALLS_FILE.exists():
        return []
    try:
        return json.loads(FIREWALLS_FILE.read_text(encoding='utf-8'))
    except Exception:
        return []


def save_firewalls(items: List[Dict[str, Any]]) -> None:
    FIREWALLS_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


def next_firewall_id(items: List[Dict[str, Any]]) -> int:
    return max([int(x.get('id', 0)) for x in items] + [0]) + 1


def serialize_firewall(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'id': item['id'],
        'name': item['name'],
        'host': item['host'],
        'verify_ssl': item.get('verify_ssl', False),
        'log_index': item.get('log_index', 'logs-suricata.eve-*'),
        'description': item.get('description', ''),
        'has_secret': bool(item.get('api_key_enc') and item.get('api_secret_enc')),
        'created_at': item.get('created_at', 0),
        'updated_at': item.get('updated_at', 0),
    }


def get_firewall_or_404(firewall_id: int) -> Dict[str, Any]:
    for item in load_firewalls():
        if int(item.get('id', 0)) == firewall_id:
            return item
    raise HTTPException(status_code=404, detail='방화벽을 찾을 수 없습니다.')


# ---------- shared helpers ----------
def opnsense_request(target: Dict[str, Any], method: str, path: str, json_data: Optional[Dict[str, Any]] = None) -> Any:
    host = str(target.get('host', '')).strip().rstrip('/')
    if not host:
        raise HTTPException(status_code=500, detail='방화벽 host 누락')

    url = f'{host}{path}'
    headers: Dict[str, str] = {}
    if json_data is not None:
        headers['Content-Type'] = 'application/json'

    api_key = decrypt_text(target['api_key_enc'])
    api_secret = decrypt_text(target['api_secret_enc'])

    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            auth=(api_key, api_secret),
            json=json_data,
            verify=bool(target.get('verify_ssl', False)),
            timeout=OPNSENSE_TIMEOUT,
            headers=headers,
        )
    except requests.exceptions.ConnectTimeout:
        raise HTTPException(status_code=504, detail=f'OPNsense 연결 시간 초과: {url}')
    except requests.exceptions.ReadTimeout:
        raise HTTPException(status_code=504, detail=f'OPNsense 응답 시간 초과: {url}')
    except requests.exceptions.ConnectionError as e:
        raise HTTPException(status_code=502, detail=f'OPNsense 연결 실패: {str(e)}')
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f'요청 중 예외 발생: {str(e)}')

    try:
        data = response.json()
    except ValueError:
        data = {'raw_text': response.text}

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail={'message': 'OPNsense API 오류', 'url': url, 'response': data},
        )
    return data


def safe_block(target: Dict[str, Any], path: str, method: str = 'GET', json_data: Optional[Dict[str, Any]] = None, default: Optional[Any] = None):
    try:
        return opnsense_request(target, method, path, json_data=json_data)
    except Exception as e:
        if default is None:
            default = {}
        if isinstance(default, dict):
            return {**default, 'error': str(e)}
        return {'data': default, 'error': str(e)}


def safe_apply_firewall(target: Dict[str, Any]):
    for path in ['/api/firewall/filter_base/apply', '/api/firewall/filter/apply']:
        try:
            return opnsense_request(target, 'POST', path, json_data={})
        except Exception:
            continue
    return {'warning': 'apply endpoint failed or not supported'}


def to_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _flatten_dict(data: Any, prefix: str = '') -> Iterable[Tuple[str, Any]]:
    if isinstance(data, dict):
        for key, value in data.items():
            new_prefix = f'{prefix}.{key}' if prefix else str(key)
            yield from _flatten_dict(value, new_prefix)
    else:
        yield prefix, data


def _to_int(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().replace(',', '')
    try:
        if text.startswith('0x'):
            return int(text, 16)
        return int(float(text))
    except Exception:
        return 0


def _normalize_key(key: str) -> str:
    return ''.join(ch for ch in key.lower() if ch.isalnum())


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


# ---------- summaries ----------
def summarize_system(system_raw: Any) -> Dict[str, Any]:
    if not isinstance(system_raw, dict):
        return {'hostname': '-', 'platform': '-', 'cpu_arch': '-', 'uptime': '-', 'updates': '-', 'versions': []}
    versions = system_raw.get('versions', [])
    if not isinstance(versions, list):
        versions = []
    firmware_line = versions[0] if len(versions) > 0 else ''
    platform_line = versions[1] if len(versions) > 1 else ''
    ssl_line = versions[2] if len(versions) > 2 else ''
    cpu_arch = '-'
    if isinstance(firmware_line, str) and '-' in firmware_line:
        cpu_arch = firmware_line.split('-')[-1].upper()
    return {
        'hostname': system_raw.get('name', '-'),
        'platform': platform_line or '-',
        'cpu_arch': cpu_arch,
        'uptime': '-',
        'firmware_line': firmware_line or '-',
        'ssl_line': ssl_line or '-',
        'updates': system_raw.get('updates', '-'),
        'versions': versions,
    }


def summarize_memory(memory_raw: Any) -> Dict[str, Any]:
    if not isinstance(memory_raw, dict):
        return {'total': 0, 'used': 0, 'free': 0, 'used_percent': 0.0, 'source': 'unavailable'}
    vmstat = memory_raw.get('vmstat', {}) if isinstance(memory_raw, dict) else {}
    flat = dict(_flatten_dict(vmstat))
    page_size = _pick_first(flat, ['v_page_size', 'pagesize', 'hw.pagesize', 'vm.stats.vm.v_page_size'])
    page_count = _pick_first(flat, ['v_page_count', 'pagecount', 'vm.stats.vm.v_page_count'])
    physmem_bytes = _pick_first(flat, ['hw.physmem', 'physmem', 'realmem'])
    free_count = _pick_first(flat, ['v_free_count', 'freecount', 'vm.stats.vm.v_free_count'])
    inactive_count = _pick_first(flat, ['v_inactive_count', 'inactivecount', 'vm.stats.vm.v_inactive_count'])
    cache_count = _pick_first(flat, ['v_cache_count', 'cachecount', 'vm.stats.vm.v_cache_count'])
    laundry_count = _pick_first(flat, ['v_laundry_count', 'laundrycount', 'vm.stats.vm.v_laundry_count'])

    total = physmem_bytes if physmem_bytes > 0 else page_size * page_count if page_size > 0 and page_count > 0 else 0
    available = 0
    if page_size > 0:
        available_pages = free_count + inactive_count + cache_count + laundry_count
        available = available_pages * page_size
    if total > 0:
        available = max(min(available, total), 0)
        used = max(total - available, 0)
        return {
            'total': int(total),
            'used': int(used),
            'free': int(available),
            'used_percent': round((used / total) * 100, 1) if total > 0 else 0.0,
            'source': 'vmstat-system-memory',
        }

    zone_stats = vmstat.get('memory-zone-statistics', {})
    zones = zone_stats.get('zone', [])
    if not isinstance(zones, list) or len(zones) == 0:
        return {'total': 0, 'used': 0, 'free': 0, 'used_percent': 0.0, 'source': 'no-zone-data'}

    total_bytes = 0
    used_bytes = 0
    free_bytes = 0
    for zone in zones:
        if not isinstance(zone, dict):
            continue
        size = to_int(zone.get('size'))
        used = to_int(zone.get('used'))
        free = to_int(zone.get('free'))
        if size <= 0:
            continue
        used_bytes += size * used
        free_bytes += size * free
        total_bytes += size * (used + free)

    return {
        'total': int(total_bytes),
        'used': int(used_bytes),
        'free': int(free_bytes),
        'used_percent': round((used_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0.0,
        'source': 'memory-zone-statistics-fallback',
    }


def summarize_disk(disk_raw: Any) -> Dict[str, Any]:
    devices = disk_raw.get('devices', []) if isinstance(disk_raw, dict) else disk_raw if isinstance(disk_raw, list) else []
    if not isinstance(devices, list):
        devices = []
    root_device = None
    for device in devices:
        if isinstance(device, dict) and device.get('mountpoint') == '/':
            root_device = device
            break
    if root_device is None and devices:
        root_device = devices[0]
    if not isinstance(root_device, dict):
        return {'device': '-', 'mountpoint': '-', 'blocks': '0 B', 'used': '0 B', 'available': '0 B', 'used_pct': 0}
    return {
        'device': root_device.get('device', '-'),
        'mountpoint': root_device.get('mountpoint', '-'),
        'blocks': root_device.get('blocks', '0 B'),
        'used': root_device.get('used', '0 B'),
        'available': root_device.get('available', '0 B'),
        'used_pct': root_device.get('used_pct', 0),
    }


# ---------- elastic ----------
def elastic_headers() -> Dict[str, str]:
    headers = {'Content-Type': 'application/json'}
    if ELASTIC_API_KEY:
        headers['Authorization'] = f'ApiKey {ELASTIC_API_KEY}'
    return headers


def elastic_auth():
    if ELASTIC_API_KEY:
        return None
    if ELASTIC_USERNAME and ELASTIC_PASSWORD:
        return (ELASTIC_USERNAME, ELASTIC_PASSWORD)
    return None


def ensure_elastic_config():
    if not ELASTIC_URL:
        raise HTTPException(status_code=500, detail='ELASTIC_URL 누락')
    if not ELASTIC_API_KEY and not (ELASTIC_USERNAME and ELASTIC_PASSWORD):
        raise HTTPException(status_code=500, detail='Elastic 인증 정보 누락')


def search_firewall_events(log_index: str, size: int, minutes: int, action: str = '', interface: str = '', query_text: str = '') -> List[Dict[str, Any]]:
    ensure_elastic_config()
    must: List[Dict[str, Any]] = [
        {'range': {'@timestamp': {'gte': f'now-{minutes}m'}}},
    ]
    if action:
        must.append({'term': {'event.action.keyword': action}})
    if interface:
        must.append({'term': {'observer.ingress.interface.name.keyword': interface}})
    if query_text:
        must.append({
            'multi_match': {
                'query': query_text,
                'fields': [
                    'source.ip', 'destination.ip', 'rule.name', 'message', 'network.transport', 'event.action'
                ]
            }
        })

    body = {
        'size': size,
        'sort': [{'@timestamp': {'order': 'desc'}}],
        'query': {'bool': {'must': must}},
        '_source': [
            '@timestamp', 'event.action', 'event.kind', 'event.category', 'source.ip', 'source.port',
            'destination.ip', 'destination.port', 'network.transport', 'network.protocol',
            'observer.ingress.interface.name', 'observer.egress.interface.name',
            'rule.name', 'rule.id', 'message', 'suricata.eve.alert.signature',
            'suricata.eve.alert.category', 'suricata.eve.alert.severity', 'host.name'
        ],
    }

    resp = requests.post(
        f'{ELASTIC_URL}/{log_index}/_search',
        headers=elastic_headers(),
        auth=elastic_auth(),
        json=body,
        verify=ELASTIC_VERIFY_SSL,
        timeout=20,
    )
    resp.raise_for_status()
    payload = resp.json()
    hits = payload.get('hits', {}).get('hits', [])
    rows = []
    for hit in hits:
        src = hit.get('_source', {})
        rows.append({
            'timestamp': src.get('@timestamp', '-'),
            'action': src.get('event', {}).get('action', src.get('message', '-')) if isinstance(src.get('event'), dict) else '-',
            'interface': (
                (((src.get('observer') or {}).get('ingress') or {}).get('interface') or {}).get('name')
                or (((src.get('observer') or {}).get('egress') or {}).get('interface') or {}).get('name')
                or '-'
            ),
            'protocol': src.get('network', {}).get('transport', src.get('network', {}).get('protocol', '-')) if isinstance(src.get('network'), dict) else '-',
            'source_ip': src.get('source', {}).get('ip', '-') if isinstance(src.get('source'), dict) else '-',
            'source_port': src.get('source', {}).get('port', '-') if isinstance(src.get('source'), dict) else '-',
            'destination_ip': src.get('destination', {}).get('ip', '-') if isinstance(src.get('destination'), dict) else '-',
            'destination_port': src.get('destination', {}).get('port', '-') if isinstance(src.get('destination'), dict) else '-',
            'rule': (
                (src.get('rule') or {}).get('name')
                or ((src.get('suricata') or {}).get('eve') or {}).get('alert', {}).get('signature')
                or src.get('message', '-')
            ),
            'severity': (((src.get('suricata') or {}).get('eve') or {}).get('alert') or {}).get('severity', '-'),
            'category': (((src.get('suricata') or {}).get('eve') or {}).get('alert') or {}).get('category', '-'),
            'host': src.get('host', {}).get('name', '-') if isinstance(src.get('host'), dict) else '-',
        })
    return rows


# ---------- basic ----------
@app.get('/')
def root():
    return {'ok': True, 'message': 'Backend is running'}


@app.get('/health')
def health():
    return {'status': 'running'}


# ---------- firewalls ----------
@app.get('/api/firewalls')
def list_firewalls():
    return [serialize_firewall(x) for x in load_firewalls()]


@app.post('/api/firewalls')
def create_firewall(body: FirewallCreateBody):
    items = load_firewalls()
    now = int(time.time())
    item = {
        'id': next_firewall_id(items),
        'name': body.name.strip(),
        'host': body.host.strip().rstrip('/'),
        'api_key_enc': encrypt_text(body.api_key.strip()),
        'api_secret_enc': encrypt_text(body.api_secret.strip()),
        'verify_ssl': body.verify_ssl,
        'log_index': body.log_index.strip() or 'logs-suricata.eve-*',
        'description': body.description.strip(),
        'created_at': now,
        'updated_at': now,
    }
    items.append(item)
    save_firewalls(items)
    return serialize_firewall(item)


@app.put('/api/firewalls/{firewall_id}')
def update_firewall(firewall_id: int, body: FirewallUpdateBody):
    items = load_firewalls()
    updated = None
    for item in items:
        if int(item.get('id', 0)) != firewall_id:
            continue
        if body.name is not None:
            item['name'] = body.name.strip()
        if body.host is not None:
            item['host'] = body.host.strip().rstrip('/')
        if body.api_key is not None and body.api_key.strip():
            item['api_key_enc'] = encrypt_text(body.api_key.strip())
        if body.api_secret is not None and body.api_secret.strip():
            item['api_secret_enc'] = encrypt_text(body.api_secret.strip())
        if body.verify_ssl is not None:
            item['verify_ssl'] = body.verify_ssl
        if body.log_index is not None:
            item['log_index'] = body.log_index.strip() or 'logs-suricata.eve-*'
        if body.description is not None:
            item['description'] = body.description.strip()
        item['updated_at'] = int(time.time())
        updated = item
        break
    if updated is None:
        raise HTTPException(status_code=404, detail='방화벽을 찾을 수 없습니다.')
    save_firewalls(items)
    return serialize_firewall(updated)


@app.delete('/api/firewalls/{firewall_id}')
def delete_firewall(firewall_id: int):
    items = load_firewalls()
    next_items = [x for x in items if int(x.get('id', 0)) != firewall_id]
    if len(next_items) == len(items):
        raise HTTPException(status_code=404, detail='방화벽을 찾을 수 없습니다.')
    save_firewalls(next_items)
    return {'ok': True}


# ---------- per-firewall opnsense ----------
@app.get('/api/firewalls/{firewall_id}/dashboard')
def dashboard(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    status_data = safe_block(target, '/api/core/firmware/status', method='POST', json_data={}, default={})
    rules_data = safe_block(target, '/api/firewall/filter/searchRule', method='GET', default={'rows': []})
    system_data = safe_block(target, '/api/diagnostics/system/system_information', method='GET', default={})
    interfaces_data = safe_block(target, '/api/interfaces/overview/export', method='GET', default={})
    services_data = safe_block(target, '/api/core/service/search', method='GET', default={})
    traffic_data = safe_block(target, '/api/diagnostics/interface/get_interface_statistics', method='GET', default={})
    memory_data = safe_block(target, '/api/diagnostics/system/memory', method='GET', default={})
    disk_data = safe_block(target, '/api/diagnostics/system/system_disk', method='GET', default={'devices': []})
    aliases_data = safe_block(target, '/api/firewall/alias_util/aliases', method='GET', default=[])

    return {
        'status': status_data,
        'product': status_data.get('product', {}) if isinstance(status_data, dict) else {},
        'rules': rules_data if isinstance(rules_data, dict) else {'rows': []},
        'system': system_data,
        'system_summary': summarize_system(system_data),
        'interfaces': interfaces_data,
        'services': services_data,
        'traffic': traffic_data,
        'memory': memory_data,
        'memory_summary': summarize_memory(memory_data),
        'disk': disk_data,
        'disk_summary': summarize_disk(disk_data),
        'aliases': aliases_data,
        'firewall': serialize_firewall(target),
    }


@app.get('/api/firewalls/{firewall_id}/rules')
def get_rules(firewall_id: int):
    target = get_firewall_or_404(firewall_id)
    return opnsense_request(target, 'GET', '/api/firewall/filter/searchRule')


@app.post('/api/firewalls/{firewall_id}/rules')
def add_rule(firewall_id: int, body: RuleCreateBody):
    target = get_firewall_or_404(firewall_id)
    payload = {
        'rule': {
            'enabled': body.enabled,
            'quick': body.quick,
            'action': body.action,
            'interface': body.interface,
            'direction': body.direction,
            'ipprotocol': 'inet',
            'protocol': body.protocol,
            'source_net': body.sourceNet,
            'source_port': body.sourcePort,
            'destination_net': body.destinationNet,
            'destination_port': body.destinationPort,
            'description': body.description or 'API rule',
            'log': '1' if body.log else '0',
        }
    }
    result = opnsense_request(target, 'POST', '/api/firewall/filter/addRule', json_data=payload)
    apply_result = safe_apply_firewall(target)
    return {'message': 'Rule added successfully', 'result': result, 'apply': apply_result}


@app.delete('/api/firewalls/{firewall_id}/rules/{uuid}')
def delete_rule(firewall_id: int, uuid: str):
    target = get_firewall_or_404(firewall_id)
    result = opnsense_request(target, 'POST', f'/api/firewall/filter/delRule/{uuid}', json_data={})
    apply_result = safe_apply_firewall(target)
    return {'message': 'Rule deleted successfully', 'result': result, 'apply': apply_result}


@app.post('/api/firewalls/{firewall_id}/event-logs')
def get_event_logs(firewall_id: int, body: EventLogsQueryBody):
    target = get_firewall_or_404(firewall_id)
    rows = search_firewall_events(
        log_index=target.get('log_index', 'logs-suricata.eve-*'),
        size=max(1, min(body.size, 200)),
        minutes=max(1, min(body.minutes, 24 * 60)),
        action=body.action.strip(),
        interface=body.interface.strip(),
        query_text=body.query.strip(),
    )
    return {'rows': rows, 'firewall': serialize_firewall(target)}
