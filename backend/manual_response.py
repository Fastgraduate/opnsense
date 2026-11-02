"""Persistent manual IP response through the official OPNsense API.

No credentials or network transport live here; main.py supplies its existing
transport. A successful HTTP response alone is never treated as an applied rule.
"""
import ipaddress
import re
from urllib.parse import quote, urlparse


class ResponseError(Exception):
    def __init__(self, message, detail=None):
        super().__init__(message)
        self.detail = {"message": message, **(detail or {})}


def value(field):
    """Model endpoints return select fields as {key: {selected, value}}."""
    if isinstance(field, dict):
        return ','.join(str(k) for k, v in field.items()
                        if isinstance(v, dict) and str(v.get('selected', '0')) == '1')
    if isinstance(field, list):
        return ','.join(map(str, field))
    return str(field if field is not None else '')


def contents(field):
    return [x for x in re.split(r'[\s,]+', value(field)) if x]


def approved(result, step):
    if not isinstance(result, dict) or result.get('validations') or result.get('error'):
        raise ResponseError(f'{step}: OPNsense 응답을 확인하지 못했습니다.', {'response': result})
    status = str(result.get('result') or result.get('status') or '').strip().lower()
    if status not in {'ok', 'saved', 'deleted', 'done', 'success'}:
        raise ResponseError(f'{step}: OPNsense가 성공을 반환하지 않았습니다.', {'response': result})
    return result


class ManualResponse:
    def __init__(self, request, target, alias):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,31}', alias):
            raise ResponseError('차단 Alias 이름이 올바르지 않습니다.')
        self.request, self.target, self.alias = request, target, alias
        self.tag = f'Security Console manual [{alias}]'

    def call(self, method, paths, body=None):
        if isinstance(paths, str):
            paths = [paths]
        for i, path in enumerate(paths):
            try:
                return self.request(self.target, method, path, json_data=body)
            except Exception as exc:
                # Never retry a mutation after a timeout or denied permission.
                if getattr(exc, 'status_code', None) not in {404, 405} or i == len(paths)-1:
                    raise
        raise ResponseError('지원되는 OPNsense API가 없습니다.')

    def api(self, controller, snake, camel, suffix=''):
        return [f'/api/firewall/{controller}/{name}{suffix}' for name in dict.fromkeys([snake, camel])]

    def alias_config(self):
        result = self.call('GET', self.api('alias', 'search_item', 'searchItem',
            '?current=1&rowCount=-1&searchPhrase=' + quote(self.alias)))
        if not isinstance(result, dict) or not isinstance(result.get('rows'), list):
            raise ResponseError('Alias 목록 조회 응답이 올바르지 않습니다.')
        matches = [r for r in result['rows'] if r.get('name') == self.alias]
        if len(matches) > 1:
            raise ResponseError('동일 이름의 Alias가 여러 개 있습니다.')
        if not matches:
            return None, None
        uid = matches[0]['uuid']
        result = self.call('GET', self.api('alias', 'get_item', 'getItem', '/' + uid))
        config = result.get('alias') if isinstance(result, dict) else None
        if not isinstance(config, dict) or value(config.get('name')) != self.alias:
            raise ResponseError('Alias 설정을 확인하지 못했습니다.')
        return uid, {k: value(v) for k, v in config.items()}

    def table(self):
        result = self.call('GET', f'/api/firewall/alias_util/list/{quote(self.alias)}?current=1&rowCount=-1')
        if not isinstance(result, dict) or not isinstance(result.get('rows'), list):
            raise ResponseError('실제 방화벽 Alias 테이블을 확인하지 못했습니다.')
        entries = set()
        for row in result['rows']:
            raw = row if isinstance(row, str) else row.get('ip') or row.get('address') or row.get('network')
            if not raw:
                raise ResponseError('Alias 테이블 주소 필드가 없습니다.')
            if raw:
                try:
                    entries.add(str(ipaddress.ip_network(str(raw), strict=False)))
                except ValueError:
                    raise ResponseError('Alias 테이블에 해석할 수 없는 주소가 있습니다.')
        return entries

    def member(self, ip, entries):
        address = ipaddress.ip_address(ip)
        return any(address in ipaddress.ip_network(n) for n in entries)

    def rules(self):
        result = self.call('GET', self.api('filter', 'search_rule', 'searchRule',
            '?current=1&rowCount=-1&searchPhrase=' + quote(self.tag)))
        if not isinstance(result, dict) or not isinstance(result.get('rows'), list):
            raise ResponseError('차단 규칙 목록을 확인하지 못했습니다.')
        return result['rows']

    def rule_spec(self, side):
        # Empty interface = floating rule on all interfaces, including WAN/LAN.
        return {'enabled': '1', 'sequence': '1', 'action': 'block', 'quick': '1',
                'interface': '', 'direction': 'any', 'ipprotocol': 'inet46',
                'protocol': 'any', 'source_net': self.alias if side == 'source' else 'any',
                'destination_net': self.alias if side == 'destination' else 'any',
                'source_not': '0', 'destination_not': '0', 'source_port': '',
                'destination_port': '', 'log': '1', 'description': f'{self.tag} {side}'}

    def check_rules(self):
        rows = self.rules()
        for side in ('source', 'destination'):
            spec = self.rule_spec(side)
            matches = [r for r in rows if r.get('description') == spec['description']]
            if len(matches) != 1:
                return False
            data = self.call('GET', self.api('filter', 'get_rule', 'getRule', '/' + matches[0]['uuid']))
            rule = data.get('rule', {})
            if any(value(rule.get(k)) != v for k, v in spec.items()):
                return False
        return True

    def ensure_rules(self, created):
        rows = self.rules()
        for side in ('source', 'destination'):
            spec = self.rule_spec(side)
            matches = [r for r in rows if r.get('description') == spec['description']]
            if len(matches) > 1:
                raise ResponseError('관리 차단 규칙이 중복돼 있습니다. 중복 규칙을 확인하세요.')
            if matches:
                uid = matches[0]['uuid']
                data = self.call('GET', self.api('filter', 'get_rule', 'getRule', '/' + uid))
                current = data.get('rule', {})
                if any(value(current.get(k)) != v for k, v in spec.items()):
                    # Do not silently overwrite an administrator's edited rule.
                    raise ResponseError('기존 관리 차단 규칙이 변경돼 있습니다. Floating/Both/Quick/순서 1 설정을 확인하세요.')
            else:
                data = approved(self.call('POST', self.api('filter', 'add_rule', 'addRule'), {'rule': spec}), '차단 규칙 생성')
                if not data.get('uuid'):
                    raise ResponseError('생성한 차단 규칙 UUID가 없습니다.')
                created.append(data['uuid'])

    def apply(self):
        approved(self.call('POST', '/api/firewall/alias/reconfigure', {}), 'Alias 적용')
        return approved(self.call('POST', '/api/firewall/filter/apply', {}), '방화벽 규칙 적용')

    def validate_address(self, ip, force, protected=(), client_ip=None):
        try:
            address = ipaddress.ip_address(ip.strip())
        except ValueError:
            raise ResponseError('유효한 단일 IP 주소를 입력하세요.')
        if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local:
            raise ResponseError('이 주소는 차단 대상으로 사용할 수 없습니다.')
        hosts = list(protected)
        hosts += [urlparse(str(self.target.get(k) or '')).hostname for k in ('host', 'elastic_url')]
        if client_ip:
            hosts.append(client_ip)
        for host in hosts:
            if not host:
                continue
            try:
                if address in ipaddress.ip_network(str(host), strict=False):
                    raise ResponseError('관리 PC·방화벽·ELK 보호 주소입니다. 반대 방향 로그의 공격자 IP를 선택하세요.')
            except ValueError:
                continue
        if not address.is_global and not force:
            raise ResponseError('실습망 사설 IP 허용을 선택한 뒤 차단하세요.')
        return str(address)

    def change(self, ip, block):
        uid, config = self.alias_config()
        if config and (config.get('type') != 'host' or config.get('enabled') != '1'):
            raise ResponseError('수동 차단 Alias는 활성화된 Host 유형이어야 합니다.')
        old = contents(config.get('content', '')) if config else []
        # Preserve other hosts; permit only literal IPs in this dedicated alias.
        canonical = []
        for entry in old:
            try:
                canonical.append(str(ipaddress.ip_address(entry)))
            except ValueError:
                raise ResponseError('차단 Alias에 IP 이외의 항목이 있습니다. 전용 Host Alias를 사용하세요.')
        new = list(dict.fromkeys(canonical + [ip])) if block else [x for x in canonical if x != ip]
        if not config and not block:
            return {'ok': True, 'already_absent': True, 'apply': {'status': 'ok'}}
        created = []
        touched = False
        try:
            touched = True  # A timeout can still mean the write reached OPNsense.
            if uid:
                approved(self.call('POST', self.api('alias', 'set_item', 'setItem', '/' + uid),
                    {'alias': {'content': '\n'.join(new)}}), 'Alias 영구 저장')
            else:
                result = approved(self.call('POST', self.api('alias', 'add_item', 'addItem'),
                    {'alias': {'name': self.alias, 'enabled': '1', 'type': 'host',
                     'content': '\n'.join(new), 'description': self.tag}}), 'Alias 생성')
                uid = result.get('uuid')
                if not uid:
                    raise ResponseError('Alias UUID가 없습니다.')
            if block:
                self.ensure_rules(created)
            applied = self.apply()
            _, saved = self.alias_config()
            saved_ips = contents(saved.get('content', '')) if saved else []
            if (ip in saved_ips) != block or self.member(ip, self.table()) != block:
                raise ResponseError('Alias 저장 내용과 실제 테이블의 적용 결과가 일치하지 않습니다.')
            if block and not self.check_rules():
                raise ResponseError('차단 규칙 설정을 재확인하지 못했습니다.')
        except Exception as exc:
            rollback_errors = []
            if touched:
                try:
                    if not uid:
                        uid, _ = self.alias_config()
                    if uid:
                        approved(self.call('POST', self.api('alias', 'set_item', 'setItem', '/' + uid),
                            {'alias': {'content': '\n'.join(old)}}), 'Alias 복원')
                    for rule_id in created:
                        approved(self.call('POST', self.api('filter', 'del_rule', 'delRule', '/' + rule_id), {}), '생성 규칙 복원')
                    self.apply()
                except Exception as rollback:
                    rollback_errors.append(str(rollback))
            raise ResponseError('차단 변경을 완료하지 못했습니다. ' + str(exc) +
                (' 설정 복원에도 실패했습니다. OPNsense에서 Alias와 규칙을 직접 확인하세요.' if rollback_errors else ''),
                {'cause': getattr(exc, 'detail', str(exc)), 'rollback_errors': rollback_errors,
                 'hint': 'OPNsense Alias/Filter API 권한 및 실제 설정을 확인하세요.'}) from exc
        state_warning = ''
        if block:
            try:
                # OPNsense parses CIDR filters as exact networks, not regexes.
                address = ipaddress.ip_address(ip)
                pattern = f"{address}/{address.max_prefixlen}"
                approved(self.call('POST', ['/api/diagnostics/firewall/kill_states',
                    '/api/diagnostics/firewall/killStates'], {'filter': pattern}), '기존 연결 종료')
            except Exception:
                state_warning = '차단 규칙은 적용됐지만 기존 연결 종료를 확인하지 못했습니다. 새 연결로 검증하세요.'
        return {'ok': True, 'apply': applied, 'state_warning': state_warning,
                'rule_created': bool(created), 'alias_created': config is None}
