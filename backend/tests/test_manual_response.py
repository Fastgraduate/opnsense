"""Offline OPNsense contract/failure tests: python -m unittest tests.test_manual_response -v."""
import copy
import unittest
from manual_response import ManualResponse, ResponseError, value


class FakeFirewall:
    def __init__(self):
        self.alias = None
        self.rules = {}
        self.runtime = []
        self.fail_apply_once = False
        self.fail_kill = False
        self.no_runtime = False
        self.killed = []
        self.calls = []

    def __call__(self, target, method, path, json_data=None):
        self.calls.append((method, path, copy.deepcopy(json_data)))
        path = path.split('?')[0]
        if '/alias/search_item' in path:
            return {'rows': [{'uuid': 'alias-1', 'name': self.alias['name']}] if self.alias else []}
        if '/alias/get_item/' in path:
            return {'alias': copy.deepcopy(self.alias)}
        if path.endswith('/alias/add_item'):
            self.alias = copy.deepcopy(json_data['alias'])
            return {'result': 'saved', 'uuid': 'alias-1'}
        if '/alias/set_item/' in path:
            self.alias.update(json_data['alias'])
            return {'result': 'saved'}
        if path.endswith('/alias/reconfigure'):
            self.runtime = [] if self.no_runtime else self.alias['content'].split()
            return {'status': 'ok'}
        if '/alias_util/list/' in path:
            return {'rows': [{'ip': ip} for ip in self.runtime]}
        if path.endswith('/filter/search_rule'):
            return {'rows': [dict(r, uuid=k) for k, r in self.rules.items()]}
        if '/filter/get_rule/' in path:
            return {'rule': copy.deepcopy(self.rules[path.split('/')[-1]])}
        if path.endswith('/filter/add_rule'):
            uid = 'rule-' + str(len(self.rules) + 1)
            self.rules[uid] = copy.deepcopy(json_data['rule'])
            return {'result': 'saved', 'uuid': uid}
        if '/filter/del_rule/' in path:
            del self.rules[path.split('/')[-1]]
            return {'result': 'deleted'}
        if path.endswith('/filter/apply'):
            if self.fail_apply_once:
                self.fail_apply_once = False
                return {'status': 'failed'}
            return {'status': 'OK\n'}
        if path.endswith('/firewall/kill_states'):
            if self.fail_kill:
                raise RuntimeError('permission denied')
            self.killed.append(json_data['filter'])
            return {'result': 'ok', 'dropped_states': 2}
        raise AssertionError(path)


class ManualResponseTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeFirewall()
        self.service = ManualResponse(self.fake, {'host': 'https://192.168.0.9',
            'elastic_url': 'https://192.168.10.148:9200'}, 'blocked_attackers')

    def test_block_persists_rules_table_and_exact_state_filter(self):
        result = self.service.change('192.168.0.6', True)
        self.assertTrue(result['ok'])
        self.assertEqual(self.fake.alias['content'], '192.168.0.6')
        self.assertEqual(len(self.fake.rules), 2)
        self.assertEqual(self.fake.killed, ['192.168.0.6/32'])
        self.assertTrue(self.service.check_rules())

    def test_duplicate_block_and_unblock_preserve_other_hosts(self):
        self.service.change('192.168.0.6', True)
        self.service.change('192.168.0.60', True)
        self.service.change('192.168.0.6', True)
        self.assertEqual(len(self.fake.rules), 2)
        self.service.change('192.168.0.6', False)
        self.assertEqual(self.fake.runtime, ['192.168.0.60'])
        self.assertEqual(self.fake.alias['content'], '192.168.0.60')
        self.service.change('192.168.0.60', False)
        self.assertEqual(self.fake.runtime, [])

    def test_apply_failure_rolls_back(self):
        self.service.change('192.168.0.60', True)
        self.fake.fail_apply_once = True
        with self.assertRaises(ResponseError):
            self.service.change('192.168.0.6', True)
        self.assertEqual(self.fake.runtime, ['192.168.0.60'])
        self.assertEqual(self.fake.alias['content'], '192.168.0.60')

    def test_readback_failure_is_not_success(self):
        self.fake.no_runtime = True
        with self.assertRaises(ResponseError):
            self.service.change('192.168.0.6', True)
        self.assertEqual(self.fake.alias['content'], '')
        self.assertEqual(self.fake.rules, {})

    def test_state_failure_reports_warning(self):
        self.fake.fail_kill = True
        result = self.service.change('192.168.0.6', True)
        self.assertTrue(result['state_warning'])
        self.assertEqual(self.fake.runtime, ['192.168.0.6'])

    def test_protected_addresses_ignore_force(self):
        for ip in ['127.0.0.1', '0.0.0.0', '224.0.0.1', '169.254.1.2',
                   '192.168.0.9', '192.168.10.148', '192.168.0.3']:
            with self.subTest(ip=ip), self.assertRaises(ResponseError):
                self.service.validate_address(ip, True, ['192.168.0.3'])
        with self.assertRaises(ResponseError):
            self.service.validate_address('192.168.0.6', False)
        self.assertEqual(self.service.validate_address('192.168.0.6', True), '192.168.0.6')

    def test_ipv6_exact_host_and_selection_decode(self):
        self.service.change('2001:db8::6', True)
        self.assertEqual(self.fake.killed, ['2001:db8::6/128'])
        self.assertFalse(self.service.member('2001:db8::60', self.service.table()))
        self.assertEqual(value({'inet': {'selected': 0}, 'inet46': {'selected': 1}}), 'inet46')

    def test_changed_admin_rule_is_not_overwritten(self):
        self.service.change('192.168.0.60', True)
        self.fake.rules['rule-1']['quick'] = '0'
        with self.assertRaises(ResponseError):
            self.service.change('192.168.0.6', True)
        self.assertEqual(self.fake.rules['rule-1']['quick'], '0')
        self.assertEqual(self.fake.runtime, ['192.168.0.60'])

    def test_no_retry_on_timeout(self):
        calls = []
        def timeout(*args, **kwargs):
            calls.append(args)
            raise TimeoutError('timeout')
        service = ManualResponse(timeout, {}, 'blocked_attackers')
        with self.assertRaises(TimeoutError):
            service.call('POST', ['/snake', '/camel'], {})
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
