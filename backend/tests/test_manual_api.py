"""FastAPI routes with an in-memory firewall; no real device requests."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
import main
from tests.test_manual_response import FakeFirewall

class ManualApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fake = FakeFirewall()
        target = {'id': 2, 'host': 'https://192.168.0.9', 'elastic_url': 'https://192.168.10.148:9200'}
        for p in [patch.object(main, 'opnsense_request', self.fake),
                  patch.object(main, 'get_firewall_or_404', return_value=target),
                  patch.object(main, 'MANUAL_BLOCK_FILE', Path(self.temp.name) / 'history.json'),
                  patch.object(main, '_protected_manual_addresses', return_value=['192.168.0.3'])]:
            p.start()
            self.addCleanup(p.stop)
        self.client = TestClient(main.app)

    def test_block_list_unblock(self):
        r = self.client.post('/api/firewalls/2/security-alerts/event-1/block', json={'source_ip': '192.168.0.6', 'force': True})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()['ok'])
        listing = self.client.get('/api/firewalls/2/manual-blocks').json()
        self.assertEqual(listing['count'], 1)
        self.assertEqual(listing['rows'][0]['status'], 'blocked')
        r = self.client.delete('/api/firewalls/2/manual-blocks/192.168.0.6')
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.client.get('/api/firewalls/2/manual-blocks').json()['rows'], [])

    def test_protected_ip_400_without_mutation(self):
        r = self.client.post('/api/firewalls/2/security-alerts/event-1/block', json={'source_ip': '192.168.10.148', 'force': True})
        self.assertEqual(r.status_code, 400)
        self.assertIn('보호 주소', r.json()['detail']['message'])
        self.assertEqual(self.fake.calls, [])

    def test_failure_502_without_false_history(self):
        self.fake.fail_apply_once = True
        r = self.client.post('/api/firewalls/2/security-alerts/event-1/block', json={'source_ip': '192.168.0.6', 'force': True})
        self.assertEqual(r.status_code, 502)
        self.assertFalse(main.MANUAL_BLOCK_FILE.exists())
        self.assertEqual(self.fake.runtime, [])

if __name__ == '__main__':
    unittest.main()
