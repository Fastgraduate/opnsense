import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import main
from tests.test_manual_response import FakeFirewall

class AutomaticEditTests(unittest.TestCase):
    def setUp(self):
        self.fake=FakeFirewall()
        self.fake.alias={'name':'auto_blocked_attackers','type':'host','enabled':'1','content':'192.168.0.60'}
        self.fake.runtime=['192.168.0.60']
        for p in [patch.object(main,'opnsense_request',self.fake),
                  patch.object(main,'get_firewall_or_404',return_value={'host':'https://192.168.0.9','elastic_url':'https://192.168.10.148:9200'}),
                  patch.dict(main.os.environ,{'SECURITY_AUTO_BLOCK_ALIAS_2':'auto_blocked_attackers'}),
                  patch.object(main,'_protected_manual_addresses',return_value=['192.168.0.3'])]:
            p.start();self.addCleanup(p.stop)
        self.client=TestClient(main.app)
    def test_add_list_remove_preserves_other(self):
        r=self.client.post('/api/firewalls/2/automatic-blocks',json={'source_ip':'192.168.0.6','force':True})
        self.assertEqual(r.status_code,200,r.text)
        data=self.client.get('/api/firewalls/2/automatic-blocks').json()
        self.assertTrue(data['editable'])
        self.assertTrue(all(r['can_remove'] for r in data['rows']))
        self.assertIn('192.168.0.6',[r['ip'] for r in data['rows']])
        r=self.client.delete('/api/firewalls/2/automatic-blocks/192.168.0.6')
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.fake.runtime,['192.168.0.60'])
    def test_protected_ip_denied(self):
        r=self.client.post('/api/firewalls/2/automatic-blocks',json={'source_ip':'192.168.0.3','force':True})
        self.assertEqual(r.status_code,400)
        self.assertEqual(self.fake.runtime,['192.168.0.60'])
    def test_failure_rolls_back(self):
        self.fake.fail_apply_once=True
        r=self.client.post('/api/firewalls/2/automatic-blocks',json={'source_ip':'192.168.0.6','force':True})
        self.assertEqual(r.status_code,502)
        self.assertEqual(self.fake.runtime,['192.168.0.60'])
    def test_dynamic_alias_is_not_modified(self):
        self.fake.alias['type']='urltable'
        r=self.client.post('/api/firewalls/2/automatic-blocks',json={'source_ip':'192.168.0.6','force':True})
        self.assertEqual(r.status_code,409)
