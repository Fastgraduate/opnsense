import unittest
import sqlite3
from attack_search import search_rows

class SearchTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{'source_ip': '192.168.0.6', 'ml': {'prediction': 'SQL_Injection', 'main_result_display': 'SQL_Injection 95%'}},
                     {'source_ip': '192.168.0.60', 'ml': {'prediction': 'Normal'}},
                     {'source_ip': '192.168.0.6', 'ml': {'prediction': 'SQL_Injection'}}]
    def test_sql_filters_and_groups(self):
        result=search_rows(self.rows, "SELECT source_ip, COUNT(*) AS count FROM logs WHERE attack_type='SQL_Injection' GROUP BY source_ip")
        self.assertEqual(result['rows'], [{'source_ip':'192.168.0.6','count':2}])
    def test_mutations_are_denied(self):
        for sql in ["DELETE FROM logs", "DROP TABLE logs", "ATTACH DATABASE '/tmp/test' AS other", "PRAGMA database_list", "SELECT load_extension('x')", "SELECT * FROM sqlite_master"]:
            with self.subTest(sql=sql), self.assertRaises(sqlite3.Error): search_rows(self.rows,sql)
    def test_result_limit(self):
        result=search_rows(self.rows*200, 'SELECT * FROM logs')
        self.assertEqual(len(result['rows']),500)
        self.assertTrue(result['result_truncated'])
    def test_normal_does_not_match_attack(self):
        self.assertEqual(len(search_rows(self.rows,"SELECT * FROM logs WHERE attack_type='Normal'")['rows']),1)

class ApiTests(unittest.TestCase):
    def test_page_source_and_cursor(self):
        from unittest.mock import patch
        import main
        pages=[{'rows':[{'source_ip':'one'}], 'has_more':True, 'next_cursor':'next', 'total':2},
               {'rows':[{'source_ip':'two'}], 'has_more':False, 'total':2}]
        with patch.object(main,'get_security_alert_page',side_effect=pages) as page, patch.object(main,'get_firewall_or_404',return_value={'log_index':'suricata-filtered-*'}):
            result=main.search_attack_logs(2,main.AttackSearchBody(sql="SELECT COUNT(*) AS count FROM logs"))
            self.assertEqual(result['rows'],[{'count':2}])
            self.assertEqual(page.call_args_list[1].kwargs['cursor'],'next')
            self.assertEqual(page.call_args_list[0].kwargs['result'],'attack')
            self.assertEqual(page.call_args_list[0].kwargs['to_ms'],page.call_args_list[1].kwargs['to_ms'])
    def test_automatic_unconfigured_and_separate(self):
        from unittest.mock import patch
        import main
        with patch.object(main,'get_firewall_or_404',return_value={}), patch.dict(main.os.environ,{},clear=True):
            self.assertFalse(main.list_automatic_blocks(2)['available'])
            with patch.dict(main.os.environ,{'SECURITY_AUTO_BLOCK_ALIAS':'blocked_attackers'}), self.assertRaises(main.HTTPException):
                main.list_automatic_blocks(2)
