import ast
import unittest
from pathlib import Path
from elk_results import decorate, stored_analysis, is_attack

class DisplayTests(unittest.TestCase):
    def test_top_two_stored_result(self):
        ml = stored_analysis({'raw': {'ml': {'main_result_display':'SQL_Injection · 68.3%', 'secondary_result_display':'2순위 Cross_Site_Scripting · 24.7%', 'show_secondary':True}}})
        self.assertEqual(ml['prediction'], 'SQL_Injection')
        self.assertTrue(ml['show_secondary'])
        self.assertEqual(ml['risk_score'], None)
    def test_normal_and_missing_are_distinct(self):
        normal = decorate({'_id':'1','raw':{'main_result_display':'Normal · 94.2%', 'show_secondary':False},'event_type':'alert'})
        self.assertFalse(is_attack(normal))
        self.assertTrue(normal['ml']['available'])
        missing = decorate({'_id':'2','event_type':'alert','raw':{}})
        self.assertFalse(missing['ml']['available'])
        self.assertTrue(is_attack(missing))
    def test_flat_fields_and_false_string(self):
        ml = stored_analysis({'raw': {'ml.main_result_display':['HOST_Scan · 85.0%'], 'ml.show_secondary':'false','ml.secondary_result_display':'unused', 'ml.risk.score':42}})
        self.assertFalse(ml['show_secondary'])
        self.assertEqual(ml['secondary_result_display'],'')
        self.assertEqual(ml['risk_score'],42)
    def test_stable_distinct_document_ids(self):
        a = decorate({'_index':'a','_id':'one','id':'transient'})
        self.assertEqual(a['id'],decorate({'_index':'a','_id':'one','id':'new'})['id'])
        self.assertNotEqual(a['id'],decorate({'_index':'b','_id':'one'})['id'])
    def test_json_original(self):
        ml=stored_analysis({'raw':{'event':{'original':'{"main_result_display":"Normal · 99.0%"}'}}})
        self.assertEqual(ml['prediction'],'Normal')
    def test_read_endpoint_does_not_infer_or_write(self):
        source=Path(__file__).with_name('main.py').read_text()
        tree=ast.parse(source)
        endpoints=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='get_security_alerts']
        node=endpoints[0];node.decorator_list=[]
        rows=[{'_id':'one','raw':{'final_pred':'Normal'}},{'_id':'two','raw':{'main_result_display':'SQL_Injection · 96.0%'}},{'_id':'two','raw':{'main_result_display':'SQL_Injection · 96.0%'}}]
        ns={'decorate':decorate,'is_attack':is_attack,'get_firewall_or_404':lambda fid:{'log_index':'test'},'serialize_firewall':lambda t:t,'search_firewall_events':lambda **kw:rows}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'isolated-endpoint','exec'),ns)
        result=ns['get_security_alerts'](1)
        self.assertEqual(len(result['rows']),1)
        self.assertEqual(len(ns['get_security_alerts'](1,include_all_events=True)['rows']),2)
        self.assertNotIn('predict_event',source)
        self.assertNotIn('ml_v32_service',source)
        self.assertNotIn('security-automation/evaluate',source)
        self.assertNotIn('security-automation/cleanup',source)

if __name__=='__main__': unittest.main()
