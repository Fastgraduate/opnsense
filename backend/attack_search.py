"""Read-only SQL over a bounded snapshot of the real detection stream."""
import json
import sqlite3

COLUMNS = ['id', 'timestamp', 'source_ip', 'destination_ip', 'source_port',
           'destination_port', 'protocol', 'action', 'rule', 'attack_type',
           'main_result_display', 'secondary_result_display', 'risk', 'raw']


def search_rows(rows, query):
    db = sqlite3.connect(':memory:')
    try:
        db.execute('CREATE TABLE logs (' + ','.join('"'+k+'" TEXT' for k in COLUMNS) + ')')
        values = []
        for row in rows:
            ml = row.get('ml') or {}
            raw = row.get('raw') or {}
            def nested(path):
                current = raw
                for key in path.split('.'):
                    if not isinstance(current, dict): return ''
                    current = current.get(key, '')
                return current
            data = {**row,
                    'protocol': row.get('protocol') or nested('network.transport') or nested('suricata.eve.proto') or nested('proto'),
                    'action': row.get('action') or nested('event.action') or nested('suricata.eve.alert.action'),
                    'source_port': row.get('source_port') or nested('source.port'),
                    'destination_port': row.get('destination_port') or nested('destination.port'),
                    'risk': ml.get('final_risk') or ml.get('risk_label') or row.get('final_risk'), 'attack_type': ml.get('prediction') or row.get('category'),
                    'main_result_display': ml.get('main_result_display') or row.get('main_result_display'),
                    'secondary_result_display': ml.get('secondary_result_display') or row.get('secondary_result_display')}
            values.append([json.dumps(data.get(k), ensure_ascii=False) if isinstance(data.get(k), (dict,list))
                           else str(data.get(k) or '') for k in COLUMNS])
        db.executemany('INSERT INTO logs VALUES ('+','.join('?' for _ in COLUMNS)+')', values)
        # Disallow writes, ATTACH, PRAGMA, external tables and extension/file functions.
        funcs = {'count','sum','avg','min','max','lower','upper','length','coalesce','ifnull','round','like','substr','abs'}
        def authorize(action, arg1, arg2, *_):
            if action == sqlite3.SQLITE_SELECT: return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ and arg1 == 'logs': return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_FUNCTION and (arg2 or '').lower() in funcs: return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        db.set_authorizer(authorize)
        budget = [0]
        def stop():
            budget[0] += 1
            return budget[0] > 1000
        db.set_progress_handler(stop, 1000)
        cursor = db.execute(query)
        columns = [x[0] for x in cursor.description or []]
        if len(columns) != len(set(columns)): raise ValueError('중복 컬럼에는 AS로 다른 이름을 지정하세요.')
        found = cursor.fetchmany(501)
        return {'columns': columns, 'rows': [dict(zip(columns,r)) for r in found[:500]],
                'result_truncated': len(found)>500}
    finally:
        db.close()
