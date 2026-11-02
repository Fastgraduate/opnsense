"""Local server recovery only. Never exposed as an HTTP endpoint."""
import argparse
import time
from pathlib import Path
from dotenv import load_dotenv
try:
    from .auth import AuthStore
except ImportError:
    from auth import AuthStore
import os


def main():
    base = Path(__file__).resolve().parent
    load_dotenv(base / '.env')
    parser = argparse.ArgumentParser(description='서버 운영자용 인증 기기 복구')
    parser.add_argument('--reset-mfa', required=True, metavar='USERNAME')
    args = parser.parse_args()
    store = AuthStore(os.getenv('AUTH_DB_PATH') or base / 'data' / 'auth.sqlite3')
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT id FROM users WHERE username=?', (args.reset_mfa.strip().lower(),)).fetchone()
        if not row:
            raise SystemExit('계정을 찾을 수 없습니다.')
        db.execute("UPDATE users SET mfa_secret='',mfa_enabled=0,last_step=-1,updated_at=? WHERE id=?", (int(time.time()), row['id']))
        for table in ('sessions', 'challenges', 'recovery_codes'):
            db.execute(f'DELETE FROM {table} WHERE user_id=?', (row['id'],))
        db.execute('INSERT INTO audit_events(at,actor_id,action,method,route,status,client_ip) VALUES(?,?,?,?,?,?,?)',
                   (int(time.time()), row['id'], 'local_operator_mfa_reset', 'CLI', '', 200, 'local'))
    print('인증 연결과 기존 세션을 초기화했습니다. 다음 로그인에서 인증 앱을 다시 등록해야 합니다.')

if __name__ == '__main__':
    main()
