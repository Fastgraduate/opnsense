import base64
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.middleware.cors import CORSMiddleware
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import auth
from mfa_support import accepted_step

PASSWORD='Correct horse battery 2026!'
CODE='team-code-for-tests'
ORIGIN='http://localhost:5173'

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv('AUTH_DB_PATH', str(tmp_path/'auth.sqlite3'))
    monkeypatch.setenv('AUTH_REGISTRATION_CODE',CODE)
    app=FastAPI();auth.install_auth(app,tmp_path,[ORIGIN])
    app.add_middleware(CORSMiddleware,allow_origins=[ORIGIN],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
    @app.get('/api/firewalls')
    def get(): return []
    @app.post('/api/firewalls/1/rules')
    def mutate(): return {'ok':True}
    @app.post('/api/firewalls/1/security-alerts/search')
    def search(): return {'rows':[]}
    return TestClient(app),app


def register(c, username='adminuser'):
    r=c.post('/api/auth/register',json=dict(username=username,name=username,email=username+'@example.com',password=PASSWORD,registration_code=CODE,role='admin'))
    assert r.status_code==201,r.text


def begin(c,username='adminuser',remember=False):
    r=c.post('/api/auth/login',json=dict(username=username,password=PASSWORD,remember=remember))
    assert r.status_code==200,r.text
    return r.json()


def enroll(c,username='adminuser',remember=False):
    register(c,username);pending=begin(c,username,remember)
    assert pending['enrollment_required']
    r=c.post('/api/auth/mfa/complete',json={'challenge':pending['challenge'],'code':pyotp.TOTP(pending['setup']['secret']).now()})
    assert r.status_code==200,r.text
    result=r.json();result['secret']=pending['setup']['secret'];return result


def headers(result):
    return {'Authorization':'Bearer '+result['access_token'],'X-Dashboard-Request':'1','Origin':ORIGIN}


def stepup(result,index=0):return dict(current_password=PASSWORD,code=result['recovery_codes'][index])


def test_password_alone_cannot_access_and_failed_codes_count(env):
    c,app=env;register(c);p=begin(c)
    assert 'access_token' not in p and not c.cookies.get(auth.COOKIE)
    assert c.get('/api/firewalls',headers={'Authorization':'Bearer '+p['challenge']}).status_code==401
    for i in range(5):assert c.post('/api/auth/mfa/complete',json=dict(challenge=p['challenge'],code='invalid-code')).status_code==401
    assert c.post('/api/auth/mfa/complete',json=dict(challenge=p['challenge'],code=pyotp.TOTP(p['setup']['secret']).now())).status_code==401
    with app.state.auth_store.connect() as db:assert db.execute('SELECT attempts FROM challenges').fetchone()[0]==5


def test_expired_challenge(env):
    c,app=env;register(c);p=begin(c)
    with app.state.auth_store.connect() as db:db.execute('UPDATE challenges SET expires_at=0')
    assert c.post('/api/auth/mfa/complete',json=dict(challenge=p['challenge'],code=pyotp.TOTP(p['setup']['secret']).now())).status_code==401


def test_encryption_replay_and_one_use_recovery(env):
    c,app=env;r=enroll(c)
    with app.state.auth_store.connect() as db:
        row=db.execute('SELECT * FROM users').fetchone(); assert row['mfa_secret']!=r['secret'] and r['secret'] not in row['mfa_secret']
        assert db.execute('SELECT COUNT(*) FROM recovery_codes').fetchone()[0]==10
    p=begin(c)
    assert p['setup'] is None and not p['enrollment_required']
    assert c.post('/api/auth/mfa/complete',json=dict(challenge=p['challenge'],code=pyotp.TOTP(r['secret']).now())).status_code==401
    body=dict(challenge=p['challenge'],code=r['recovery_codes'][0])
    assert c.post('/api/auth/mfa/complete',json=body).status_code==200
    assert c.post('/api/auth/mfa/complete',json=body).status_code==401
    p=begin(c)
    assert c.post('/api/auth/mfa/complete',json=dict(challenge=p['challenge'],code=r['recovery_codes'][0])).status_code==401


def test_concurrent_recovery_only_one_success(env):
    c,app=env;r=enroll(c);p=begin(c)
    body=dict(challenge=p['challenge'],code=r['recovery_codes'][0])
    def run(_):return TestClient(app).post('/api/auth/mfa/complete',json=body).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:assert sorted(pool.map(run,[1,2]))==[200,401]


def test_remember_expiry_logout_csrf(env):
    c,app=env;r=enroll(c,remember=True)
    assert r['access_token'] is None and c.cookies.get(auth.COOKIE)
    assert c.get('/api/firewalls').status_code==200
    assert c.post('/api/firewalls/1/rules').status_code==403
    assert c.post('/api/firewalls/1/rules',headers={'X-Dashboard-Request':'1','Origin':ORIGIN}).status_code==200
    assert c.post('/api/firewalls/1/rules',headers={'X-Dashboard-Request':'1','Origin':'https://evil.test'}).status_code==403
    token=c.cookies.get(auth.COOKIE)
    assert c.post('/api/auth/logout',headers={'X-Dashboard-Request':'1'}).status_code==200
    assert c.get('/api/firewalls',headers={'Authorization':'Bearer '+token}).status_code==401


def test_viewer_role_policy_and_admin_no_self_elevation(env):
    c,app=env;admin=enroll(c);viewer=enroll(c,'vieweruser');h=headers(viewer)
    assert admin['user']['role']=='admin' and viewer['user']['role']=='viewer'
    assert c.get('/api/firewalls',headers=h).status_code==200
    assert c.post('/api/firewalls/1/security-alerts/search',headers=h).status_code==200
    assert c.post('/api/firewalls/1/rules',headers=h).status_code==403
    assert c.get('/api/auth/admin/users',headers=h).status_code==403
    assert c.get('/api/auth/admin/audit',headers=h).status_code==403
    assert c.put('/api/auth/me',json=dict(name='viewer',email='a@example.com',role='admin'),headers=h).json()['role']=='viewer'
    assert c.put('/api/auth/admin/users/2/role',json=dict(role='admin',**stepup(viewer)),headers=h).status_code==403


def test_role_change_revokes_sessions_and_last_admin_guard(env):
    c,app=env;admin=enroll(c);viewer=enroll(c,'vieweruser');h=headers(admin)
    assert c.put('/api/auth/admin/users/1/role',json=dict(role='viewer',**stepup(admin)),headers=h).status_code==409
    assert c.put('/api/auth/admin/users/2/role',json=dict(role='admin',**stepup(admin)),headers=h).status_code==200
    assert c.get('/api/firewalls',headers=headers(viewer)).status_code==401
    p=begin(c,'vieweruser');r=c.post('/api/auth/mfa/complete',json=dict(challenge=p['challenge'],code=viewer['recovery_codes'][0])).json()
    assert r['user']['role']=='admin'


def test_reauth_required_password_change_revoke_every_session_and_challenge(env):
    c,app=env;r=enroll(c);h=headers(r);p=begin(c)
    assert c.put('/api/auth/password',json=dict(current_password=PASSWORD,new_password='Changed password 2026!',code='wrong-code'),headers=h).status_code==400
    assert c.put('/api/auth/password',json=dict(new_password='Changed password 2026!',**stepup(r)),headers=h).status_code==200
    assert c.get('/api/firewalls',headers=h).status_code==401
    assert c.post('/api/auth/mfa/complete',json=dict(challenge=p['challenge'],code=r['recovery_codes'][1])).status_code==401


def test_reset_requires_factor_and_forces_new_enrollment(env):
    c,app=env;r=enroll(c);h=headers(r)
    assert c.post('/api/auth/mfa/reset',json=dict(current_password=PASSWORD,code='wrong-code'),headers=h).status_code==400
    assert c.post('/api/auth/mfa/reset',json=stepup(r),headers=h).status_code==200
    assert c.get('/api/firewalls',headers=h).status_code==401
    p=begin(c);assert p['enrollment_required'] and p['setup']['secret']!=r['secret']


def test_rotate_recovery_and_audit_contains_no_secrets(env):
    c,app=env;r=enroll(c);h=headers(r)
    assert c.post('/api/auth/mfa/recovery-codes',json=stepup(r),headers=h).status_code==200
    p=begin(c)
    assert c.post('/api/auth/mfa/complete',json=dict(challenge=p['challenge'],code=r['recovery_codes'][1])).status_code==401
    c.post('/api/firewalls/1/rules?password=NEVER_RECORD_ME',json={'password':PASSWORD},headers=h)
    audit=c.get('/api/auth/admin/audit',headers=h)
    assert audit.status_code==200
    assert any(row['action']=='mfa_enrolled_login_success' for row in audit.json()['rows'])
    for secret in [PASSWORD,r['secret'],p['challenge'],r['access_token'],'NEVER_RECORD_ME',*r['recovery_codes']]:assert secret not in audit.text


def test_server_expiry_and_restart(env):
    c,app=env;r=enroll(c);store=app.state.auth_store
    restarted=auth.AuthStore(store.path,CODE);assert restarted.session(r['access_token'])
    with store.connect() as db:db.execute('UPDATE sessions SET expires_at=0')
    assert c.get('/api/firewalls',headers=headers(r)).status_code==401


def test_legacy_migration_preserves_users_promotes_first_revokes_sessions(tmp_path,monkeypatch):
    dbpath=tmp_path/'old.sqlite3'
    with sqlite3.connect(dbpath) as db:
        db.executescript('''CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,name TEXT,email TEXT,password_hash TEXT,created_at INTEGER,updated_at INTEGER);
        CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER,expires_at INTEGER,remember INTEGER);
        INSERT INTO users VALUES(3,'oldadmin','이름','a@example.com','HASH',1,1);
        INSERT INTO users VALUES(8,'oldmember','이름','b@example.com','HASH2',1,1);
        INSERT INTO sessions VALUES('oldtoken',3,9999999999,1);''')
    store=auth.AuthStore(dbpath,CODE)
    with store.connect() as db:
        rows=db.execute('SELECT * FROM users ORDER BY id').fetchall()
        assert rows[0]['role']=='admin' and rows[1]['role']=='viewer'
        assert rows[0]['password_hash']=='HASH'
        assert db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]==0
    # Repeated startup must not re-promote a different account.
    auth.AuthStore(dbpath,CODE)


def test_rfc6238_vector_and_replay():
    secret=base64.b32encode(b'12345678901234567890').decode()
    assert accepted_step(secret,'287082',now=59)==1
    assert accepted_step(secret,'287082',last_step=1,now=59) is None
    assert accepted_step(secret,'000000',now=59) is None


def test_lost_key_fails_closed(env):
    c,app=env;enroll(c);store=app.state.auth_store
    (store.path.parent/'mfa_encryption.key').unlink()
    with pytest.raises(RuntimeError,match='key missing'):auth.AuthStore(store.path,CODE)
