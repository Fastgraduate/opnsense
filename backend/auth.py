"""Local account authentication. No firewall credentials are stored in this database."""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import pyotp
from typing import Literal
try:
    from .mfa_support import load_cipher, accepted_step, provisioning
except ImportError:
    from mfa_support import load_cipher, accepted_step, provisioning
from contextlib import contextmanager
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

COOKIE = 'opnsense_session'
PUBLIC = {'/api/auth/status', '/api/auth/register', '/api/auth/login', '/api/auth/mfa/complete'}
SAFE = {'GET', 'HEAD', 'OPTIONS'}


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=5, dklen=32).hex()
    return f'scrypt$16384$8$5${salt}${digest}'


def verify_password(password, encoded):
    try:
        return hmac.compare_digest(password_hash(password, encoded.split('$')[-2]), encoded)
    except (ValueError, IndexError):
        return False


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()


class RegisterBody(BaseModel):
    username: str = Field(min_length=4, max_length=32)
    name: str = Field(min_length=1, max_length=50)
    email: str = Field(max_length=254)
    password: str = Field(min_length=10, max_length=128)
    registration_code: str = Field(default='', max_length=256)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)
    remember: bool = False


class CompleteBody(BaseModel):
    challenge: str = Field(min_length=20, max_length=256)
    code: str = Field(min_length=6, max_length=64)


class StepUpBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=64)


class RoleBody(StepUpBody):
    role: Literal['admin', 'viewer']


class ProfileBody(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    email: str = Field(max_length=254)


class PasswordBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=10, max_length=128)
    code: str = Field(min_length=6, max_length=64)


class AuthStore:
    def __init__(self, path, registration_code=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Shared secret limits registration to members of the monitoring team.
        code_path = self.path.parent / 'registration_code.txt'
        self.registration_code = registration_code or os.getenv('AUTH_REGISTRATION_CODE', '').strip()
        if not self.registration_code:
            try:
                fd = os.open(code_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, 'w') as file:
                    file.write(secrets.token_urlsafe(24))
            except FileExistsError:
                pass
            self.registration_code = code_path.read_text().strip()
        if not self.registration_code:
            raise RuntimeError('AUTH_REGISTRATION_CODE must not be empty')
        self.dummy_hash = password_hash(secrets.token_urlsafe(32))
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                  name TEXT NOT NULL, email TEXT NOT NULL, password_hash TEXT NOT NULL,
                  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                  expires_at INTEGER NOT NULL, remember INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
                CREATE TABLE IF NOT EXISTS attempts (bucket TEXT NOT NULL, at INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS attempts_bucket ON attempts(bucket, at);
            ''')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            fields = {row['name'] for row in db.execute('PRAGMA table_info(users)')}
            upgrading = 'role' not in fields
            for name, definition in [
                ('role', "TEXT NOT NULL DEFAULT 'viewer'"),
                ('mfa_secret', "TEXT NOT NULL DEFAULT ''"),
                ('mfa_enabled', 'INTEGER NOT NULL DEFAULT 0'),
                ('last_step', 'INTEGER NOT NULL DEFAULT -1'),
            ]:
                if name not in fields:
                    db.execute(f'ALTER TABLE users ADD COLUMN {name} {definition}')
            db.execute('''CREATE TABLE IF NOT EXISTS challenges (
                token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                expires_at INTEGER NOT NULL, remember INTEGER NOT NULL, password_version TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, pending_secret TEXT NOT NULL DEFAULT '')''')
            db.execute('CREATE TABLE IF NOT EXISTS recovery_codes(user_id INTEGER NOT NULL REFERENCES users(id), code_hash TEXT NOT NULL UNIQUE)')
            db.execute('''CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
                actor_id INTEGER, action TEXT NOT NULL, method TEXT NOT NULL,
                route TEXT NOT NULL, status INTEGER NOT NULL, client_ip TEXT NOT NULL)''')
            if upgrading:
                first = db.execute('SELECT id FROM users ORDER BY id LIMIT 1').fetchone()
                if first:
                    db.execute("UPDATE users SET role='admin' WHERE id=?", (first['id'],))
                db.execute('DELETE FROM sessions')
                db.execute("INSERT INTO audit_events(at,action,method,route,status,client_ip) VALUES(?, 'security_migration', 'SYSTEM', '', 200, 'local')", (int(time.time()),))
            has_secrets = db.execute("SELECT 1 FROM users WHERE mfa_secret<>'' LIMIT 1").fetchone() is not None
        self.cipher = load_cipher(self.path.parent, has_secrets)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def throttle(self, *buckets, limit=10):
        now = int(time.time())
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM attempts WHERE at < ?', (now - 900,))
            for bucket in buckets:
                count = db.execute('SELECT COUNT(*) FROM attempts WHERE bucket=?', (fingerprint(bucket),)).fetchone()[0]
                if count >= limit:
                    raise HTTPException(429, '요청 횟수를 초과했습니다. 15분 후 다시 시도하세요.', headers={'Retry-After': '900'})
            db.executemany('INSERT INTO attempts VALUES (?, ?)', [(fingerprint(b), now) for b in buckets])

    @staticmethod
    def public_user(row):
        return {key: row[key] for key in ('id', 'username', 'name', 'email', 'created_at', 'updated_at', 'role', 'mfa_enabled')}

    def session(self, token):
        if not token or len(token) > 256:
            return None
        with self.connect() as db:
            row = db.execute('''SELECT u.*, s.expires_at, s.remember FROM sessions s
                JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.mfa_enabled=1''',
                (fingerprint(token), int(time.time()))).fetchone()
        return dict(row) if row else None

    def revoke(self, token):
        if token:
            with self.connect() as db:
                db.execute('DELETE FROM sessions WHERE token_hash=?', (fingerprint(token),))

    def audit(self, actor_id, action, method, route, status, client_ip):
        with self.connect() as db:
            db.execute('INSERT INTO audit_events(at,actor_id,action,method,route,status,client_ip) VALUES(?,?,?,?,?,?,?)',
                       (int(time.time()), actor_id, action, method, route[:200], status, client_ip[:64]))

    def consume_factor(self, db, user, code):
        code = code.strip()
        if len(code) == 6 and code.isdigit():
            if not user['mfa_enabled']:
                return False
            secret = self.cipher.decrypt(user['mfa_secret'].encode()).decode()
            step = accepted_step(secret, code, user['last_step'])
            if step is None:
                return False
            db.execute('UPDATE users SET last_step=? WHERE id=?', (step, user['id']))
            return True
        digest = fingerprint(code.replace('-', '').lower())
        return db.execute('DELETE FROM recovery_codes WHERE user_id=? AND code_hash=?', (user['id'], digest)).rowcount == 1

    def new_recovery_codes(self, db, user_id):
        codes = [secrets.token_hex(10) for _ in range(10)]
        db.execute('DELETE FROM recovery_codes WHERE user_id=?', (user_id,))
        db.executemany('INSERT INTO recovery_codes VALUES(?,?)', [(user_id, fingerprint(code)) for code in codes])
        return ['-'.join(code[i:i+5] for i in range(0, 20, 5)) for code in codes]


def clean_profile(name, email):
    name, email = name.strip(), email.strip()
    if not name or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        raise HTTPException(400, '이름과 올바른 이메일 주소를 입력하세요.')
    return name, email


def install_auth(app, base_dir, origins):
    store = AuthStore(os.getenv('AUTH_DB_PATH') or Path(base_dir) / 'data' / 'auth.sqlite3')
    app.state.auth_store = store
    secure = os.getenv('AUTH_COOKIE_SECURE', 'false').lower() == 'true'
    remember_days = max(1, min(30, int(os.getenv('AUTH_REMEMBER_DAYS', '7'))))
    normal_seconds = 8 * 60 * 60
    router = APIRouter(prefix='/api/auth', tags=['Authentication'])

    def token_from(request):
        auth = request.headers.get('authorization', '')
        if auth.startswith('Bearer '):
            return auth[7:], False
        return request.cookies.get(COOKIE, ''), True

    def clear_cookie(response):
        response.delete_cookie(COOKIE, path='/', secure=secure, httponly=True, samesite='lax')

    def viewer_allowed(method, path):
        if path.startswith('/api/auth/'):
            return not path.startswith('/api/auth/admin/')
        if method in {'GET', 'HEAD'}:
            return True
        # These POST APIs only query logs; all other mutations are denied by default.
        return method == 'POST' and bool(re.fullmatch(
            r'/api/firewalls/[0-9]+/(opnsense-logs|event-logs|security-alerts/search)', path))

    @app.middleware('http')
    async def authenticate(request: Request, call_next):
        path = request.url.path.rstrip('/') or '/'
        protected = path.startswith('/api/') or path in {'/docs', '/redoc', '/openapi.json', '/docs/oauth2-redirect'}
        actor = None
        async def finish(response, action=None):
            if protected:
                response.headers['Cache-Control'] = 'no-store'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            if secure:
                response.headers['Strict-Transport-Security'] = 'max-age=31536000'
            should_audit = protected and request.method != 'OPTIONS' and (
                request.method not in SAFE or response.status_code >= 400)
            if should_audit:
                route = (path if request.scope.get('route') else '') or ('/api/auth/unknown' if path.startswith('/api/auth/') else '/api/unknown')
                # Deliberately exclude query strings, bodies, cookies, OTPs and tokens.
                await run_in_threadpool(store.audit, actor, action or getattr(request.state, 'audit_action', 'api_request'),
                                        request.method, route, response.status_code, request.client.host)
            return response
        if request.method not in SAFE and protected:
            origin = request.headers.get('origin')
            if origin and origin not in origins:
                return await finish(JSONResponse({'detail': '허용되지 않은 요청 출처입니다.'}, status_code=403), 'origin_denied')
        if protected and path not in PUBLIC and request.method != 'OPTIONS':
            token, cookie_auth = token_from(request)
            session = await run_in_threadpool(store.session, token)
            if not session:
                response = JSONResponse({'detail': '로그인이 필요하거나 로그인 시간이 만료되었습니다.'}, status_code=401)
                clear_cookie(response)
                return await finish(response, 'authentication_denied')
            actor = session['id']
            if cookie_auth and request.method not in SAFE and request.headers.get('x-dashboard-request') != '1':
                return await finish(JSONResponse({'detail': '요청 검증에 실패했습니다.'}, status_code=403), 'csrf_denied')
            if session['role'] != 'admin' and not viewer_allowed(request.method, path):
                return await finish(JSONResponse({'detail': '관리자 권한이 필요합니다.'}, status_code=403), 'permission_denied')
            request.state.auth = session
            request.state.auth_token = token
        try:
            response = await call_next(request)
        except Exception:
            await run_in_threadpool(store.audit, actor, 'server_error', request.method,
                                    getattr(request.scope.get('route'), 'path', '/api/unknown'), 500, request.client.host)
            raise
        actor = getattr(request.state, 'audit_actor', actor)
        return await finish(response)

    @router.get('/status')
    def status():
        return {'registration_code_required': True, 'remember_days': remember_days, 'mfa_required': True}

    @router.post('/register', status_code=201)
    def register(body: RegisterBody, request: Request):
        store.throttle('register:' + request.client.host, limit=10)
        if not hmac.compare_digest(body.registration_code.encode(), store.registration_code.encode()):
            raise HTTPException(403, '가입 코드가 올바르지 않습니다. 운영자에게 확인하세요.')
        username = body.username.strip().lower()
        if not re.fullmatch(r'[a-z0-9_]{4,32}', username):
            raise HTTPException(400, '아이디는 영문 소문자·숫자·밑줄 4~32자로 입력하세요.')
        name, email = clean_profile(body.name, body.email)
        encoded = password_hash(body.password)
        now = int(time.time())
        try:
            with store.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                role = 'viewer' if db.execute('SELECT 1 FROM users LIMIT 1').fetchone() else 'admin'
                user_id = db.execute('INSERT INTO users(username,name,email,password_hash,created_at,updated_at,role) VALUES(?,?,?,?,?,?,?)',
                           (username, name, email, encoded, now, now, role)).lastrowid
                request.state.audit_actor = user_id
                request.state.audit_action = 'register_success'
        except sqlite3.IntegrityError:
            raise HTTPException(409, '이미 사용 중인 아이디입니다.')
        return {'ok': True, 'message': '회원가입이 완료되었습니다. 로그인해 주세요.'}

    @router.post('/login')
    def login(body: LoginBody, request: Request, response: Response):
        username = body.username.strip().lower()
        store.throttle('login-ip:' + request.client.host, limit=30)
        store.throttle('login-user:' + username, limit=10)
        with store.connect() as db:
            user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        valid = verify_password(body.password, user['password_hash'] if user else store.dummy_hash)
        if not user or not valid:
            raise HTTPException(401, '아이디 또는 비밀번호가 올바르지 않습니다.')
        challenge = secrets.token_urlsafe(32)
        secret = pyotp.random_base32() if not user['mfa_enabled'] else ''
        encrypted = store.cipher.encrypt(secret.encode()).decode() if secret else ''
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM users WHERE id=?', (user['id'],)).fetchone()
            if current['password_hash'] != user['password_hash'] or current['mfa_secret'] != user['mfa_secret']:
                raise HTTPException(409, '계정 보안 설정이 변경되었습니다. 다시 로그인하세요.')
            db.execute('DELETE FROM challenges WHERE expires_at<=? OR user_id=?', (int(time.time()), user['id']))
            db.execute('INSERT INTO challenges(token_hash,user_id,expires_at,remember,password_version,pending_secret) VALUES(?,?,?,?,?,?)',
                       (fingerprint(challenge), user['id'], int(time.time()) + 300, int(body.remember), fingerprint(user['password_hash']), encrypted))
        request.state.audit_actor = user['id']
        request.state.audit_action = 'password_verified_mfa_pending'
        # No session cookie or access token exists until the second factor is verified.
        return {'mfa_required': True, 'challenge': challenge, 'enrollment_required': not bool(user['mfa_enabled']),
                'setup': provisioning(secret, user['username']) if secret else None}

    @router.post('/mfa/complete')
    def complete_mfa(body: CompleteBody, request: Request, response: Response):
        store.throttle('mfa-ip:' + request.client.host, limit=30)
        now = int(time.time())
        recovery_codes = None
        failure = None
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            challenge = db.execute('SELECT * FROM challenges WHERE token_hash=?', (fingerprint(body.challenge),)).fetchone()
            if not challenge or challenge['expires_at'] <= now or challenge['attempts'] >= 5:
                raise HTTPException(401, '인증 요청이 만료되었습니다. 아이디와 비밀번호부터 다시 입력하세요.')
            user = db.execute('SELECT * FROM users WHERE id=?', (challenge['user_id'],)).fetchone()
            request.state.audit_actor = user['id']
            if fingerprint(user['password_hash']) != challenge['password_version']:
                raise HTTPException(401, '계정이 변경되었습니다. 다시 로그인하세요.')
            valid = False
            if challenge['pending_secret'] and not user['mfa_enabled']:
                secret = store.cipher.decrypt(challenge['pending_secret'].encode()).decode()
                step = accepted_step(secret, body.code.strip())
                if step is not None:
                    db.execute('UPDATE users SET mfa_secret=?,mfa_enabled=1,last_step=? WHERE id=?',
                               (challenge['pending_secret'], step, user['id']))
                    recovery_codes = store.new_recovery_codes(db, user['id'])
                    valid = True
            elif not challenge['pending_secret'] and user['mfa_enabled']:
                valid = store.consume_factor(db, user, body.code)
            if not valid:
                db.execute('UPDATE challenges SET attempts=attempts+1 WHERE token_hash=?', (fingerprint(body.challenge),))
                failure = '인증 코드가 올바르지 않거나 이미 사용되었습니다. 새 코드를 입력하세요.'
                request.state.audit_action = 'mfa_failed'
            else:
                db.execute('DELETE FROM challenges WHERE user_id=?', (user['id'],))
                old_token, _ = token_from(request)
                db.execute('DELETE FROM sessions WHERE token_hash=? OR expires_at<=?', (fingerprint(old_token), now))
                token = secrets.token_urlsafe(32)
                remember = bool(challenge['remember'])
                ttl = remember_days * 86400 if remember else normal_seconds
                expires = now + ttl
                db.execute('INSERT INTO sessions VALUES(?,?,?,?)', (fingerprint(token), user['id'], expires, int(remember)))
                db.execute('DELETE FROM attempts WHERE bucket=?', (fingerprint('login-user:' + user['username']),))
                user = db.execute('SELECT * FROM users WHERE id=?', (user['id'],)).fetchone()
                request.state.audit_action = 'mfa_enrolled_login_success' if recovery_codes else 'mfa_login_success'
        # Raise after commit so the failed-attempt counter cannot roll back.
        if failure:
            raise HTTPException(401, failure)
        if remember:
            response.set_cookie(COOKIE, token, max_age=ttl, httponly=True, secure=secure, samesite='lax', path='/')
        else:
            clear_cookie(response)
        return {'user': store.public_user(user), 'expires_at': expires, 'remember': remember,
                'access_token': None if remember else token, 'recovery_codes': recovery_codes}

    @router.get('/session')
    def session(request: Request):
        row = request.state.auth
        return {'user': store.public_user(row), 'expires_at': row['expires_at'], 'remember': bool(row['remember'])}

    @router.post('/logout')
    def logout(request: Request, response: Response):
        store.revoke(request.state.auth_token)
        clear_cookie(response)
        return {'ok': True}

    @router.get('/me')
    def me(request: Request):
        return store.public_user(request.state.auth)

    @router.put('/me')
    def update_profile(body: ProfileBody, request: Request):
        name, email = clean_profile(body.name, body.email)
        with store.connect() as db:
            db.execute('UPDATE users SET name=?,email=?,updated_at=? WHERE id=?',
                       (name, email, int(time.time()), request.state.auth['id']))
            user = db.execute('SELECT * FROM users WHERE id=?', (request.state.auth['id'],)).fetchone()
        return store.public_user(user)

    def step_up(db, user_id, body):
        user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if not user or not verify_password(body.current_password, user['password_hash']):
            raise HTTPException(400, '현재 비밀번호 또는 인증 코드가 올바르지 않습니다.')
        if not store.consume_factor(db, user, body.code):
            raise HTTPException(400, '현재 비밀번호 또는 인증 코드가 올바르지 않거나 이미 사용되었습니다.')
        return user

    @router.put('/password')
    def change_password(body: PasswordBody, request: Request, response: Response):
        user_id = request.state.auth['id']
        store.throttle('step-up:' + str(user_id), limit=10)
        if body.current_password == body.new_password:
            raise HTTPException(400, '새 비밀번호는 현재 비밀번호와 다르게 설정하세요.')
        encoded = password_hash(body.new_password)
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            step_up(db, user_id, body)
            db.execute('UPDATE users SET password_hash=?,updated_at=? WHERE id=?', (encoded, int(time.time()), user_id))
            db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            db.execute('DELETE FROM challenges WHERE user_id=?', (user_id,))
        request.state.audit_action = 'password_changed_sessions_revoked'
        clear_cookie(response)
        return {'ok': True, 'message': '비밀번호를 변경했습니다. 새 비밀번호로 다시 로그인하세요.'}

    @router.post('/mfa/recovery-codes')
    def regenerate_codes(body: StepUpBody, request: Request):
        user_id = request.state.auth['id']
        store.throttle('step-up:' + str(user_id), limit=10)
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            step_up(db, user_id, body)
            codes = store.new_recovery_codes(db, user_id)
        request.state.audit_action = 'recovery_codes_rotated'
        return {'recovery_codes': codes}

    @router.post('/mfa/reset')
    def reset_mfa(body: StepUpBody, request: Request, response: Response):
        user_id = request.state.auth['id']
        store.throttle('step-up:' + str(user_id), limit=10)
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            step_up(db, user_id, body)
            db.execute("UPDATE users SET mfa_secret='',mfa_enabled=0,last_step=-1 WHERE id=?", (user_id,))
            for table in ('sessions', 'challenges', 'recovery_codes'):
                db.execute(f'DELETE FROM {table} WHERE user_id=?', (user_id,))
        request.state.audit_action = 'mfa_reset_sessions_revoked'
        clear_cookie(response)
        return {'ok': True}

    @router.get('/admin/users')
    def users():
        with store.connect() as db:
            return {'rows': [store.public_user(row) for row in db.execute('SELECT * FROM users ORDER BY id')]}

    @router.put('/admin/users/{user_id}/role')
    def change_role(user_id: int, body: RoleBody, request: Request):
        actor = request.state.auth['id']
        store.throttle('step-up:' + str(actor), limit=10)
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM users WHERE id=?', (actor,)).fetchone()
            if current['role'] != 'admin':
                raise HTTPException(403, '관리자 권한이 필요합니다.')
            target = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
            if not target:
                raise HTTPException(404, '계정을 찾을 수 없습니다.')
            if target['role'] == 'admin' and body.role != 'admin' and db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] <= 1:
                raise HTTPException(409, '마지막 관리자 계정은 조회 전용으로 변경할 수 없습니다.')
            step_up(db, actor, body)
            db.execute('UPDATE users SET role=?,updated_at=? WHERE id=?', (body.role, int(time.time()), user_id))
            db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            db.execute('DELETE FROM challenges WHERE user_id=?', (user_id,))
        request.state.audit_action = f'role_changed:{user_id}:{body.role}'
        return {'ok': True}

    @router.get('/admin/audit')
    def audit(before_id: int = 0, limit: int = 50):
        limit = max(1, min(100, limit))
        with store.connect() as db:
            rows = db.execute('SELECT * FROM audit_events WHERE (?=0 OR id<?) ORDER BY id DESC LIMIT ?',
                              (before_id, before_id, limit + 1)).fetchall()
        return {'rows': [dict(row) for row in rows[:limit]], 'has_more': len(rows) > limit,
                'next_before_id': rows[limit-1]['id'] if len(rows) > limit else 0}

    app.include_router(router)
    return store
