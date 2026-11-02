"""TOTP and enrollment QR utilities. No external QR service receives secrets."""
import base64
import hmac
import io
import time
from pathlib import Path
import os
import pyotp
import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet


def load_cipher(directory, has_existing_secrets=False):
    supplied = os.getenv('AUTH_MFA_ENCRYPTION_KEY', '').strip()
    if supplied:
        return Fernet(supplied.encode())
    path = Path(directory) / 'mfa_encryption.key'
    if not path.exists() and has_existing_secrets:
        raise RuntimeError('MFA encryption key missing. Restore mfa_encryption.key; do not replace the account database.')
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(Fernet.generate_key())
    except FileExistsError:
        pass
    return Fernet(path.read_bytes().strip())


def accepted_step(secret, code, last_step=-1, now=None):
    # Check adjacent windows for clock skew, but never accept a consumed time step.
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    step = int(time.time() if now is None else now) // 30
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    for candidate in (step, step - 1, step + 1):
        if candidate > last_step and hmac.compare_digest(totp.at(candidate * 30), code):
            return candidate
    return None


def provisioning(secret, username):
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name='OPNsense Dashboard')
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=6, border=4)
    output = io.BytesIO()
    image.save(output)
    return {'secret': secret, 'qr_data_url': 'data:image/svg+xml;base64,' + base64.b64encode(output.getvalue()).decode()}
