import bcrypt
import jwt
import os
import pyotp
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()
JWT_SECRET = os.getenv('JWT_SECRET') or 'jwt-secret'
JWT_EXP = int(os.getenv('JWT_EXP', 3600))

# Password
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))

# JWT
def make_jwt(payload: dict, expiry: int = JWT_EXP) -> str:
    data = payload.copy()
    data['exp'] = datetime.utcnow() + timedelta(seconds=expiry)
    token = jwt.encode(data, JWT_SECRET, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def verify_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except Exception:
        return None

# TOTP
def generate_mfa_secret() -> str:
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str, issuer: str = 'SecureAuthFlask') -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
