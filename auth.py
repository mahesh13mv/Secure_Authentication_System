from flask import Blueprint, request, jsonify, send_file
from models import db, User
from utils import hash_password, check_password, make_jwt, generate_mfa_secret, get_totp_uri, verify_totp, verify_jwt
import qrcode
import io

bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400
    hashed = hash_password(password)
    user = User(email=email, password=hashed)
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True, 'id': user.id})

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not check_password(password, user.password):
        return jsonify({'error': 'Invalid credentials'}), 401
    # If MFA enabled, return short token for MFA step
    payload = {'id': user.id, 'email': user.email}
    if user.mfa_enabled:
        token = make_jwt({**payload, 'mfa': True}, expiry=300)
        return jsonify({'mfa_required': True, 'token': token})
    token = make_jwt(payload)
    return jsonify({'token': token})

@bp.route('/mfa/setup', methods=['POST'])
def mfa_setup():
    data = request.get_json() or {}
    token = data.get('token')
    if not token:
        return jsonify({'error': 'Token required'}), 401
    payload = verify_jwt(token)
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    user = User.query.get(payload['id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    secret = generate_mfa_secret()
    user.mfa_secret = secret
    db.session.commit()
    uri = get_totp_uri(secret, user.email)
    return jsonify({'secret': secret, 'otpauth_uri': uri, 'user_id': user.id})

@bp.route('/mfa/qr/<int:user_id>')
def mfa_qr(user_id):
    user = User.query.get(user_id)
    if not user or not user.mfa_secret:
        return jsonify({'error': 'Not found'}), 404
    uri = get_totp_uri(user.mfa_secret, user.email)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@bp.route('/mfa/verify', methods=['POST'])
def mfa_verify():
    data = request.get_json() or {}
    token = data.get('token')
    code = data.get('code')
    if not token or not code:
        return jsonify({'error': 'Token and code required'}), 400
    payload = verify_jwt(token)
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    user = User.query.get(payload['id'])
    if not user or not user.mfa_secret:
        return jsonify({'error': 'MFA not setup'}), 400
    if not verify_totp(user.mfa_secret, code):
        return jsonify({'error': 'Invalid code'}), 401
    # enable MFA if not enabled
    if not user.mfa_enabled:
        user.mfa_enabled = True
        db.session.commit()
    # issue full token
    full = make_jwt({'id': user.id, 'email': user.email})
    return jsonify({'token': full})

@bp.route('/me')
def me():
    auth = request.headers.get('Authorization', None)
    if not auth:
        return jsonify({'error': 'No token'}), 401
    parts = auth.split()
    if len(parts) != 2:
        return jsonify({'error': 'Invalid auth header'}), 401
    token = parts[1]
    payload = verify_jwt(token)
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    user = User.query.get(payload['id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': user.to_dict()})
