import base64
import hashlib
import io
import secrets
import time

import qrcode
from flask import request, render_template, jsonify


def gen_qr_token(user_agent, timestamp, sys_version, encoding):
    """Generate QR code token based on user agent and timestamp"""
    data = f"{user_agent}{timestamp}{sys_version}{secrets.token_hex(16)}"
    return hashlib.sha256(data.encode(encoding)).hexdigest()


def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Password must contain uppercase, lowercase, digit and special character"

    return True, "Password is strong"


def qr_login(sys_version, global_encoding, domain):
    ct = str(int(time.time()))
    user_agent = request.headers.get('User-Agent')
    token = gen_qr_token(user_agent, ct, sys_version, global_encoding)
    token_expire = str(int(time.time() + 180))
    qr_data = f"{domain}api/phone/scan?login_token={token}"

    # 生成二维码
    qr_img = qrcode.make(qr_data)
    buffered = io.BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode(global_encoding)

    # 存储二维码状态（可以根据需要扩展）
    token_json = {'status': 'pending', 'created_at': ct, 'expire_at': token_expire}
    return token_json, qr_code_base64, token_expire, token


def phone_scan_back(user_id, cache_instance):
    # 用户扫码调用此接口
    token = request.args.get('login_token')
    refresh_token = getattr(request, 'refresh_token', request.cookies.get('refresh_token'))

    if token:
        cache_qr_token = cache_instance.get(f"QR-token_{token}")
        if cache_qr_token:
            page_json = {'status': 'success'}
            cache_instance.set(f"QR-token_{token}", page_json, timeout=180)
            allow_json = {'status': 'success', 'refresh_token': refresh_token}
            cache_instance.set(f"QR-allow_{token}", allow_json, timeout=180)
            return render_template('auth/scan_success.html', message='授权成功，请在两分钟内完成登录')
        return None
    else:
        token_json = {'status': 'failed'}
        return jsonify(token_json)


def check_qr_login_back(cache_instance):
    token = request.args.get('token')
    callback = request.args.get('callback') or 'profile'
    cache_qr_allowed = cache_instance.get(f"QR-allow_{token}")
    if token and cache_qr_allowed:
        return jsonify({'status': 'success', 'refresh_token': cache_qr_allowed['refresh_token'], 'callback': callback})
    else:
        token_json = {'status': 'pending'}
        return jsonify(token_json)
