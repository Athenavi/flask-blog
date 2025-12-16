import base64
import hashlib
import io
import secrets
import time

import qrcode
from flask import render_template, current_app
from flask_principal import identity_changed, Identity


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
            allow_json = {'status': 'success', 'refresh_token': refresh_token, 'user_id': user_id}
            cache_instance.set(f"QR-allow_{token}", allow_json, timeout=180)
            return render_template('auth/scan_success.html', message='授权成功，请在两分钟内完成登录')
        return None
    else:
        token_json = {'status': 'failed'}
        return jsonify(token_json)


from flask import request, make_response, jsonify, flash
from flask_jwt_extended import create_access_token
from flask_login import login_user
from datetime import datetime, timezone
import uuid
from src.models import User, UserSession, db
from src.setting import app_config


def check_qr_login_back(cache_instance):
    token = request.args.get('token')
    next_url = request.args.get('next', '/profile')
    cache_qr_allowed = cache_instance.get(f"QR-allow_{token}")

    if not token or not cache_qr_allowed:
        return jsonify({'status': 'pending'})

    try:
        user_id = cache_qr_allowed.get('user_id')
        # print(user_id)

        scan_user = User.query.filter_by(id=user_id).first()
        if not scan_user:
            return jsonify({'status': 'error', 'message': '用户不存在'})

        # 生成新的访问令牌
        access_token = create_access_token(
            identity=str(scan_user.id),
            additional_claims={
                'user_id': scan_user.id,
                'email': scan_user.email,
                'jti': str(uuid.uuid4())
            },
            expires_delta=app_config.JWT_ACCESS_TOKEN_EXPIRES
        )
        refresh_token = token

        # 用户登录
        login_user(scan_user, remember=True)
        identity_changed.send(current_app._get_current_object(),
                              identity=Identity(scan_user.id))

        # 解析 User-Agent 信息
        user_agent_str = request.headers.get('User-Agent', '')
        device_type = None
        browser = None
        platform = None

        # 简单解析 User-Agent
        if 'Mobile' in user_agent_str:
            device_type = 'mobile'
        else:
            device_type = 'desktop'

        # 提取浏览器信息
        if 'Chrome' in user_agent_str and not 'Edg' in user_agent_str:
            browser = 'Chrome'
        elif 'Firefox' in user_agent_str:
            browser = 'Firefox'
        elif 'Safari' in user_agent_str and not 'Chrome' in user_agent_str:
            browser = 'Safari'
        elif 'Edg' in user_agent_str:
            browser = 'Edge'

        # 提取平台信息
        if 'Windows' in user_agent_str:
            platform = 'Windows'
        elif 'Macintosh' in user_agent_str:
            platform = 'macOS'
        elif 'Linux' in user_agent_str:
            platform = 'Linux'
        elif 'Android' in user_agent_str:
            platform = 'Android'
        elif 'iPhone' in user_agent_str or 'iPad' in user_agent_str:
            platform = 'iOS'

        # 记录用户会话
        new_session = UserSession(
            user_id=scan_user.id,
            session_id=request.cookies.get('zb_session'),
            device_type=device_type,
            browser=browser,
            platform=platform,
            ip_address=request.remote_addr,
            access_token=access_token,
            refresh_token=refresh_token,
        )
        db.session.add(new_session)
        db.session.commit()
        expires = datetime.now(timezone.utc) + app_config.JWT_ACCESS_TOKEN_EXPIRES
        login_sann_json = jsonify({'status': 'success', 'next_url': next_url})
        response = make_response(login_sann_json)
        # 设置 JWT Cookies
        response.set_cookie(
            'access_token',
            access_token,
            httponly=True,
            samesite='Lax',
            expires=expires
        )
        response.set_cookie(
            'refresh_token',
            refresh_token,
            httponly=True,
            samesite='Lax',
            expires=expires
        )
        flash('登录成功', 'success')
        return response

    except Exception as e:
        print(f"QR登录错误: {e}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': '登录失败'})
