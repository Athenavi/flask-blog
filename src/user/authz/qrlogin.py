import base64
import io
import time

import qrcode
from flask import request, render_template, jsonify

from src.utils.security.safe import gen_qr_token


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
    phone_token = request.cookies.get('jwt')
    refresh_token = request.cookies.get('refresh_token')
    if token:
        cache_qr_token = cache_instance.get(f"QR-token_{token}")
        if cache_qr_token:
            ct = str(int(time.time()))
            token_expire = str(int(time.time() + 30))
            page_json = {'status': 'success', 'created_at': ct, 'expire_at': token_expire}
            cache_instance.set(f"QR-token_{token}", page_json, timeout=60)
            allow_json = {'status': 'success', 'created_at': ct, 'expire_at': token_expire, 'token': phone_token,
                          'refresh_token': refresh_token}
            cache_instance.set(f"QR-allow_{token}", allow_json, timeout=60)
            return render_template('inform.html', status_code=200, message='授权成功，请在30秒内完成登录')
        return None
    else:
        # app.logger.info(f"Invalid token: {token} for user {user_id}")
        token_json = {'status': 'failed'}
        return jsonify(token_json)
