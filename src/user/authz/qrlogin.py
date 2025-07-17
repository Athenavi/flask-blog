import base64
import io
import time

import qrcode
from flask import request

from src.utils.security.safe import gen_qr_token


def qrlogin(sys_version, global_encoding, domain):
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
    return token_json, qr_code_base64,token_expire,token
