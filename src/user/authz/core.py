from datetime import datetime, timedelta

import pytz
from flask import request
from jwt import encode, decode

from src.config.general import zy_safe_conf

secret_key, JWT_EXPIRATION_DELTA, REFRESH_TOKEN_EXPIRATION_DELTA, TIME_ZONE = zy_safe_conf()

# 使用时区对象替代字符串
shanghai_tz = pytz.timezone(TIME_ZONE) if TIME_ZONE else pytz.utc


def generate_jwt(user_id, user_name):
    """生成基于上海时区的JWT"""
    # 获取上海时区当前时间
    now_shanghai = datetime.now(shanghai_tz)
    expiration_time = now_shanghai + timedelta(seconds=JWT_EXPIRATION_DELTA)

    # 转换为UTC时间戳保持兼容性
    payload = {
        'user_id': user_id,
        'username': user_name,
        'exp': int(expiration_time.timestamp())  # 自动转换时区时间戳
    }

    # print(f"[JWT生成] 本地过期时间: {expiration_time} (UTC时间戳: {payload['exp']})")
    token = encode(payload, secret_key, algorithm='HS256')
    return token  # 直接返回字符串


def generate_refresh_token(user_id, user_name):
    """生成基于上海时区的Refresh Token"""
    now_shanghai = datetime.now(shanghai_tz)
    expiration_time = now_shanghai + timedelta(seconds=REFRESH_TOKEN_EXPIRATION_DELTA)

    payload = {
        'user_id': user_id,
        'username': user_name,
        'exp': int(expiration_time.timestamp())
    }
    token = encode(payload, secret_key, algorithm='HS256')
    return token


def authenticate_token(token):
    """基于上海时区验证令牌"""
    try:
        payload = decode(
            token,
            secret_key,
            algorithms=['HS256']
        )

        # 获取上海时区当前时间戳
        current_ts = int(datetime.now(shanghai_tz).timestamp())

        if payload['exp'] < current_ts:
            expired_time = datetime.fromtimestamp(payload['exp'], shanghai_tz)
            print(f"[令牌过期] 实际过期时间: {expired_time.strftime('%Y-%m-%d %H:%M:%S %Z%z')}")
            return None

        return payload['user_id']
    except Exception as e:
        # print(f"认证失败: {str(e)}")
        return None


def update_jwt_cookies(response, user_id):
    """更新新的JWT，确保始终返回response对象"""
    user_name = get_username()
    jwt = generate_jwt(user_id, user_name)
    response.set_cookie('jwt', jwt, max_age=JWT_EXPIRATION_DELTA, samesite=None, secure=False)
    # 无论是否更新，都返回response对象
    return response


def authenticate_jwt(token):
    # 认证JWT令牌
    return authenticate_token(token)


def authenticate_refresh_token(token):
    # 认证刷新令牌
    return authenticate_token(token)


def get_username():
    token = request.cookies.get('jwt')
    if token:
        payload = decode(token, secret_key, algorithms=['HS256'], options={"verify_exp": False})
        return payload['username']
    else:
        refresh_token = request.cookies.get('refresh_token')
        if refresh_token:
            payload = decode(refresh_token, secret_key, algorithms=['HS256'], options={"verify_exp": False})
            return payload['username']
