from datetime import datetime, timedelta

import pytz
from flask import request, flash
from jwt import encode, decode, ExpiredSignatureError, InvalidTokenError

from src.setting import app_config

SECRET_KEY = app_config.SECRET_KEY
JWT_EXPIRATION_DELTA = app_config.JWT_EXPIRATION_DELTA
REFRESH_TOKEN_EXPIRATION_DELTA = app_config.REFRESH_TOKEN_EXPIRATION_DELTA
TIME_ZONE = app_config.TIME_ZONE
print(SECRET_KEY, JWT_EXPIRATION_DELTA, REFRESH_TOKEN_EXPIRATION_DELTA, TIME_ZONE)

# 使用时区对象替代字符串
shanghai_tz = pytz.timezone(TIME_ZONE) if TIME_ZONE else pytz.utc


class JWTHandler:
    @staticmethod
    def generate_token(user_id, username, expires_in=3600):
        """生成基于UTC时区的JWT"""
        now_utc = datetime.now(shanghai_tz)
        expiration_time = now_utc + timedelta(seconds=expires_in)

        payload = {
            'user_id': user_id,
            'username': username,
            'exp': expiration_time  # 直接使用datetime对象
        }

        token = encode(payload, SECRET_KEY, algorithm='HS256')
        return token

    @staticmethod
    def authenticate_token(token):
        try:
            # 直接使用PyJWT的自动过期验证
            payload = decode(
                token,
                SECRET_KEY,
                algorithms=['HS256'],
                options={'verify_exp': True}  # 启用自动过期验证
            )
            return payload['user_id']
        except ExpiredSignatureError:
            flash('Token expired', 'error')
            return None
        except InvalidTokenError:
            print("Invalid token")
            return None

    @staticmethod
    def decode_token(token):
        """Decode JWT token and return user info"""
        try:
            payload = decode(token, SECRET_KEY, algorithms=['HS256'])
            return {
                'user_id': payload['user_id'],
                'username': payload['username'],
                'valid': True
            }
        except ExpiredSignatureError:
            return {'valid': False, 'error': 'Token expired'}
        except InvalidTokenError:
            return {'valid': False, 'error': 'Invalid token'}

    @staticmethod
    def generate_refresh_token(user_id, expires_in=604800):  # 7 days
        """生成基于上海时区的Refresh Token"""
        now_shanghai = datetime.now(shanghai_tz)
        expiration_time = now_shanghai + timedelta(seconds=REFRESH_TOKEN_EXPIRATION_DELTA)

        payload = {
            'user_id': user_id,
            'exp': int(expiration_time.timestamp())
        }
        token = encode(payload, SECRET_KEY, algorithm='HS256')
        return token

    @staticmethod
    def update_jwt_cookies(response, user_id):
        """更新新的JWT，确保始终返回response对象"""
        user_name = JWTHandler.get_current_username()
        jwt = JWTHandler.generate_token(user_id, user_name)
        response.set_cookie('jwt', jwt, max_age=JWT_EXPIRATION_DELTA, samesite=None, secure=False)
        # 无论是否更新，都返回response对象
        return response

    @staticmethod
    def authenticate_jwt(token):
        # 认证JWT令牌
        return JWTHandler.authenticate_token(token)

    @staticmethod
    def authenticate_refresh_token(token):
        # 认证刷新令牌
        return JWTHandler.authenticate_token(token)

    @staticmethod
    def get_current_username():
        token = request.cookies.get('jwt')
        if token:
            payload = decode(token, SECRET_KEY, algorithms=['HS256'], options={"verify_exp": False})
            return payload['username']
        else:
            return None
