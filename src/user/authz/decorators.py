from functools import wraps

from flask import abort, make_response
from flask import request, redirect, url_for

from src.config.general import get_general_config
from src.user.authz.core import authenticate_jwt, authenticate_refresh_token, update_jwt_cookies


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('jwt')
        user_id = authenticate_jwt(token)
        if user_id != 1:
            return redirect(url_for('profile'))
        return f(user_id, *args, **kwargs)

    return decorated_function


def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('jwt')
        user_id = authenticate_jwt(token)
        callback_route = request.endpoint
        refresh_token = request.cookies.get('refresh_token')

        if user_id is None:
            if refresh_token is not None:
                user_id = authenticate_refresh_token(refresh_token)

            if user_id is None:
                return redirect(url_for('auth.login', callback=callback_route))

            # 使用make_response确保response是Response对象
            resp = f(user_id, *args, **kwargs)
            response = make_response(resp)
            updated_response = update_jwt_cookies(response, user_id)
            return updated_response if updated_response is not None else response

        # 确保普通情况下的返回也是Response对象
        resp = f(user_id, *args, **kwargs)
        return make_response(resp)

    return decorated_function


domain, title, beian, version, api_host, app_id, app_key, default_key = get_general_config()
# 定义白名单
allowed_origins = [domain]


def origin_required(f):
    def decorated_function(*args, **kwargs):
        origin = request.headers.get('Origin')
        if origin and origin not in allowed_origins:
            abort(403, description="请求被拒绝, 请使用白名单内的域名")
        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function
