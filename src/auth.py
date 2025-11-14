import functools
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

from flask import request, redirect, url_for, g, current_app, flash
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, decode_token, create_access_token
from flask_jwt_extended.exceptions import NoAuthorizationError, JWTDecodeError
from flask_login import current_user as s_current_user

from setting import app_config


def refresh_tokens_if_needed():
    """在请求前自动刷新即将过期的 token"""
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return
    access_token = request.cookies.get('access_token')
    if not access_token:
        return

    try:
        # 解码 token 检查剩余时间
        decoded_token = decode_token(access_token)
        exp_timestamp = decoded_token['exp']
        current_timestamp = datetime.now(timezone.utc).timestamp()

        # 如果 token 在5分钟内过期，自动刷新
        if exp_timestamp - current_timestamp < 300:
            # 使用 session 中的用户信息来刷新
            if s_current_user.is_authenticated:
                new_access_token = create_access_token(
                    identity=str(s_current_user.id),
                    additional_claims={
                        'user_id': s_current_user.id,
                        'email': s_current_user.email
                    }
                )

                # 将新的 token 存储在 g 对象中，在 after_request 中设置
                g.new_access_token = new_access_token

    except JWTDecodeError as e:
        # Token 无效，记录错误但忽略刷新
        current_app.logger.warning(f"JWT decode error during refresh: {str(e)}")
        pass


def is_safe_url(target):
    """检查 URL 是否安全，防止开放重定向攻击"""
    if not target:
        return False

    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def jwt_required(f):
    """
    简化版认证装饰器 - 主要依赖 Session，JWT 作为辅助
    """

    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # 主要验证 Session
        if not s_current_user.is_authenticated:
            # 保存 next 参数到重定向 URL
            next_url = request.args.get('next') or request.endpoint
            login_url = url_for('auth.login')

            if next_url and is_safe_url(next_url) and next_url != 'auth.login':
                login_url += f'?next={next_url}'

            return redirect(login_url)

        # 尝试验证 JWT
        try:
            verify_jwt_in_request(locations=['cookies'])
            jwt_identity = get_jwt_identity()
            current_app.logger.debug(f"JWT verified for user {jwt_identity}")
        except (NoAuthorizationError, JWTDecodeError) as e:
            # JWT 验证失败，尝试刷新
            current_app.logger.warning(f"JWT verification failed: {str(e)}")

            # 尝试刷新令牌
            refresh_tokens_if_needed()

            # 如果刷新后仍然失败，显示错误页面
            try:
                verify_jwt_in_request(locations=['cookies'])
                current_app.logger.debug("JWT verified after refresh")
            except (NoAuthorizationError, JWTDecodeError) as refresh_error:
                current_app.logger.error(f"JWT still invalid after refresh: {str(refresh_error)}")
                # 显示自定义错误页面而不是 JSON 响应
                flash("身份验证失败，请重新登录", 'error')
                return redirect(url_for('auth.login'))

        # 传递 user_id 参数给视图函数
        return f(s_current_user.id, *args, **kwargs)

    return decorated_function


def admin_required(f):
    """
    管理员认证装饰器
    """

    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # 首先验证 Session
        if not s_current_user.is_authenticated:
            # 保存 next 参数到重定向 URL
            next_url = request.args.get('next') or request.endpoint
            login_url = url_for('auth.login')

            if next_url and is_safe_url(next_url) and next_url != 'auth.login':
                login_url += f'?next={next_url}'

            return redirect(login_url)

        # 验证是否为管理员（假设管理员 ID 为 1）
        if s_current_user.id != 1:
            current_app.logger.warning(f"Non-admin user {s_current_user.id} attempted to access admin area")
            return redirect(url_for('auth.login'))

        # 尝试验证 JWT
        try:
            verify_jwt_in_request(locations=['cookies'])
            jwt_user_id = get_jwt_identity()
            current_app.logger.debug(f"Admin JWT verified for user {jwt_user_id}")

            # 检查 JWT 和 Session 用户是否一致
            if str(s_current_user.id) != str(jwt_user_id):
                # 不一致时尝试刷新 token
                current_app.logger.warning("JWT and Session user mismatch")
                refresh_tokens_if_needed()
        except (NoAuthorizationError, JWTDecodeError) as e:
            # JWT 验证失败，尝试刷新
            current_app.logger.warning(f"Admin JWT verification failed: {str(e)}")
            refresh_tokens_if_needed()

        # 传递 user_id 参数给视图函数
        return f(s_current_user.id, *args, **kwargs)

    return decorated_function


def origin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        client_domain = request.host.split(':')[0]
        config_domain = app_config.domain.split(':')[0]

        if client_domain != config_domain:
            from flask import jsonify
            return jsonify({'code': 401, 'error': 'Unauthorized access'}), 401

        return f(*args, **kwargs)

    return decorated_function
