import functools
from datetime import datetime, timezone
from typing import Callable, Any
from urllib.parse import urlparse, urljoin

from flask import request, redirect, url_for, g, current_app, flash, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, decode_token, create_access_token
from flask_jwt_extended.exceptions import NoAuthorizationError, JWTDecodeError
from flask_login import current_user as s_current_user, logout_user
from werkzeug import Response


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


def cached_check_user_banned():
    """检查当前用户是否被封禁(带缓存)"""
    from src.extensions import cache

    if not s_current_user.is_authenticated:
        return False

    # 使用用户ID作为缓存键的一部分
    cache_key = f"user_banned_status_{s_current_user.id}"

    # 尝试从缓存中获取结果
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        return cached_result

    # 缓存未命中，执行实际检查
    is_banned = s_current_user.has_role('banned')

    # 将结果缓存30分钟
    cache.set(cache_key, is_banned, timeout=300 * 6)

    return is_banned


def check_user_banned():
    """检查当前用户是否被封禁"""
    if cached_check_user_banned():
        # 用户被封禁，登出用户
        from flask import session
        logout_user()
        session.clear()
        return True
    return False


def check_access_token(access_token: str, ):
    """检查指定会话是否已过期"""
    from src.extensions import cache
    from src.models.userSession import UserSession

    hash_key = hash(str(access_token))
    # 使用哈希键作为缓存键的一部分
    cache_key = f"session_{hash_key}"
    # print(cache_key)

    # 尝试从缓存中获取结果
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        # print("缓存命中")
        return cached_result
    # 缓存未命中，查询数据库
    session = UserSession.query.filter_by(
        access_token=access_token
    ).first()
    if session is None:
        # 将结果缓存5分钟(300秒)，统一缓存时间以保持一致性
        # print("if分支缓存未命中，将结果缓存5分钟")
        cache.set(cache_key, False, timeout=300)
        return False
    else:
        cache.set(cache_key, True, timeout=300)
        # print("else分支缓存未命中，将结果缓存5分钟")
        return True


def jwt_required(f: object) -> Callable[[tuple[Any, ...], dict[str, Any]], Response | Any]:
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


def vip_required(minimum_level=1):
    """
    VIP权限装饰器
    
    :param minimum_level: 最低所需VIP等级
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(user_id, *args, **kwargs):
            # 首先确保用户已通过身份验证
            if not s_current_user.is_authenticated:
                next_url = request.args.get('next') or request.endpoint
                login_url = url_for('auth.login')

                if next_url and is_safe_url(next_url) and next_url != 'auth.login':
                    login_url += f'?next={next_url}'

                return redirect(login_url)

            # 检查用户VIP等级
            if s_current_user.vip_level < minimum_level:
                # 判断请求是否期望 JSON 响应
                if request.method != 'GET':
                    return jsonify({'error': f'此功能需要的VIP{minimum_level}'}), 403

            # 检查VIP是否过期
            from datetime import datetime
            if s_current_user.vip_expires_at and s_current_user.vip_expires_at < datetime.now():
                # 判断请求是否期望 JSON 响应
                if request.method != 'GET':
                    return jsonify({'error': '您的VIP已过期，请续费'}), 403

                flash('您的VIP已过期，请续费')
                return redirect(url_for('vip.plans'))

            # 继续执行原始函数
            return f(user_id, *args, **kwargs)

        return decorated_function

    return decorator


def origin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # 延迟导入app_config以避免循环导入
        from src.setting import app_config
        client_domain = request.host.split(':')[0]
        config_domain = app_config.domain.split(':')[0]

        if client_domain != config_domain:
            from flask import jsonify
            return jsonify({'code': 401, 'error': 'Unauthorized access'}), 401

        return f(*args, **kwargs)

    return decorated_function
