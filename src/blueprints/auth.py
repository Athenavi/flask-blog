import re
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import Blueprint, make_response, current_app
from flask import render_template, jsonify, flash
from flask_bcrypt import check_password_hash

from src.database import get_db
from src.models import User
from src.utils.security.jwt_handler import JWTHandler, JWT_EXPIRATION_DELTA, REFRESH_TOKEN_EXPIRATION_DELTA

auth_bp = Blueprint('auth', __name__, template_folder='templates')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        # 验证
        errors = []

        if not username or len(username) < 3:
            errors.append('用户名至少需要3个字符')

        if not email or not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+', email):
            errors.append('请输入有效的电子邮件地址')

        if not password or len(password) < 8:
            errors.append('密码至少需要8个字符')

        if password != confirm_password:
            errors.append('密码不匹配')

        # 检查用户是否已存在
        if User.query.filter_by(username=username).first():
            errors.append('用户名已存在')

        if User.query.filter_by(email=email).first():
            errors.append('电子邮件已注册')

        if errors:
            if request.is_json:
                return jsonify({
                    'success': False,
                    'errors': errors
                }), 400
            else:
                for error in errors:
                    flash(error, 'error')
                return render_template('auth/register.html')

        # 创建新用户
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            register_ip=request.remote_addr
        )
        with get_db() as db:
            try:
                db.add(new_user)

                if request.is_json:
                    return jsonify({
                        'success': True,
                        'message': '注册成功',
                        'user': new_user.to_dict()
                    })
                else:
                    flash('注册成功！请登录。', 'success')
                    return redirect(url_for('auth.login'))

            except Exception as e:
                db.rollback()
                if request.is_json:
                    return jsonify({
                        'success': False,
                        'message': '注册失败'
                    }), 500
                else:
                    flash('注册失败，请重试。', 'error')
                    return render_template('auth/register.html')

    return render_template('auth/register.html')


from flask import request, redirect, url_for
from urllib.parse import urlparse, urljoin


def is_safe_url(target):
    """检查URL是否安全（同源）"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


def resolve_callback(callback, default='profile'):
    """
    解析callback参数，可能是endpoint名称或URL路径
    """
    if not callback:
        return url_for(default)

    # 如果callback已经是URL路径且安全，直接使用
    if callback.startswith('/') and is_safe_url(callback):
        return callback

    # 如果callback是endpoint名称，尝试解析为URL
    try:
        # 分割可能的端点参数
        if '?' in callback:
            endpoint_part, query_part = callback.split('?', 1)
        else:
            endpoint_part, query_part = callback, ''

        # 尝试解析端点
        url_path = url_for(endpoint_part)

        # 添加查询参数
        if query_part:
            url_path = f"{url_path}?{query_part}"

        return url_path
    except Exception as e:
        # 如果端点解析失败，回退到默认
        current_app.logger.warning(f"Failed to resolve callback '{callback}': {str(e)}")
        return url_for(default)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    try:
        # 获取并正确解析callback参数
        raw_callback = request.args.get('callback') or '/profile'
        callback_url = resolve_callback(raw_callback, 'profile')

        if request.method == 'GET':
            user_agent = request.headers.get('User-Agent', '')
            if is_mobile_device(user_agent):
                # 对于移动端，传递原始callback参数
                mobile_callback = raw_callback or 'profile'
                return redirect(f'/api/mobile/scanner?callback={mobile_callback}')

        if request.method == 'POST':
            if request.is_json:
                data = request.get_json()
                email = data.get('email')
                password = data.get('password')
            else:
                email = request.form.get('email')
                password = request.form.get('password')

            user = User.query.filter_by(email=email).first()

            if user and check_password_hash(user.password, password):
                token = JWTHandler.generate_token(user_id=user.id, username=user.username)
                refresh_token = JWTHandler.generate_refresh_token(user_id=user.id)

                if request.is_json:
                    return jsonify({
                        'success': True,
                        'message': '登录成功',
                        'user': user.to_dict(),
                        'access_token': token,
                        'refresh_token': refresh_token
                    })
                else:
                    expires = datetime.now(timezone.utc) + timedelta(seconds=JWT_EXPIRATION_DELTA)
                    refresh_expires = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_TOKEN_EXPIRATION_DELTA)

                    response = make_response(redirect(callback_url))
                    response.set_cookie('jwt', token, httponly=True, expires=expires)
                    response.set_cookie('refresh_token', refresh_token, httponly=True, expires=refresh_expires)
                    flash('登录成功', 'success')
                    return response
            else:
                if request.is_json:
                    return jsonify({
                        'success': False,
                        'message': '无效的电子邮件或密码'
                    }), 401
                else:
                    flash('无效的电子邮件或密码', 'error')
                    # 传递原始callback用于表单
                    return render_template('auth/login.html', email=email, callback=raw_callback)

        # 检查是否已登录
        if jwt_cookie := request.cookies.get('jwt'):
            try:
                JWTHandler.authenticate_token(jwt_cookie)
                return redirect(callback_url)
            except Exception:
                flash('您的登录已过期，请重新登录', 'error')

        # 传递原始callback用于表单
        return render_template('auth/login.html', callback=raw_callback)
    except Exception as e:
        flash('登录过程中发生错误，请稍后再试', 'error')
        current_app.logger.error(f"Login error: {str(e)}")
        return render_template('auth/login.html')


# 移动设备检测函数
def is_mobile_device(user_agent):
    """检查User-Agent判断是否为移动设备"""
    mobile_keywords = [
        'mobile', 'android', 'iphone', 'ipad', 'ipod',
        'blackberry', 'windows phone', 'opera mini', 'iemobile'
    ]
    user_agent = user_agent.lower()
    return any(keyword in user_agent for keyword in mobile_keywords)


@auth_bp.route('/logout')
def logout():
    response = make_response(redirect('/login'))
    response.set_cookie('jwt', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    return response

