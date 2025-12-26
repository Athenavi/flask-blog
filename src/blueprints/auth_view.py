import logging
import uuid
from datetime import datetime, timezone

import bcrypt
from flask import Blueprint
from flask import render_template, jsonify, flash
from flask_babel import refresh, _
from flask_bcrypt import check_password_hash
from flask_login import login_user, logout_user

from src.extensions import limiter
from src.models import User, UserSession, db
from src.setting import app_config

auth_bp = Blueprint('auth', __name__, template_folder='templates')
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp, Optional, Email

from flask import url_for
from urllib.parse import urlparse, urljoin

from flask import redirect, current_app, request, make_response
from functools import wraps
from flask_principal import identity_changed, AnonymousIdentity, Identity

logger = logging.getLogger(__name__)


def babel_language_switch(view_func):
    """装饰器：用于URL参数语言切换"""

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        response = make_response(view_func(*args, **kwargs))

        # 如果通过URL参数切换语言，则设置cookie
        lang_from_request = request.args.get('lang')
        if lang_from_request in ['zh_CN', 'en']:
            app_config.BABEL_DEFAULT_LOCALE = lang_from_request  # 使用属性而不是字典键赋值
            refresh()
            response.set_cookie('lang', lang_from_request, max_age=30 * 24 * 60 * 60)

        return response

    return wrapped_view


class RegisterForm(FlaskForm):
    # 基础信息
    username = StringField(_('用户名'), validators=[
        DataRequired(message=_('用户名不能为空')),
        Length(min=3, max=20, message=_('用户名长度必须在3-20个字符之间')),
        Regexp(r'^[a-zA-Z0-9_]+', message=_('用户名只能包含字母、数字和下划线'))
    ])

    email = StringField(_('邮箱'), validators=[
        DataRequired(message=_('邮箱不能为空')),
        Length(max=255, message=_('邮箱地址过长'))
    ])

    password = PasswordField(_('密码'), validators=[
        DataRequired(message=_('密码不能为空')),
        Length(min=8, message=_('密码至少需要8个字符')),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&*!])[A-Za-z\d@#$%^&*!]+',
               message=_('密码必须包含大小写字母、数字和特殊字符'))
    ])

    confirm_password = PasswordField(_('确认密码'), validators=[
        DataRequired(message=_('请确认密码')),
        EqualTo('password', message=_('两次输入的密码不一致'))
    ])

    # 个人信息
    bio = TextAreaField(_('个人简介'), validators=[
        Optional(),
        Length(max=500, message=_('个人简介不能超过500字符'))
    ])

    display_name = StringField(_('显示名称'), validators=[
        Optional(),
        Length(max=50, message=_('显示名称不能超过50字符'))
    ])

    location = StringField(_('所在地'), validators=[
        Optional(),
        Length(max=100, message=_('所在地信息过长'))
    ])

    website = StringField(_('个人网站'), validators=[
        Optional(),
        Length(max=255, message=_('网站地址过长')),
        Regexp(r'^https?://.+', message=_('请输入有效的网址（以http://或https://开头）'))
    ])

    # 偏好设置
    locale = SelectField(_('语言偏好'), choices=[
        ('zh_CN', _('简体中文')),
        ('en_US', _('English')),
        ('ja_JP', _('日本語'))
    ], default='zh_CN')

    profile_private = BooleanField(_('私密资料'), default=False)

    # 订阅设置
    newsletter = BooleanField(_('订阅新闻通讯'), default=True)
    marketing_emails = BooleanField(_('接收营销邮件'), default=False)

    # 条款同意
    terms = BooleanField(_('同意条款'), validators=[
        DataRequired(message=_('必须同意服务条款才能注册'))
    ])


@auth_bp.route('/register', methods=['GET', 'POST'])
@babel_language_switch
@limiter.limit("5 per minute")
def register():
    from src.models import db, EmailSubscription  # 移动导入语句
    form = RegisterForm()

    if form.validate_on_submit():
        # 检查用户名和邮箱是否已存在
        if User.query.filter_by(username=form.username.data).first():
            flash('用户名已存在', 'error')
            return render_template('auth/register.html', form=form)

        if User.query.filter_by(email=form.email.data).first():
            flash('电子邮件已注册', 'error')
            return render_template('auth/register.html', form=form)

        try:
            # 创建新用户
            hashed_password = bcrypt.hashpw(
                form.password.data.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')

            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password,
                bio=form.bio.data,
                locale=form.locale.data,
                profile_private=form.profile_private.data,
                register_ip=request.remote_addr
            )

            db.session.add(new_user)
            db.session.flush()  # 获取用户ID

            # 创建邮箱订阅设置
            if form.newsletter.data or form.marketing_emails.data:
                email_sub = EmailSubscription(
                    user_id=new_user.id,
                    subscribed=True,
                    created_at=datetime.now(timezone.utc)
                )
                db.session.add(email_sub)

            db.session.commit()

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
            logger.error(e)
            db.session.rollback()
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': '注册失败，请重试'
                }), 500
            else:
                flash('注册失败，请重试。', 'error')
                return render_template('auth/register.html', form=form)

    # 处理验证错误
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'error')

    return render_template('auth/register.html', form=form)


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

    # 如果callback是完整URL且安全，直接使用
    if callback.startswith(('http://', 'https://')):
        parsed_url = urlparse(callback)
        if is_safe_url(callback):
            return callback
        else:
            # 如果URL不安全，只使用路径部分
            return parsed_url.path

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


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    remember_me = BooleanField('Remember Me')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    next_url = request.args.get('next', '/profile')
    next_url = resolve_callback(next_url, default='profile')
    from flask_login import current_user
    if current_user.is_authenticated:
        return redirect(next_url)
    form = LoginForm()
    mobile_device = False
    try:
        if request.method == 'GET':
            user_agent = request.headers.get('User-Agent', '')
            if is_mobile_device(user_agent):
                mobile_device = True

        if request.method == 'POST':
            response = login_post_response(form, mobile_device=mobile_device, next_url=next_url)
            # 确保总是返回响应对象
            if response is None:
                flash('登录过程中发生错误，请稍后再试', 'error')
                return render_template('auth/login.html', form=form, mobile_device=mobile_device)
            return response

        return render_template('auth/login.html', form=form, next=request.args.get('next', '/profile'),
                               mobile_device=mobile_device)
    except Exception as e:
        flash('登录过程中发生错误，请稍后再试', 'error')
        current_app.logger.error(f"Login error: {str(e)}")
        # 确保即使在异常情况下也返回响应对象
        return render_template('auth/login.html', form=form, mobile_device=mobile_device)


@auth_bp.route('/api/i18n/set_language', methods=['POST'])
def set_language():
    """处理语言切换请求"""
    from flask import jsonify, make_response
    data = request.get_json()
    if not data or 'language' not in data:
        return jsonify({'success': False, 'message': 'Invalid request'}), 400

    lang = data['language']
    if lang not in ['en', 'zh_CN']:
        return jsonify({'success': False, 'message': 'Unsupported language'}), 400

    response = make_response(jsonify({'success': True, 'message': 'Language updated'}))
    response.set_cookie('lang', lang, max_age=31536000)  # 1年有效期
    return response


# 移动设备检测函数
from user_agents import parse


def is_mobile_device(user_agent):
    """检查User-Agent判断是否为移动设备"""
    user_agent = parse(user_agent)
    return user_agent.is_mobile


@auth_bp.route('/logout')
def logout():
    response = make_response(redirect('/profile'))
    cookies_to_clear = ['jwt', 'refresh_token', 'access_token', 'zb_session']
    for cookie_name in cookies_to_clear:
        response.set_cookie(cookie_name, '', expires=0)
    logout_user()
    # 告诉 Flask-Principal 用户已登出
    identity_changed.send(current_app._get_current_object(),
                          identity=AnonymousIdentity())
    return response


@limiter.limit("10 per minute")
def login_post_response(form, mobile_device=False, next_url=None):
    # 导入 current_app 到函数作用域
    from flask import current_app
    
    if request.is_json:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
    else:
        email = form.email.data
        password = form.password.data

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        from flask_jwt_extended import create_access_token, create_refresh_token
        # 0. 生成双 JWT token

        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={'user_id': user.id, 'email': user.email, 'jti': str(uuid.uuid4()), },
            expires_delta=app_config.JWT_ACCESS_TOKEN_EXPIRES
        )
        refresh_token = create_refresh_token(identity=str(user.id),
                                             expires_delta=app_config.JWT_REFRESH_TOKEN_EXPIRES,
                                             additional_claims={'created_at': str(user.created_at)}
                                             )
        try:
            # 1. 创建 Session 登录
            remember_me = form.remember_me.data if hasattr(form, 'remember_me') else False
            login_user(user, remember=remember_me)
            # Tell Flask-Principal the identity changed
            identity_changed.send(current_app._get_current_object(),
                                  identity=Identity(user.id))

            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': '登录成功',
                    'user': user.to_dict(),
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                })
            else:
                import datetime
                expires = datetime.datetime.now(timezone.utc) + app_config.JWT_ACCESS_TOKEN_EXPIRES
                refresh_expires = datetime.datetime.now(
                    timezone.utc) + app_config.JWT_REFRESH_TOKEN_EXPIRES if remember_me else None
                response = make_response(redirect(next_url or '/profile'))

                # 设置 Session Cookie（Flask-Login 会自动处理）
                # 设置 JWT Cookies
                response.set_cookie(
                    'access_token',
                    access_token,
                    httponly=True,
                    samesite='Lax',
                    expires=expires
                )
                if remember_me:
                    response.set_cookie(
                        'refresh_token',
                        refresh_token,
                        httponly=True,
                        samesite='Lax',
                        expires=refresh_expires
                    )
                flash('登录成功', 'success')
                return response

        except Exception as e:
            logger.error(f"登录过程中的异常: {str(e)}")
            # 在异常情况下也要确保返回响应对象
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': '登录过程中发生错误，请稍后再试'
                }), 500
            else:
                flash('登录过程中发生错误，请稍后再试', 'error')
                return render_template('auth/login.html', form=form, email=email, mobile_device=mobile_device)
        finally:
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

            # 计算会话过期时间
            from datetime import datetime, timedelta
            from flask import current_app
            expiry_time = datetime.now() + current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=2))

            new_session = UserSession(
                user_id=user.id,
                session_id=request.cookies.get('zb_session'),
                device_type=device_type,
                browser=browser,
                platform=platform,
                ip_address=request.remote_addr,  # 记录登录 IP 地址
                access_token=access_token,
                refresh_token=refresh_token,
                expiry_time=expiry_time  # 添加必需的 expiry_time 参数
            )
            db.session.add(new_session)
            db.session.commit()
    else:
        if request.is_json:
            return jsonify({
                'success': False,
                'message': '无效的电子邮件或密码'
            }), 401
        else:
            flash('无效的电子邮件或密码', 'error')
            # 确保在非JSON请求中也返回响应对象
            return render_template('auth/login.html', form=form, email=email, mobile_device=mobile_device)
