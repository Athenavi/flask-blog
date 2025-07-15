from flask import Blueprint, request, redirect, url_for, render_template, make_response

from src.config.general import cloudflare_turnstile_conf
from src.user.authz.core import authenticate_jwt
from src.user.authz.login import user_login, create_user
from src.utils.security.ip_utils import get_client_ip
from src.utils.security.safe import verify_api_request

auth_bp = Blueprint('auth', __name__, template_folder='templates')


# 登录路由
@auth_bp.route('/login', methods=['POST', 'GET'])
def login():
    callback_route = request.args.get('callback', 'index_html')
    if request.cookies.get('jwt'):
        user_id = authenticate_jwt(request.cookies.get('jwt'))
        if user_id:
            return redirect(url_for(callback_route))
    site_key, turnstile_secret_key = cloudflare_turnstile_conf()
    if request.method == 'POST':
        captcha_result = verify_api_request(request)
        if captcha_result == 'success':
            return user_login(callback_route, site_key)
        else:
            return render_template('LoginRegister.html', title="登录", msg="验证失败，请重试", error=captcha_result,
                                   site_key=site_key)
    return render_template('LoginRegister.html', title="登录", site_key=site_key)


# 登出路由
@auth_bp.route('/logout')
def logout():
    response = make_response(redirect(url_for('auth.login')))
    response.set_cookie('jwt', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    return response


# 注册路由
@auth_bp.route('/register', methods=['POST', 'GET'])
def register():
    callback_route = request.args.get('callback', 'index_html')
    if request.cookies.get('jwt'):
        user_id = authenticate_jwt(request.cookies.get('jwt'))
        if user_id:
            return redirect(url_for(callback_route))
    ip = get_client_ip(request)
    site_key, turnstile_secret_key = cloudflare_turnstile_conf()
    return create_user(ip, site_key)
