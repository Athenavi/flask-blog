import requests
from flask import jsonify, redirect, render_template

from src.error import error
from src.user.authz.login import tp_mail_login
from src.utils.security.ip_utils import get_client_ip
from src.utils.security.safe import run_security_checks


def cc_login(provider, domain, api_host, app_id, app_key):
    if run_security_checks(api_host):
        pass
    else:
        return error(message="彩虹聚合登录API接口配置错误,您的程序无法使用第三方登录", status_code='503'), 503
    if provider not in ['qq', 'wx', 'alipay', 'sina', 'baidu', 'huawei', 'xiaomi', 'dingtalk', 'douyin']:
        return jsonify({'message': 'Invalid login provider'})

    redirect_uri = domain + "callback/" + provider

    api_safe_check = [api_host, app_id, app_key]
    if 'error' in api_safe_check:
        return error(message=api_safe_check, status_code='503'), 503
    login_url = f'{api_host}connect.php?act=login&appid={app_id}&appkey={app_key}&type={provider}&redirect_uri={redirect_uri}'
    response = requests.get(login_url)
    data = response.json()
    code = data.get('code')
    msg = data.get('msg')
    if code == 0:
        cc_url = data.get('url')
    else:
        return error(message=msg, status_code='503')

    return redirect(cc_url, 302)


def callback(provider, request, api_host, app_id, app_key):
    if provider not in ['qq', 'wx', 'alipay', 'sina', 'baidu', 'huawei', 'xiaomi', 'dingtalk']:
        return jsonify({'message': 'Invalid login provider'})

    authorization_code = request.args.get('code')

    callback_url = f'{api_host}connect.php?act=callback&appid={app_id}&appkey={app_key}&type={provider}&code={authorization_code}'

    response = requests.get(callback_url)
    data = response.json()
    code = data.get('code')
    msg = data.get('msg')
    if code == 0:
        social_uid = data.get('social_uid')
        ip = get_client_ip(request)
        user_email = social_uid + f"@{provider}.com"
        return tp_mail_login(user_email, ip)

    return render_template('LoginRegister.html', error=msg)
