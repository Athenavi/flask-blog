import hashlib
import random
import re
import string

import requests

from src.config.general import cloudflare_turnstile_conf


def run_security_checks(url):
    pattern = r"^(https?://)?([a-zA-Z0-9-]+\.)*[a-zA-Z]{2,}(\/)$"
    if re.match(pattern, url):
        return True
    else:
        return False


def clean_html_format(text):
    clean_text = re.sub('<.*?>', '', str(text))
    return clean_text


def filter_sensitive_words(comment_content):
    sensitive_words = ['违禁词1', '违禁词2', '敏感词1', '敏感词2']

    comment_content_lower = comment_content.lower()
    for word in sensitive_words:
        if word in comment_content_lower:
            return False

    return True


def random_string(param):
    return ''.join(random.sample(string.ascii_letters + string.digits, param))


def is_valid_hash(length, f_hash):
    """
    验证哈希值是否为指定长度的十六进制字符串
    :param length: 哈希值的预期长度
    :param f_hash: 哈希值字符串
    :return: 如果哈希值有效则返回 True，否则返回 False
    """
    if f_hash is None or not isinstance(f_hash, str) or len(f_hash) != length or not all(
            c in '0123456789abcdef' for c in f_hash.lower()):
        return False
    return True


def verify_api_request(request):
    site_key, turnstile_secret_key = cloudflare_turnstile_conf()
    if site_key is None:
        return 'success'
    token = request.form.get('cf-turnstile-response')
    if not token:
        return ['missing-input-response']
    client_ip = request.headers.get('CF-Connecting-IP') or request.remote_addr
    verify_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = {
        'secret': turnstile_secret_key,
        'response': token,
        'remoteip': client_ip
    }

    try:
        response = requests.post(verify_url, data=data, timeout=10)
        result = response.json()
    except requests.exceptions.RequestException as e:
        print(f"请求失败: {e}")
        return ['internal-error']
    if not result.get('success'):
        error_codes = result.get('error-codes', ['unknown-error'])
        print(f"验证失败，错误代码: {error_codes}")
        return error_codes

    return "success"


def gen_qr_token(input_string, current_time, sys_version, encoding='utf-8'):
    ct = current_time
    rd_num = random.randint(617, 1013)
    input_string = sys_version + ct + input_string + str(rd_num)
    # print(input_string)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode(encoding))
    return sha256_hash.hexdigest()
