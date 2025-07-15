import os

from dotenv import load_dotenv

from src.other.rand import generate_random_text


def get_general_config():
    load_dotenv()

    domain = os.getenv('DOMAIN')
    title = os.getenv('TITLE') or 'zyblog'
    beian = os.getenv('BEIAN') or '京ICP备12345678号'
    version = os.getenv('VERSION') or '2.0'
    api_host = os.getenv('API_HOST')
    app_id = os.getenv('APP_ID')
    app_key = os.getenv('APP_KEY')
    default_key = os.getenv('DEFAULT_KEY') or '237127'

    return domain, title, beian, version, api_host, app_id, app_key, default_key


def zy_safe_conf():
    load_dotenv()
    secret_key = os.getenv('SECRET_KEY') or generate_random_text(16)
    jwt_expiration_delta = int(os.getenv('JWT_EXPIRATION_DELTA')) or 7200
    refresh_token_expiration_delta = int(os.getenv('REFRESH_TOKEN_EXPIRATION_DELTA')) or 64800
    time_zone = os.getenv('TIME_ZONE') or 'Asia/Shanghai'
    return secret_key, jwt_expiration_delta, refresh_token_expiration_delta, time_zone


def cloudflare_turnstile_conf():
    load_dotenv()
    site_key = os.getenv('TURNSTILE_SITE_KEY')
    turnstile_secret_key = os.getenv('TURNSTILE_SECRET_KEY')
    if os.getenv('TURNSTILE_OPEN').lower() == 'false':
        site_key = None
        turnstile_secret_key = None
    return site_key, turnstile_secret_key


def show_files(path):
    # 指定目录的路径
    directory = path
    files = os.listdir(directory)
    return files
