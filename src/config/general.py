import os

from dotenv import load_dotenv

from src.other.rand import generate_random_text


def get_general_config():
    load_dotenv()

    domain = os.getenv('DOMAIN').rstrip('/') + '/'
    title = os.getenv('TITLE') or 'zyblog'
    beian = os.getenv('BEIAN') or '京ICP备12345678号'

    return domain, title, beian


def zy_safe_conf():
    load_dotenv()
    secret_key = os.getenv('SECRET_KEY') or generate_random_text(16)
    jwt_expiration_delta = int(os.getenv('JWT_EXPIRATION_DELTA')) or 7200
    refresh_token_expiration_delta = int(os.getenv('REFRESH_TOKEN_EXPIRATION_DELTA')) or 64800
    time_zone = os.getenv('TIME_ZONE') or 'Asia/Shanghai'
    return secret_key, jwt_expiration_delta, refresh_token_expiration_delta, time_zone
