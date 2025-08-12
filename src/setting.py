import os
from datetime import timedelta
from src.config.general import get_general_config
from src.database import get_sqlalchemy_uri


class BaseConfig:
    """基础配置类"""
    global_encoding = 'utf-8'
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    domain, sitename, beian, sys_version, api_host, app_id, app_key, DEFAULT_KEY = get_general_config()

    SQLALCHEMY_DATABASE_URI = get_sqlalchemy_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    CACHE_TYPE = 'simple'
    SESSION_COOKIE_NAME = 'zb_session'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=48)
    TEMP_FOLDER = 'temp/upload'
    AVATAR_SERVER = "https://api.7trees.cn/avatar"
    ALLOWED_MIMES = [
        # 常见图片格式
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/bmp',
        'image/tiff',
        'image/webp',
        # 常见视频格式
        'video/mp4',
        'video/avi',
        'video/mpeg',
        'video/quicktime',
        'video/x-msvideo',
        'video/mp2t',
        'video/x-flv',
        'video/webm',
        'video/x-m4v',
        'video/3gpp',
        # 常见音频格式
        'audio/wav',
        'audio/mpeg',
        'audio/ogg',
        'audio/flac',
        'audio/aac',
        'audio/mp3',
    ]
    UPLOAD_LIMIT = 60 * 1024 * 1024
    MAX_LINE = 1000
    MAX_CACHE_TIMESTAMP = 7200


class AppConfig(BaseConfig):
    """应用配置类，可以继承基础配置并进行覆盖或添加"""

    pass

