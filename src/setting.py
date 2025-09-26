import os
from datetime import timedelta

from dotenv import load_dotenv

from src.config.general import get_general_config
from src.other.rand import generate_random_text

# 加载 .env 文件
load_dotenv()


def get_sqlalchemy_uri(db_config):
    """获取SQLAlchemy数据库URI，兼容空密码情况"""
    if not all(
            [db_config.get('db_host'), db_config.get('db_user'), db_config.get('db_port'), db_config.get('db_name')]):
        print('数据库连接配置不完整，请检查 .env 文件或环境变量。')
        return None

    # 构建SQLAlchemy数据库URI
    password_part = f":{db_config.get('db_password')}" if db_config.get('db_password') else ""
    sqlalchemy_uri = f"postgresql+psycopg2://{db_config.get('db_user')}{password_part}@{db_config.get('db_host')}:{db_config.get('db_port')}/{db_config.get('db_name')}"

    # 安全日志，如果密码存在则隐藏
    if db_config.get('db_password'):
        print(f"SQLAlchemy URI: {sqlalchemy_uri.replace(db_config.get('db_password'), '***')}")
    else:
        print(f"SQLAlchemy URI: {sqlalchemy_uri}")

    return sqlalchemy_uri


class BaseConfig:
    """基础配置类"""
    global_encoding = 'utf-8'
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    SECRET_KEY = os.environ.get('SECRET_KEY') or generate_random_text(32)
    domain, sitename, beian = get_general_config()

    # 注意：这里暂时设为None，在子类中具体设置
    SQLALCHEMY_DATABASE_URI = None
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
    db_host = os.environ.get('DB_HOST') or os.getenv('DATABASE_HOST', 'localhost')
    db_user = os.environ.get('DB_USER') or os.getenv('DATABASE_USER', 'postgres')
    db_port = int(os.environ.get('DB_PORT')) or int(os.getenv('DATABASE_PORT', 5432))
    db_name = os.environ.get('DB_NAME') or os.getenv('DATABASE_NAME')
    db_password = os.environ.get('DB_PASSWORD') or os.getenv('DATABASE_PASSWORD')
    db_pool_size = os.environ.get('DB_POOL_SIZE') or os.getenv('DATABASE_POOL_SIZE', '16')

    # 配置连接池参数
    pool_config = {
        "pool_size": int(db_pool_size),  # 连接池大小
        "max_overflow": 20,
        "pool_timeout": 5,
        "pool_recycle": 1200,
        "pool_pre_ping": True,
    }

    RedisConfig = {
        "host": os.environ.get('REDIS_HOST') or os.getenv('REDIS_HOST', 'localhost'),
        "port": os.environ.get('REDIS_PORT') or os.getenv('REDIS_PORT', 6379),
        "db": os.environ.get('REDIS_DB') or os.getenv('REDIS_DB', 0),
        "password": os.environ.get('REDIS_PASSWORD') or os.getenv('REDIS_PASSWORD') or None,
        "decode_responses": True,
        "socket_connect_timeout": 3,  # 连接超时3秒
        "socket_timeout": 3,  # 读写超时3秒
        "retry_on_timeout": True,  # 超时重试
        "max_connections": 10  # 连接池大小
    }

    # 在子类中设置数据库URI
    SQLALCHEMY_DATABASE_URI = get_sqlalchemy_uri({
        'db_host': db_host,
        'db_user': db_user,
        'db_port': db_port,
        'db_name': db_name,
        'db_password': db_password
    })
