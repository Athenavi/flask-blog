import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

from src.other.rand import generate_random_text

# 加载 .env 文件
load_dotenv()


def get_sqlalchemy_uri(db_config):
    """获取SQLAlchemy数据库URI，支持多种数据库引擎"""
    db_engine = db_config.get('db_engine', 'postgresql').lower()
    db_host = db_config.get('db_host')
    db_user = db_config.get('db_user')
    db_port = db_config.get('db_port')
    db_name = db_config.get('db_name')
    db_password = db_config.get('db_password')

    # 检查必要配置
    if db_engine != 'sqlite' and not all([db_host, db_user, db_port, db_name]):
        print(
            'The database connection configuration is incomplete. Please check the .env file or environment variables.')
        print('please check console output for more details.')

    # 根据数据库引擎构建URI
    if db_engine == 'sqlite':
        # SQLite使用文件路径
        sqlalchemy_uri = f"sqlite:///{db_name or 'app.db'}"

    elif db_engine == 'mysql':
        password_part = f":{db_password}" if db_password else ""
        sqlalchemy_uri = f"mysql+pymysql://{db_user}{password_part}@{db_host}:{db_port}/{db_name}"

    elif db_engine == 'oracle':
        password_part = f":{db_password}" if db_password else ""
        sqlalchemy_uri = f"oracle+cx_oracle://{db_user}{password_part}@{db_host}:{db_port}/?service_name={db_name}"

    elif db_engine == 'mssql':
        password_part = f":{db_password}" if db_password else ""
        sqlalchemy_uri = f"mssql+pyodbc://{db_user}{password_part}@{db_host}:{db_port}/{db_name}?driver=ODBC+Driver+17+for+SQL+Server"

    else:  # PostgreSQL (默认)
        password_part = f":{db_password}" if db_password else ""
        sqlalchemy_uri = f"postgresql+psycopg2://{db_user}{password_part}@{db_host}:{db_port}/{db_name}"

    # 安全日志，如果密码存在则隐藏
    if db_password:
        safe_uri = sqlalchemy_uri.replace(db_password, '***')
    else:
        safe_uri = sqlalchemy_uri

    print(f"数据库引擎: {db_engine}")
    print(f"SQLAlchemy URI: {safe_uri}")

    return sqlalchemy_uri


class BaseConfig:
    """基础配置类"""
    global_encoding = 'utf-8'
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    SECRET_KEY = os.environ.get('SECRET_KEY') or generate_random_text(32)

    # 使用条件判断处理可能的 None 值
    jwt_expiration = os.getenv('JWT_EXPIRATION_DELTA')
    JWT_EXPIRATION_DELTA = int(jwt_expiration) if jwt_expiration is not None else 7200

    refresh_expiration = os.getenv('REFRESH_TOKEN_EXPIRATION_DELTA')
    REFRESH_TOKEN_EXPIRATION_DELTA = int(refresh_expiration) if refresh_expiration is not None else 64800

    TIME_ZONE = os.getenv('TIME_ZONE') or 'Asia/Shanghai'

    domain_env = os.getenv('DOMAIN')
    domain = (domain_env.rstrip('/') + '/') if domain_env is not None else '/'

    sitename = os.getenv('TITLE') or 'zyblog'
    beian = os.getenv('BEIAN') or '京ICP备12345678号'

    # 数据库引擎配置
    DB_ENGINE = os.getenv('DB_ENGINE', 'postgresql').lower()

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
    USER_FREE_STORAGE_LIMIT = 0.5 * 1024 * 1024 * 1024  # 512MB 用户免费空间限制


class AppConfig(BaseConfig):
    """应用配置类，可以继承基础配置并进行覆盖或添加"""
    db_engine = os.environ.get('DB_ENGINE') or os.getenv('DB_ENGINE', 'postgresql')
    db_host = os.environ.get('DB_HOST') or os.getenv('DATABASE_HOST', 'localhost')
    db_user = os.environ.get('DB_USER') or os.getenv('DATABASE_USER', 'postgres')
    db_name = os.environ.get('DB_NAME') or os.getenv('DATABASE_NAME')
    db_password = os.environ.get('DB_PASSWORD') or os.getenv('DATABASE_PASSWORD')
    db_port_env = os.environ.get('DB_PORT') or os.getenv('DATABASE_PORT')
    db_port = int(db_port_env) if db_port_env is not None else 5432
    db_pool_size_env = os.environ.get('DB_POOL_SIZE') or os.getenv('DATABASE_POOL_SIZE')
    db_pool_size = int(db_pool_size_env) if db_pool_size_env is not None else 16

    # 配置连接池参数
    @property
    def SQLALCHEMY_DATABASE_URI(self):
        """动态获取数据库URI"""
        return get_sqlalchemy_uri({
            'db_engine': self.db_engine,
            'db_host': self.db_host,
            'db_user': self.db_user,
            'db_port': self.db_port,
            'db_name': self.db_name,
            'db_password': self.db_password
        })

    @property
    def pool_config(self):
        """动态获取连接池配置"""
        if self.db_engine == 'sqlite':
            return {}
        else:
            return {
                "pool_size": int(self.db_pool_size),
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


class WechatPayConfig:
    # 微信支付配置 (服务商模式或直连模式)
    WECHAT_APPID = os.getenv('WECHAT_APPID')  # 小程序/公众号AppID
    WECHAT_MCHID = os.getenv('WECHAT_MCHID')  # 商户号
    WECHAT_API_V3_KEY = os.getenv('WECHAT_API_V3_KEY')  # APIv3密钥

    private_key_path = Path('keys/wechat/private_key.pem')
    WECHAT_PRIVATE_KEY = private_key_path.read_text() if private_key_path.exists() else None  # 商户私钥
    WECHAT_CERT_SERIAL_NO = os.getenv('WECHAT_CERT_SERIAL_NO')  # 证书序列号
    WECHAT_NOTIFY_URL = os.getenv('WECHAT_NOTIFY_URL', 'https://yourdomain.com/api/payment/wechat/notify')
    WECHAT_CERT_DIR = './cert'


class AliPayConfig:
    # 支付宝配置
    ALIPAY_APPID = os.getenv('ALIPAY_APPID')
    ALIPAY_DEBUG = os.getenv('ALIPAY_DEBUG', True)  # 沙箱模式设为True
    ALIPAY_GATEWAY = 'https://openapi.alipaydev.com/gateway.do' if ALIPAY_DEBUG else 'https://openapi.alipay.com/gateway.do'
    ALIPAY_RETURN_URL = os.getenv('ALIPAY_RETURN_URL', 'https://yourdomain.com/payment/success')  # 同步回调(网页支付)
    ALIPAY_NOTIFY_URL = os.getenv('ALIPAY_NOTIFY_URL', 'https://yourdomain.com/api/payment/alipay/notify')  # 异步回调
    # 密钥字符串 (推荐从环境变量或文件读取)
    private_key_path = Path('keys/alipay/app_private_key.pem')
    ALIPAY_PRIVATE_KEY_STRING = private_key_path.read_text() if private_key_path.exists() else None
    public_key_path = Path('keys/alipay/alipay_public_key.pem')
    ALIPAY_PUBLIC_KEY_STRING = public_key_path.read_text() if public_key_path.exists() else None


app_config = AppConfig()
