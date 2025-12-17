import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

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
    SECRET_KEY = os.environ.get('SECRET_KEY')

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
    RATELIMIT_DEFAULT = "10/second"
    # 邮件配置
    # MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.example.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', True)
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    BABEL_DEFAULT_LOCALE = 'zh_CN'
    BABEL_DEFAULT_TIMEZONE = 'Asia/Shanghai'
    BABEL_SUPPORTED_LOCALES = ['zh_CN', "en"]
    BABEL_TRANSLATION_DIRECTORIES = 'translations'
    # jwt
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=JWT_EXPIRATION_DELTA)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=REFRESH_TOKEN_EXPIRATION_DELTA)
    JWT_ACCESS_COOKIE_NAME = 'access_token'
    JWT_REFRESH_COOKIE_NAME = 'refresh_token'
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_COOKIE_SECURE = False
    JWT_COOKIE_CSRF_PROTECT = False
    JWT_SESSION_COOKIE = False
    REMEMBER_COOKIE_DURATION = timedelta(days=30)  # 记住登录状态30天
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)

    # 直播配置
    RTMP_SERVER = os.environ.get('RTMP_SERVER', 'rtmp://localhost/live')
    HTTP_LIVE_SERVER = os.environ.get('HTTP_LIVE_SERVER', 'http://localhost:8080/hls')
    LIVE_SECRET_KEY = os.environ.get('LIVE_SECRET_KEY', 'default_secret')
    LIVE_LOCAL_MODE = os.environ.get('LIVE_LOCAL_MODE', 'False').lower() == 'true'

    # 安全头配置（Talisman）
    TALISMAN_CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': ["'self'", "cdn.example.com"],
        'style-src': ["'self'", "'unsafe-inline'"]
    }


class AppConfig(BaseConfig):
    """应用配置类，可以继承基础配置并进行覆盖或添加"""
    def __init__(self):
        super().__init__()
        # 初始化数据库URI
        self.SQLALCHEMY_DATABASE_URI = self._get_database_uri()
        
    db_engine = os.environ.get('DB_ENGINE') or os.getenv('DB_ENGINE', 'postgresql')
    db_host = os.environ.get('DB_HOST') or os.getenv('DATABASE_HOST', 'localhost')
    db_user = os.environ.get('DB_USER') or os.getenv('DATABASE_USER', 'postgres')
    db_name = os.environ.get('DB_NAME') or os.getenv('DATABASE_NAME')
    db_password = os.environ.get('DB_PASSWORD') or os.getenv('DATABASE_PASSWORD')
    db_port_env = os.environ.get('DB_PORT') or os.getenv('DATABASE_PORT')
    db_port = int(db_port_env) if db_port_env is not None else 5432
    db_pool_size_env = os.environ.get('DB_POOL_SIZE') or os.getenv('DATABASE_POOL_SIZE')
    db_pool_size = int(db_pool_size_env) if db_pool_size_env is not None else 16

    def _get_database_uri(self):
        """获取数据库URI"""
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

    # 私钥可以是文件路径或者直接的内容
    private_key_env = os.getenv('WECHAT_PRIVATE_KEY')
    if private_key_env:
        # 如果环境变量中提供了私钥内容或者是文件路径
        WECHAT_PRIVATE_KEY = private_key_env
    else:
        # 默认从文件读取
        private_key_path = Path('keys/wechat/private_key.pem')
        WECHAT_PRIVATE_KEY = None
        if private_key_path.exists():
            try:
                WECHAT_PRIVATE_KEY = private_key_path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                # 尝试使用其他编码读取文件
                try:
                    WECHAT_PRIVATE_KEY = private_key_path.read_text(encoding='gbk')
                except UnicodeDecodeError:
                    # 如果仍然失败，以二进制方式读取
                    WECHAT_PRIVATE_KEY = private_key_path.read_bytes().decode('utf-8', errors='ignore')
    
    WECHAT_CERT_SERIAL_NO = os.getenv('WECHAT_CERT_SERIAL_NO')  # 证书序列号
    WECHAT_NOTIFY_URL = os.getenv('WECHAT_NOTIFY_URL', 'https://yourdomain.com/api/payment/wechat/notify')
    WECHAT_CERT_DIR = os.getenv('WECHAT_CERT_DIR', './cert')


class AliPayConfig:
    # 支付宝配置

    def __init__(self):
        # 延迟导入以避免循环导入
        try:
            from src.blueprints.blog import get_site_domain
            # 获取domain，优先使用get_site_domain()函数获取的值
            domain = get_site_domain() or os.getenv('DOMAIN')
            domain = (domain.rstrip('/') + '/') if domain is not None else '/'
        except Exception:
            # 如果获取失败，则使用环境变量或默认值
            domain = os.getenv('DOMAIN', 'http://localhost:9421/')
            domain = (domain.rstrip('/') + '/') if domain is not None else '/'
        
        if domain is None:
            print("域名配置有问题")

        self.ALIPAY_APPID = os.getenv('ALIPAY_APPID')
        self.ALIPAY_DEBUG = os.getenv('ALIPAY_DEBUG', 'True').lower() == 'true'  # 沙箱模式设为True
        self.ALIPAY_GATEWAY = 'https://openapi.alipaydev.com/gateway.do' if self.ALIPAY_DEBUG else 'https://openapi.alipay.com/gateway.do'
        self.ALIPAY_RETURN_URL = os.getenv('ALIPAY_RETURN_URL', f'{domain}api/payment/alipay/return')  # 同步回调(网页支付)
        self.ALIPAY_NOTIFY_URL = os.getenv('ALIPAY_NOTIFY_URL', f'{domain}api/payment/alipay/notify')  # 异步回调
        # 密钥字符串 (推荐从环境变量或文件读取)
        private_key_path = Path('keys/alipay/app_private_key.pem')
        self.ALIPAY_PRIVATE_KEY_STRING = private_key_path.read_text(encoding='utf-8') if private_key_path.exists() else None
        public_key_path = Path('keys/alipay/alipay_public_key.pem')
        self.ALIPAY_PUBLIC_KEY_STRING = public_key_path.read_text(encoding='utf-8') if public_key_path.exists() else None


# 延迟导入以避免循环导入
def get_app_config():
    from src.other.rand import generate_random_text
    # 更新BaseConfig中的SECRET_KEY
    BaseConfig.SECRET_KEY = os.environ.get('SECRET_KEY') or generate_random_text(32)

    # 获取domain环境变量
    domain_env = os.getenv('DOMAIN')
    BaseConfig.domain = (domain_env.rstrip('/') + '/') if domain_env is not None else '/'

    # 创建AppConfig实例并初始化数据库URI
    config = AppConfig()
    return config


app_config = get_app_config()


class ProductionConfig(AppConfig):
    """生产环境配置"""
    def __init__(self):
        super().__init__()
        self.DEBUG = False
        self.TESTING = False

    
class DevelopmentConfig(AppConfig):
    """开发环境配置"""
    def __init__(self):
        super().__init__()
        self.DEBUG = True
        self.TESTING = False

    
class TestingConfig(AppConfig):
    """测试环境配置"""
    def __init__(self):
        super().__init__()
        self.DEBUG = True
        self.TESTING = True
