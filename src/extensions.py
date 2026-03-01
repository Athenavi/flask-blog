"""扩展模块，初始化Flask扩展实例"""

from flask_babel import Babel
from flask_caching import Cache
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_principal import Principal
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# 初始化扩展实例
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
babel = Babel()
mail = Mail()
cache = Cache()
jwt = JWTManager()
cors = CORS()
csrf = CSRFProtect()
principal = Principal()

# 条件导入SocketIO以支持serverless部署
try:
    from flask_socketio import SocketIO

    socketio = SocketIO()
    SOCKETIO_AVAILABLE = True
except ImportError:
    SocketIO = None
    # 创建一个模拟的SocketIO对象，用于serverless环境
    class MockSocketIO:
        def init_app(self, app, **kwargs):
            pass

        def emit(self, event, *args, **kwargs):
            # 在serverless环境中忽略socket事件
            pass

        def on_event(self, event, handler):
            pass


    socketio = MockSocketIO()
    SOCKETIO_AVAILABLE = False

# 限流器 - 使用内存存储
limiter = Limiter(
    key_func=get_remote_address,  # 使用客户端IP作为限流键
    default_limits=["200 per day", "50 per hour"]  # 默认限制
)


def init_extensions(app):
    """初始化所有扩展"""
    # 初始化数据库
    db.init_app(app)
    migrate.init_app(app, db)

    # 初始化登录管理
    login_manager.init_app(app)
    login_manager.login_view = 'auth_bp.login'  # 设置登录视图
    login_manager.login_message = '请先登录以访问此页面。'  # 设置登录消息

    # 初始化其他扩展
    babel.init_app(app)
    mail.init_app(app)
    cache.init_app(app)
    jwt.init_app(app)
    cors.init_app(app)
    csrf.init_app(app)
    principal.init_app(app)

    # 初始化限流器
    limiter.init_app(app)

    # 初始化SocketIO（如果可用）
    if SOCKETIO_AVAILABLE:
        # 初始化SocketIO
        socketio.init_app(app, async_mode='gevent')
    else:
        app.logger.info("SocketIO not available, running in serverless mode")

    # 配置登录管理器的匿名用户
    from flask_login import AnonymousUserMixin

    class AnonyUser(AnonymousUserMixin):
        id = -1
        permissions = []

        def __init__(self):
            self.id = -1
            self.permissions = []

        @staticmethod
        def can(perm):
            # 匿名用户没有任何权限
            return False

    login_manager.anonymous_user = AnonyUser
