from flask import Flask
from flask_babel import Babel
from flask_caching import Cache
from flask_cors import CORS
from flask_jwt_extended import JWTManager
# from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_principal import Principal
from flask_restful import Api
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

# 初始化扩展
db = SQLAlchemy()
cache = Cache()
login_manager = LoginManager()
csrf = CSRFProtect()
mail = Mail()
api = Api()
cors = CORS()
migrate = Migrate()
babel = Babel()
principal = Principal()
socketio = SocketIO()
jwt = JWTManager()
#talisman = Talisman()
limiter = Limiter(key_func=get_remote_address)


def init_extensions(app: Flask):
    """集中初始化所有扩展"""
    db.init_app(app)
    cache.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    api.init_app(app)
    cors.init_app(app)
    migrate.init_app(app, db)  # 需要关联数据库实例
    #talisman.init_app(app)
    limiter.init_app(app)
    babel.init_app(app)
    principal.init_app(app)
    # 登录管理器额外配置
    login_manager.login_view = 'auth.login'
    login_manager.login_message = '请先登录'

    # 初始化SocketIO
    # 明确指定使用gevent异步模式
    socketio.init_app(app, async_mode='gevent')

    # JWT配置
    jwt.init_app(app)
