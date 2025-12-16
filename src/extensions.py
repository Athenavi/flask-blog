import flask_monitoringdashboard as dashboard
from flask import Flask
from flask_babel import Babel
from flask_caching import Cache
from flask_cors import CORS
from flask_jwt_extended import JWTManager
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
dashboard = dashboard


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
    # talisman.init_app(app)
    # limiter.init_app(app)
    babel.init_app(app)
    principal.init_app(app)
    # 登录管理器额外配置
    login_manager.login_view = 'auth.login'
    login_manager.login_message = '请先登录'

    # 初始化SocketIO
    # 让 Flask-SocketIO 自动选择最佳异步模式
    socketio.init_app(app)

    # JWT配置
    jwt.init_app(app)

    # 初始化直播服务
    from services.live import LiveStreamService
    live_service = LiveStreamService(app)
    # 将 live_service 添加到 app 对象上，避免导入问题
    app.live_service = live_service
    
    # 配置监控面板
    try:
        # 检查配置文件是否存在，如果不存在则创建一个基本配置
        import os
        config_file = 'dashboard_config.cfg'
        if not os.path.exists(config_file):
            with open(config_file, 'w') as f:
                f.write(f"""
[dashboard]
APP_VERSION=1.0
CUSTOM_LINK=dashboard
MONITOR_LEVEL=3
OUTDATED_THRESHOLD=3600
GIT=
ENABLE_LOGGING=True
                    """)
        
        dashboard.config.init_from(file=config_file)
        # 绑定应用
        dashboard.bind(app)
        if hasattr(dashboard, 'blueprint'):
            csrf.exempt(dashboard.blueprint)
    except Exception as e:
        app.logger.error(f"Failed to initialize Flask-MonitoringDashboard: {str(e)}")
        # 即使监控面板初始化失败，也不影响主应用运行