from datetime import datetime, timezone

from flask import Flask, send_file, jsonify
from flask_migrate import Migrate
from jinja2 import select_autoescape
from werkzeug.exceptions import NotFound
from werkzeug.middleware.proxy_fix import ProxyFix

from src.blog.article.core.views import blog_detail_back
from src.blueprints.admin_vip import admin_vip_bp
from src.blueprints.api import api_bp
from src.blueprints.auth import auth_bp
from src.blueprints.category import category_bp
from src.blueprints.dashboard import dashboard_bp
from src.blueprints.media import media_bp
from src.blueprints.my import my_bp
from src.blueprints.noti import noti_bp
from src.blueprints.other import other_bp
from src.blueprints.relation import relation_bp
from src.blueprints.role import role_bp
from src.blueprints.theme import theme_bp
from src.blueprints.vip_routes import vip_bp
from src.blueprints.website import website_bp
from src.error import error
from src.extensions import cache
from src.models import db
from src.other.filters import json_filter, string_split, article_author, md2html, relative_time_filter, category_filter, \
    f2list
from src.other.search import search_handler
from src.plugin import plugin_bp, init_plugin_manager
from src.setting import app_config
from src.user.authz.decorators import jwt_required
from src.utils.security.jwt_handler import JWTHandler


def create_app(config_class=app_config):
    """应用工厂函数"""
    app = Flask(
        __name__,
        template_folder=f'{config_class.base_dir}/templates',
        static_folder=f'{config_class.base_dir}/static'
    )

    # 加载配置
    app.config.from_object(config_class)

    # 初始化扩展
    db.init_app(app)
    cache.init_app(app)

    # 初始化 Migrate（需要在 db.init_app 之后）
    Migrate(app, db)

    # 配置代理中间件
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

    # 配置 Jinja2 环境
    app.jinja_env.autoescape = select_autoescape(['html', 'xml'])
    app.jinja_env.add_extension('jinja2.ext.loopcontrols')

    # 注册模板过滤器
    register_template_filters(app)

    # 注册上下文处理器
    register_context_processors(app, config_class)

    # 注册直接路由
    register_direct_routes(app, config_class)

    # 注册蓝图
    register_blueprints(app)

    # 初始化插件管理器
    init_plugin_manager(app)

    # 配置日志
    configure_logging(app)

    # 打印运行信息
    print_startup_info(config_class)

    return app


def register_context_processors(app, config_class):
    """注册上下文处理器"""

    @app.context_processor
    def inject_variables():
        return dict(
            beian=config_class.beian,
            title=config_class.sitename,
            username=JWTHandler.get_current_username(),
            domain=config_class.domain
        )


def register_direct_routes(app, config_class):
    """注册直接定义在应用上的路由"""

    @app.route('/search', methods=['GET', 'POST'])
    @jwt_required
    def search(user_id):
        return search_handler(user_id, config_class.domain, config_class.global_encoding,
                              app.config['MAX_CACHE_TIMESTAMP'])

    @app.route('/favicon.ico', methods=['GET'])
    def favicon():
        return send_file(f'{config_class.base_dir}/static/favicon.ico', mimetype='image/png', max_age=3600)

    @app.route('/p/<slug_name>', methods=['GET', 'POST'])
    def blog_detail(slug_name):
        return blog_detail_back(blog_slug=slug_name)

    @app.route('/health')
    def health_check():
        """健康检查端点"""
        return jsonify({
            "status": "healthy",
            "message": "Application is running",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    @app.errorhandler(500)
    @app.errorhandler(Exception)
    def handle_error(e):
        if isinstance(e, NotFound):
            return error(message="页面未找到", status_code=404)
        elif isinstance(e, Exception):
            return error(message="服务器错误", status_code=500)
        else:
            return error(message="未知错误", status_code=500)

    @app.route('/<path:undefined_path>')
    def undefined_route(undefined_path):
        error_message = f"Undefined path: {undefined_path}"
        app.logger.error(error_message)
        return error(message=error_message, status_code=500)


def register_template_filters(app):
    """注册模板过滤器"""
    app.add_template_filter(json_filter, 'fromjson')
    app.add_template_filter(string_split, 'string.split')
    app.add_template_filter(article_author, 'Author')
    app.add_template_filter(md2html, 'md2html')
    app.add_template_filter(relative_time_filter, 'relative_time')
    app.add_template_filter(category_filter, 'CategoryName')
    app.add_template_filter(f2list, 'F2list')


def register_blueprints(app):
    """注册所有蓝图"""
    app.register_blueprint(media_bp)
    app.register_blueprint(theme_bp)
    app.register_blueprint(website_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(my_bp)
    app.register_blueprint(relation_bp)
    app.register_blueprint(role_bp)
    app.register_blueprint(category_bp)
    app.register_blueprint(noti_bp)
    app.register_blueprint(plugin_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(other_bp)
    app.register_blueprint(vip_bp)
    app.register_blueprint(admin_vip_bp)


def configure_logging(app):
    """配置日志"""
    # 移除默认的日志处理程序
    app.logger.handlers = []
    app.logger.info("app.py logging已启动，并使用全局日志配置。")


def print_startup_info(config_class):
    """打印启动信息"""
    print(f"running at: {config_class.base_dir}")
    print("sys information")
    domain = config_class.domain.rstrip('/') + '/'
    print("++++++++++==========================++++++++++")
    print(
        f'\n domain: {domain} \n title: {config_class.sitename} \n beian: {config_class.beian} \n')

    # 安全检查
    if config_class.SECRET_KEY == 'your-secret-key-here':
        print("WARNING: 应用存在被破解的风险，请修改 SECRET_KEY 变量的值")
        print("WARNING: 请修改 SECRET_KEY 变量的值")
        print("WARNING: 请修改 SECRET_KEY 变量的值")
        print("WARNING: 请修改 SECRET_KEY 变量的值")

    print("++++++++++==========================++++++++++")
