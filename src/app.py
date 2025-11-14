from datetime import datetime, timezone

from flask import Flask, jsonify, g
from flask_principal import identity_loaded, RoleNeed
from jinja2 import select_autoescape
from werkzeug.exceptions import NotFound
from werkzeug.middleware.proxy_fix import ProxyFix

from auth import jwt_required
from security import PermissionNeed
from src.blueprints.admin_vip import admin_vip_bp
from src.blueprints.api import api_bp
from src.blueprints.auth import auth_bp
from src.blueprints.blog import blog_bp, get_footer, get_site_title, get_banner, get_site_domain, get_site_beian, \
    get_site_menu, get_current_menu_slug, blog_detail_back, get_username
from src.blueprints.category import category_bp
from src.blueprints.dashboard import admin_bp
from src.blueprints.media import media_bp
from src.blueprints.my import my_bp
from src.blueprints.noti import noti_bp
from src.blueprints.relation import relation_bp
from src.blueprints.role import role_bp
from src.blueprints.session_views import session_bp
from src.blueprints.theme import theme_bp
from src.blueprints.vip_routes import vip_bp
from src.blueprints.website import website_bp
from src.error import error
from src.extensions import init_extensions, login_manager, csrf
from src.other.filters import json_filter, string_split, article_author, md2html, relative_time_filter, category_filter, \
    f2list
from src.other.search import search_handler
from src.plugin import plugin_bp, init_plugin_manager
from src.scheduler import session_scheduler
from src.setting import app_config


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
    init_extensions(app)
    # 初始化定时任务
    session_scheduler.init_app(app)

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

    print_startup_info(config_class)

    return app


def register_context_processors(app, config_class):
    """注册上下文处理器"""
    default_menu_data = [{'id': 1, 'title': '我的', 'url': '/profile', 'target': '_blank', 'order_index': 0},
                         {'id': 3, 'title': '推荐', 'url': '/featured', 'target': '_self', 'order_index': 1}]

    @app.context_processor
    def inject_variables():
        return dict(
            beian=get_site_beian() or config_class.beian,
            title=get_site_title() or config_class.sitename,
            domain=get_site_domain() or config_class.domain,
            username=get_username(),
            menu=get_site_menu(get_current_menu_slug()) or default_menu_data,
            footer=get_footer(),
            banner=get_banner()
        )


def register_direct_routes(app, config_class):
    """注册直接定义在应用上的路由"""

    @login_manager.user_loader
    def load_user(user_id):
        from src.models.user import User, db
        user = db.session.query(User).filter_by(id=user_id).first()
        return user

    # 身份加载信号处理器
    @identity_loaded.connect_via(app)
    def on_identity_loaded(sender, identity):
        """当身份加载时，设置用户拥有的角色和权限"""
        if hasattr(identity, 'id') and identity.id:
            from src.models import User
            user = User.query.get(identity.id)
            if user:
                # 添加用户角色
                identity.provides.add(RoleNeed('authenticated'))

                # 添加用户拥有的所有角色
                for role in user.roles:
                    identity.provides.add(RoleNeed(role.name))

                    # 添加角色对应的所有权限
                    for permission in role.permissions:
                        identity.provides.add(PermissionNeed(permission.code))

    @app.after_request
    def after_request(response):
        # 设置新的 access_token 如果存在
        if hasattr(g, 'new_access_token'):
            response.set_cookie(
                'access_token',
                g.new_access_token,
                httponly=True,
                secure=app.config.get('PREFER_SECURE', False)
            )
        return response

    from flask import redirect
    @app.route('/space')
    @app.route('/profile')
    @jwt_required
    def profile(user_id):
        """当前用户的个人资料页面"""
        return redirect(f'/space/{user_id}')

    @app.route('/search', methods=['GET', 'POST'])
    @jwt_required
    def search(user_id):
        return search_handler(user_id, config_class.domain, config_class.global_encoding,
                              app.config['MAX_CACHE_TIMESTAMP'])

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

    from flask_login import login_required
    @app.route('/debug')
    @login_required
    def debug_point():
        """调试端点"""
        return jsonify({
            "status": "debug",
            "message": "Debug point",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    @app.errorhandler(404)
    @app.errorhandler(500)
    @app.errorhandler(Exception)
    def handle_error(e):
        # 记录详细错误信息到日志
        app.logger.error(f"Error: {str(e)}")

        # 根据异常类型返回不同的响应
        if isinstance(e, NotFound):
            # 返回 404 错误页面或 JSON 响应
            return error(404, "Page Not Found")
        else:
            # 返回 500 错误页面或 JSON 响应
            return error(500, "Internal Server Error")

    from flask_principal import PermissionDenied

    @app.errorhandler(PermissionDenied)
    def handle_permission_denied(error):
        return jsonify({
            'error': '权限不足',
            'message': '您没有执行此操作的权限'
        }), 403

    @app.route('/<path:undefined_path>')
    def undefined_route(undefined_path):
        error_message = f"Undefined path: {undefined_path}"
        app.logger.error(error_message)
        return error(message=error_message, status_code=404)


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
    blueprints = [
        media_bp,
        theme_bp,
        website_bp,
        admin_bp,
        my_bp,
        relation_bp,
        role_bp,
        category_bp,
        noti_bp,
        plugin_bp,
        api_bp,
        blog_bp,
        vip_bp,
        admin_vip_bp,
        session_bp
    ]

    for bp in blueprints:
        app.register_blueprint(bp)
        app.logger.info(f"=====Blueprint {bp.name} load success.=====")
        if bp != auth_bp:
            csrf.exempt(bp)

    app.register_blueprint(auth_bp)


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
