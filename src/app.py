"""
主应用文件
负责应用工厂函数和核心配置"""

import logging
import os
from datetime import datetime, timezone

from flask import Flask, g, request
from flask import jsonify
from flask_principal import identity_loaded, RoleNeed
from werkzeug.exceptions import NotFound

from src.auth_utils import jwt_required
from src.blueprints.admin_vip import admin_vip_bp
from src.blueprints.analytics import analytics_bp
from src.blueprints.api import api_bp
from src.blueprints.auth_view import auth_bp
from src.blueprints.blog import blog_bp, get_site_beian, get_site_title, get_site_domain, get_username_no_check, \
    get_site_menu, get_current_menu_slug, get_footer, get_banner, blog_detail_back
from src.blueprints.category import category_bp
from src.blueprints.dashboard import admin_bp
from src.blueprints.media import media_bp
from src.blueprints.my import my_bp
from src.blueprints.noti import noti_bp
from src.blueprints.payment import payment_bp
from src.blueprints.relation import relation_bp
from src.blueprints.role import role_bp
from src.blueprints.seo import seo_bp
from src.blueprints.session_views import session_bp
# from src.blueprints.supabase_api import supabase_api_bp
# from src.blueprints.supabase_auth import supabase_auth_bp
from src.blueprints.theme import theme_bp
from src.blueprints.vip_routes import vip_bp
from src.blueprints.website import website_bp
from src.error import error
from src.extensions import limiter, csrf
from src.extensions import login_manager
from src.logger_config import init_optimized_logger
from src.other.search import search_handler
from src.plugin import plugin_bp
from src.security import PermissionNeed, init_security_headers
from src.setting import ProductionConfig
from src.utils.analytics import record_page_view
from src.utils.config_manager import config_manager
from src.utils.filters import json_filter, string_split, article_author, md2html, relative_time_filter, category_filter, \
    f2list
from src.utils.storage.s3_storage import s3_storage

# 条件导入大型库以减少函数大小
try:
    import gevent.monkey
    gevent.monkey.patch_all()
    print("Gevent monkey patching applied.")
except ImportError:
    gevent = None  # 定义 gevent 为 None 以避免未定义变量
    print("No gevent found. Skipping monkey patching. This is expected in serverless environments.")

# 初始化优化的日志系统
logger = init_optimized_logger()


def create_app(config_class=None):
    """应用工厂函数"""
    # 如果没有提供配置类，则使用默认的生产配置
    if config_class is None:
        config_class = ProductionConfig()

    static_folder = os.path.join(config_class.base_dir, 'static')
    templates_folder = os.path.join(config_class.base_dir, 'templates')

    # 导入Blueprints以避免循环导入
    app = Flask(__name__, template_folder=templates_folder, static_folder=static_folder, static_url_path='/static')
    app.config.from_object(config_class)

    # 初始化扩展
    from src.extensions import init_extensions
    init_extensions(app)

    # 初始化S3存储
    try:
        s3_storage.init_app(app)
    except Exception as e:
        print(f"！！！警告: S3存储初始化失败: {str(e)}")
        print("！！！系统将继续运行，但媒体功能受限")

    # 初始化配置管理器
    try:
        with app.app_context():  # 使用应用上下文确保配置管理器正确初始化
            config_manager.refresh_all_configs(app)
        print("配置管理器初始化成功")
    except Exception as e:
        print(f"！！！警告: 配置管理器初始化失败: {str(e)}")
        print("！！！系统将继续运行，但配置可能无法实时更新")

    # 初始化安全头
    init_security_headers(app)

    # 注册蓝图
    register_blueprints(app)

    # 注册上下文处理器
    register_context_processors(app, config_class)

    # 注册直接路由
    register_direct_routes(app, config_class)

    # 注册模板过滤器
    register_template_filters(app)

    # 条件初始化调度器（在serverless环境中可能不需要）
    if not os.environ.get('VERCEL'):
        from src.scheduler import init_scheduler
        init_scheduler(app)

    # 初始化监控
    try:
        from src.monitoring import monitor
        monitor.init_app(app)
    except ImportError:
        monitor = None
        app.logger.warning("监控系统导入失败")

    # 配置日志
    configure_logging(app)

    # 添加访问统计中间件
    @app.before_request
    def track_page_view():
        # 排除静态资源和API健康检查等路径
        excluded_paths = ['/static', '/health', '/api/check-login', '/api/monitoring', '/api/health']
        if not any(request.path.startswith(path) for path in excluded_paths):
            from flask_login import current_user
            user_id = current_user.id if current_user.is_authenticated else None
            record_page_view(
                user_id=user_id,
                page_url=request.url,
                page_title=get_page_title(),
                referrer=request.referrer
            )

    print_startup_info(config_class)

    return app


def get_page_title():
    """根据当前请求获取页面标题"""
    from flask import g

    # 尝试从全局变量获取页面标题
    if hasattr(g, 'page_title'):
        return g.page_title

    # 根据endpoint确定页面标题
    endpoint = request.endpoint
    if endpoint:
        title_map = {
            'blog_bp.index': '首页',
            'blog_bp.detail': '文章详情',
            'blog_bp.category_list': '分类列表',
            'auth_bp.login': '登录',
            'auth_bp.register': '注册',
            'my_bp.profile': '个人资料',
            'my_bp.dashboard': '仪表板',
            'admin_bp.admin_user': '管理后台',
            'admin_bp.admin_blog': '博客管理',
        }
        return title_map.get(endpoint, endpoint)

    return request.endpoint or '未知页面'


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
            username=get_username_no_check(),
            menu=get_site_menu(get_current_menu_slug()) or default_menu_data,
            footer=get_footer(),
            banner=get_banner()
        )


def register_direct_routes(app, config_class):
    """注册直接定义在应用上的路由"""

    @login_manager.user_loader
    def load_user(user_id):
        from src.models.user import User, db
        try:
            user = db.session.query(User).filter_by(id=user_id).first()
            return user
        except Exception as e:
            db.session.rollback()
            # 记录错误但不要让应用程序崩溃
            app.logger.error(f"Error loading user {user_id}: {str(e)}")
            return None

    # 身份加载信号处理器
    @identity_loaded.connect_via(app)
    def on_identity_loaded(_sender, identity):
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
                secure=app.config.get('JWT_COOKIE_SECURE', False),
                samesite=app.config.get('JWT_COOKIE_SAMESITE', 'Lax'),
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
    @limiter.limit("10 per minute")
    def search(user_id):
        return search_handler(user_id, config_class.domain, config_class.global_encoding,
                              app.config['MAX_CACHE_TIMESTAMP'])

    @app.route('/p/<slug_name>', methods=['GET', 'POST'])
    def blog_detail(slug_name):
        return blog_detail_back(blog_slug=slug_name)

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

        # 避免在错误处理中再次出现错误导致循环
        try:
            # 根据异常类型返回不同的响应
            if isinstance(e, NotFound):
                # 返回 404 错误页面或 JSON 响应
                return error(404, "Page Not Found")
            else:
                # 返回 500 错误页面或 JSON 响应
                return error(500, "Internal Server Error")
        except Exception as render_error:
            # 如果错误页面渲染失败，返回简单的错误响应
            app.logger.error(f"Error rendering error page: {str(render_error)}")
            from flask import jsonify
            return jsonify({'error': 'Internal Server Error', 'message': 'An error occurred'}), 500

    from flask_principal import PermissionDenied

    @app.errorhandler(PermissionDenied)
    def handle_permission_denied(permission_error):
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
    # 注册自定义模板过滤器
    from src.utils.cache_protection import staggered_ttl
    app.jinja_env.globals['staggered_ttl'] = staggered_ttl


def register_blueprints(app):
    """注册所有蓝图"""
    # 初始化插件管理器
    from src.plugin import init_plugin_manager
    init_plugin_manager(app)

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
        session_bp,
        payment_bp,
        seo_bp,
        analytics_bp,
        #supabase_api_bp,
        #supabase_auth_bp
    ]

    # 找到最长的蓝图名称长度，用于日志格式化
    max_name_length = max(len(bp.name) for bp in blueprints) if blueprints else 0

    for bp in blueprints:
        app.register_blueprint(bp)
        # 使用固定宽度格式化，使日志输出对齐美观
        app.logger.info(f"=====Blueprint {bp.name:>{max_name_length}} load success.=====")
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
    logger = logging.getLogger(__name__)
    logger.info(f"running at: {config_class.base_dir}")
    logger.info("sys information")
    domain = config_class.domain.rstrip('/') + '/'
    logger.info("++++++++++==========================++++++++++")
    logger.info(
        f'\n domain: {domain} \n title: {config_class.sitename} \n beian: {config_class.beian} \n')

    # 安全检查
    if config_class.SECRET_KEY == 'your-secret-key-here':
        logger.critical("CRITICAL: 应用存在严重安全风险，不能使用默认SECRET_KEY运行，请修改 SECRET_KEY 环境变量的值")
        logger.critical("CRITICAL: 请修改 SECRET_KEY 环境变量的值")
        logger.critical("CRITICAL: 请修改 SECRET_KEY 环境变量的值")
        logger.critical("CRITICAL: 请修改 SECRET_KEY 环境变量的值")
        # 在生产环境中，直接退出应用
        # 由于此时还没有应用上下文，我们无法使用current_app，所以只对默认SECRET_KEY发出警告
        logger.critical("CRITICAL: 正在使用默认SECRET_KEY，存在安全风险")

    logger.info("++++++++++==========================++++++++++")