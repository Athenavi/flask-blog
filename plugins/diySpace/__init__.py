from pathlib import Path

from flask import Blueprint, render_template, request, current_app, jsonify

from plugins.diySpace.diy import diy_space_put
from src.auth_utils import jwt_required
from src.blueprints.api import api_user_avatar, api_user_profile, api_user_bio, username_exists
from src.extensions import cache, csrf
from update import base_dir

TemplateDir = Path(base_dir) / 'plugins' / 'diySpace' / 'templates'
diySpace_bp = Blueprint('diySpace', __name__, template_folder=str(TemplateDir))
csrf.exempt(diySpace_bp)


# server_started = False  # 添加服务器状态标志


def register_plugin(app):
    # 创建蓝图
    bp = Blueprint('diySpace_plugin', __name__)

    # 注册路由
    bp.register_blueprint(diySpace_bp)

    # 创建插件对象（包含元数据）
    plugin = type('Plugin', (), {
        'name': 'DIY Space Plugin',
        'version': '0.0.1',
        'description': 'A plugin for user to create their own space',
        'author': 'system',
        'blueprint': bp,
        'enabled': True,
        'protect': False,
        'config': app.config.get('HELLO_PLUGIN_CONFIG', {})
    })()

    # 添加自定义方法
    plugin.greet = lambda: f"Hello from {plugin.name}!"
    return plugin


@diySpace_bp.route('/diy/space', methods=['GET', 'POST', 'PUT', 'DELETE'])
@diySpace_bp.route('/diy/space/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@jwt_required
def diy_space(user_id):
    try:
        if request.method == 'GET':
            return diy_space_back(user_id, avatar_url=api_user_avatar(user_id), profiles=api_user_profile(user_id),
                                  user_bio=api_user_bio(user_id))

        if request.method == 'PUT':
            return diy_space_put(base_dir=base_dir, user_id=user_id, encoding='utf-8')
            
        # 对于不支持的方法，返回 JSON 错误（如果是 AJAX 请求）或者 405 错误
        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            return jsonify({'error': 'Method not allowed'}), 405
        
        # 对于普通的浏览器请求，返回 405 错误
        return "Method not allowed", 405
    except Exception as e:
        current_app.logger.error(f"An error occurred: {e}")
        # 出现异常时，根据请求类型返回合适的错误格式
        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            return jsonify({'error': 'Internal server error'}), 500
        return "Internal server error", 500


@diySpace_bp.route("/@<user_name>")
def user_diy_space(user_name):
    @cache.cached(timeout=300, key_prefix=f'current_{user_name}')
    def _user_diy_space():
        user_id = username_exists(user_name)
        user_path = Path(base_dir) / 'media' / user_id / 'index.html'
        current_app.logger.info(user_path)
        if user_path.exists():
            with user_path.open('r', encoding='utf-8') as f:
                return f.read()
        else:
            return "用户主页未找到", 404

    return _user_diy_space()


def diy_space_back(user_id, avatar_url, profiles, user_bio):
    return render_template('diy_space.html', user_id=user_id, avatar_url=avatar_url,
                           profiles=profiles, userBio=user_bio)