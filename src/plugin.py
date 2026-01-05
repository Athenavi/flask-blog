from flask import Blueprint, jsonify, render_template, request

from plugins.manager import PluginManager
from src.auth_utils import admin_required
from src.models import User

plugin_bp = Blueprint('plugin_bp', __name__, url_prefix='/api/plugins')

# 初始化插件管理器（延迟到应用上下文中）
plugins_manager = None


def init_plugin_manager(app):
    """在应用上下文中初始化插件管理器"""
    global plugins_manager
    with app.app_context():
        plugins_manager = PluginManager(app)
        plugins_manager.load_plugins()
        plugins_manager.register_blueprints()


@plugin_bp.route('/install', methods=['POST'])
def install_plugin():
    # 实际应用中这里应该处理插件的安装
    return jsonify({
        'status': 'error',
        'message': 'Plugin installation not implemented yet'
    })


@plugin_bp.route('/uninstall/<plugin_name>', methods=['DELETE'])
def uninstall_plugin(plugin_name):  # 修复：添加缺失的参数
    """卸载插件：删除插件目录并从系统中移除"""
    import os
    import shutil
    from pathlib import Path

    plugin_dir = Path(os.path.dirname(__file__)).parent / 'plugins' / plugin_name

    # 检查插件是否存在
    if not plugin_dir.exists():
        return jsonify({
            'status': 'error',
            'message': f'Plugin {plugin_name} does not exist'
        })

    try:
        # 先禁用插件（如果已启用）
        plugins_manager.disable_plugin(plugin_name)

        # 删除插件目录
        shutil.rmtree(plugin_dir)

        return jsonify({
            'status': 'success',
            'message': f'Plugin {plugin_name} uninstalled successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to uninstall plugin: {str(e)}'
        })


@plugin_bp.route('/')
@admin_required
def plugin_dashboard(user_id):
    plugins = plugins_manager.get_plugin_list()
    current_user = User.query.get(user_id)
    return render_template('dashboard/plugins.html', plugins=plugins, current_user=current_user)


@plugin_bp.route('/toggle/<plugin_name>', methods=['POST'])
def toggle_plugin(plugin_name):
    data = request.get_json()
    new_state = data.get('state', False)

    if new_state:
        success = plugins_manager.enable_plugin(plugin_name)
    else:
        success = plugins_manager.disable_plugin(plugin_name)

    return jsonify({
        'status': 'success' if success else 'error',
        'message': f'插件 {plugin_name} 已{"启用" if new_state else "禁用"}',
        'new_state': new_state
    })


@plugin_bp.route('/config/<plugin_name>', methods=['GET', 'POST'])
@admin_required
def plugin_config(user_id, plugin_name):
    """处理插件配置页面"""

    # 检查插件是否存在
    if plugin_name not in plugins_manager.plugins:
        return jsonify({'error': 'Plugin not found'}), 404

    plugin = plugins_manager.plugins[plugin_name]

    # 获取插件配置（如果插件支持）
    plugin_config_data = getattr(plugin, 'config', {})

    if request.method == 'GET':
        # 渲染配置页面
        try:
            return render_template('dashboard/plugin_config.html',
                                   plugin=plugin,
                                   config=plugin_config_data)
        except Exception as e:
            return jsonify({'error': f'Failed to render config page: {str(e)}'}), 500

    elif request.method == 'POST':
        # 保存插件配置
        try:
            config_data = request.get_json()
            if config_data is None:
                return jsonify({'error': 'Invalid JSON data'}), 400

            # 更新插件配置
            plugin.config = config_data

            # 尝试保存配置到持久化存储（如果插件支持）
            if hasattr(plugin, 'save_config'):
                plugin.save_config(config_data)

            return jsonify({
                'status': 'success',
                'message': 'Plugin configuration saved successfully'
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Failed to save plugin config: {str(e)}'
            }), 500
