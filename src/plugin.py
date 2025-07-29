from flask import Blueprint, jsonify, request

plugin_bp = Blueprint('plugin_bp', __name__, url_prefix='/api/plugins')


@plugin_bp.route('/toggle/<plugin_name>', methods=['POST'])
def toggle_plugin(plugin_name):
    # 实际应用中这里应该实现插件的启用/禁用逻辑
    # 这里仅做演示
    data = request.get_json()
    new_state = data.get('state', False)

    # 在实际应用中，这里会调用 PluginManager 的方法来启用/禁用插件
    return jsonify({
        'status': 'success',
        'message': f'Plugin {plugin_name} state changed to {new_state}',
        'new_state': new_state
    })


@plugin_bp.route('/install', methods=['POST'])
def install_plugin():
    # 实际应用中这里应该处理插件的安装
    return jsonify({
        'status': 'error',
        'message': 'Plugin installation not implemented yet'
    })


@plugin_bp.route('/uninstall/<plugin_name>', methods=['DELETE'])
def uninstall_plugin():
    # 实际应用中这里应该处理插件的卸载
    return jsonify({
        'status': 'error',
        'message': 'Plugin uninstallation not implemented yet'
    })
