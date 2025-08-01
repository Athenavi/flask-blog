from flask import Blueprint, jsonify, request

plugin_bp = Blueprint('plugin_bp', __name__, url_prefix='/api/plugins')


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
