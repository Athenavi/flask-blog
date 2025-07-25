import shutil
from pathlib import Path

from flask import Blueprint, jsonify, send_from_directory, request

from src.config.theme import theme_safe_check, db_change_theme, db_get_theme
from src.user.authz.decorators import admin_required

theme_bp = Blueprint('theme', __name__, template_folder='templates')


def create_theme_blueprint(cache_instance, domain, sys_version, base_dir):
    @theme_bp.route('/theme/<theme_id>')
    @cache_instance.cached(timeout=300, key_prefix='display_detail')
    def get_theme_detail(theme_id):
        if theme_id == 'default':
            theme_properties = {
                'id': theme_id,
                'author': "系统默认",
                'title': "恢复系统默认",
                'authorWebsite': domain,
                'version': sys_version,
                'versionCode': "None",
                'updateUrl': "None",
                'screenshot': "None",
            }
            return jsonify(theme_properties)
        else:
            return theme_safe_check(theme_id=theme_id, channel=1)

    @theme_bp.route('/theme/<theme_id>/<img_name>')
    def get_screenshot(theme_id, img_name):
        if theme_id == 'default':
            return send_from_directory(base_dir, 'static/favicon.ico', mimetype='image/png', max_age=3600)
        try:
            theme_dir: Path = Path(base_dir) / 'templates' / 'theme' / theme_id
            return send_from_directory(theme_dir, img_name, mimetype='image/png', max_age=3600)
        except FileNotFoundError:
            print(f"File not found: {theme_id}/{img_name}")
            return jsonify(error='Image not found'), 404
        except Exception as e:
            print(f"Error in getting image: {e}")
            return jsonify(error='Failed to get image'), 500

    @theme_bp.route('/api/theme', methods=['DELETE'])
    @admin_required
    def delete_theme(user_id):
        theme_id = request.args.get('theme_id')
        if not theme_id:
            return jsonify({'error': 'Missing theme_id'}), 400

        if theme_id == 'default':
            return jsonify({'message': 'default Theme can not be deleted'}), 403

        theme_dir = Path(base_dir) / 'templates' / 'theme' / theme_id
        print(theme_dir)

        try:
            if not theme_dir.resolve().relative_to(Path(base_dir).resolve()):
                return jsonify({'error': 'Invalid theme path'}), 400
        except ValueError:
            return jsonify({'error': 'Path traversal attempt detected'}), 400

        # 检查目录存在性
        if not theme_dir.is_dir():
            return jsonify({'error': 'Theme not found'}), 404

        try:
            # 执行删除
            shutil.rmtree(theme_dir)
            current_theme = cache_instance.get('display_theme')
            if current_theme == theme_id:
                cache_instance.set('display_theme', 'default')
                # 可选：清理相关缓存模板
                cache_instance.delete_memoized('index')
            return jsonify({'message': 'Theme deleted successfully'}), 200

        except Exception as e:
            return jsonify({'error': f'Deletion failed: {str(e)}'}), 500

    @theme_bp.route('/api/theme', methods=['PUT'])
    @admin_required
    def change_display(user_id):
        if cache_instance.get("Theme_Lock"):
            return "failed"

        theme_id = request.args.get('NT')
        if not theme_id:
            return "failed403"

        current_theme = db_get_theme()
        if theme_id == current_theme:
            return "failed001"

        if theme_id == 'default' or theme_safe_check(theme_id, channel=2):
            try:
                if db_change_theme(user_id, theme_id):
                    cache_instance.set('display_theme', theme_id)
                    cache_instance.set(f"Theme_Lock", theme_id, timeout=15)
                    print(f'{user_id} : change theme to {theme_id}')
                    return "success"
                else:
                    return "failed"
            except Exception as e:
                print(f"Error during theme change: {e}")
                return "failed500"
            finally:
                log_msg = f"{user_id} : change theme to {theme_id}"
                print(log_msg)
        else:
            return "failed"

    return theme_bp
