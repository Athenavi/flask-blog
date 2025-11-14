import shutil
from pathlib import Path

from flask import Blueprint, jsonify, send_from_directory, request, render_template

from src.auth import admin_required
from src.extensions import cache
from src.setting import AppConfig
from src.utils.config.theme import theme_safe_check, get_all_themes

theme_bp = Blueprint('theme', __name__, template_folder='templates')


@theme_bp.route('/theme/<theme_id>')
@cache.cached(timeout=300)
def get_theme_detail(theme_id):
    return theme_safe_check(theme_id=theme_id, channel=1)


base_dir = AppConfig.base_dir


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
        current_theme = cache.get('display_theme')
        if current_theme == theme_id:
            cache.set('display_theme', 'default')
            # 可选：清理相关缓存模板
            cache.delete_memoized('index_html')
        return jsonify({'message': 'Theme deleted successfully'}), 200

    except Exception as e:
        return jsonify({'error': f'Deletion failed: {str(e)}'}), 500
    finally:
        print(f'Deleting theme {theme_id} user: {user_id} ')


@theme_bp.route('/theme/display', methods=['GET'])
def m_display():
    try:
        return render_template('dashboard/M-display.html', displayList=get_all_themes())
    except Exception as e:
        return jsonify({'error': f'Failed to get display list: {str(e)}'}), 500
