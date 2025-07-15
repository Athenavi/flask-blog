import configparser
import os

from flask import jsonify
from packaging.version import Version

from src.database import get_db_connection


def theme_safe_check(theme_id, channel=1):
    theme_path = f'templates/theme/{theme_id}'
    if not os.path.exists(theme_path):
        return False
    has_index_html = os.path.exists(os.path.join(theme_path, 'index.html'))
    has_template_ini = os.path.exists(os.path.join(theme_path, 'template.ini'))

    if has_index_html and has_template_ini:
        theme_detail = configparser.ConfigParser()
        # 读取 template.ini 文件
        theme_detail.read(f'templates/theme/{theme_id}/template.ini', encoding='utf-8')
        # 获取配置文件中的属性值
        tid = theme_detail.get('default', 'id').strip("'")
        author = theme_detail.get('default', 'author').strip("'")
        theme_title = theme_detail.get('default', 'title').strip("'")
        theme_description = theme_detail.get('default', 'description').strip("'")
        author_website = theme_detail.get('default', 'authorWebsite').strip("'")
        theme_version = theme_detail.get('default', 'version').strip("'")
        theme_version_code = theme_detail.get('default', 'versionCode').strip("'")
        update_url = theme_detail.get('default', 'updateUrl').strip("'")
        screenshot = theme_detail.get('default', 'screenshot').strip("'")

        theme_properties = {
            'id': tid,
            'author': author,
            'title': theme_title,
            'description': theme_description,
            'authorWebsite': author_website,
            'version': theme_version,
            'versionCode': theme_version_code,
            'updateUrl': update_url,
            'screenshot': screenshot,
        }

        if channel == 1:
            return jsonify(theme_properties)
        else:
            # print(Version(theme_version) > Version(sys_version))
            if Version(theme_version) < Version('1.0.0'):
                return False
            else:
                return True
    else:
        return False


def get_all_themes():
    display_list = ['default']
    themes_path = 'templates/theme'
    if os.path.exists(themes_path):
        subfolders = [f.path for f in os.scandir(themes_path) if f.is_dir()]
        for subfolder in subfolders:
            has_index_html = os.path.exists(os.path.join(subfolder, 'index.html'))
            has_template_ini = os.path.exists(os.path.join(subfolder, 'template.ini'))
            if has_index_html and has_template_ini:
                display_list.append(os.path.basename(subfolder))
    # print(display_list)
    return display_list


def db_change_theme(user_id, theme_id):
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = "INSERT INTO `custom_fields` (`user_id`, `field_name`, `field_value`) VALUES (%s, %s, %s)"
                cursor.execute(query, (user_id, "theme", theme_id))
                db.commit()
                return True
    except Exception:
        return False


def db_get_theme():
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = """
                    SELECT field_value FROM custom_fields WHERE user_id = 1 AND field_name = 'theme' ORDER BY id DESC LIMIT 1;
                """
                cursor.execute(query)
                result = cursor.fetchone()
                current_theme = result[0] if result else 'default'
    except Exception as e:
        print(f"Error getting current theme: {e}")
        current_theme = 'default'
    return str(current_theme)
