import configparser
import os
import zipfile

from flask import jsonify
from packaging.version import Version


def theme_safe_check(theme_id, channel=1):
    theme_path = f'templates/theme/{theme_id}'
    if not os.path.exists(theme_path):
        return False

    # 检查必需的文件
    has_index_html = os.path.exists(os.path.join(theme_path, 'index.html'))
    has_template_ini = os.path.exists(os.path.join(theme_path, 'template.ini'))

    # 检查额外推荐的文件
    has_screenshot = (
            os.path.exists(os.path.join(theme_path, 'screenshot.png')) or
            os.path.exists(os.path.join(theme_path, 'screenshot.jpg')) or
            os.path.exists(os.path.join(theme_path, 'screenshot.jpeg'))
    )

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

        # 尝试获取截图文件名
        screenshot = 'screenshot.png'  # 默认截图文件名
        if theme_detail.has_option('default', 'screenshot'):
            screenshot = theme_detail.get('default', 'screenshot').strip("'")
        elif has_screenshot:
            # 如果配置文件中没有指定截图，但目录中存在截图文件，则使用存在的截图
            if os.path.exists(os.path.join(theme_path, 'screenshot.png')):
                screenshot = 'screenshot.png'
            elif os.path.exists(os.path.join(theme_path, 'screenshot.jpg')):
                screenshot = 'screenshot.jpg'
            elif os.path.exists(os.path.join(theme_path, 'screenshot.jpeg')):
                screenshot = 'screenshot.jpeg'

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
    display_list = []
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


def validate_and_extract_theme(zip_path, theme_id):
    """
    验证主题ZIP文件结构并根据ID解压
    
    Args:
        zip_path: ZIP文件路径
        theme_id: 主题ID
        
    Returns:
        bool: 验证是否通过
    """
    required_files = ['index.html', 'template.ini']

    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            file_list = zip_ref.namelist()

            # 检查根目录是否包含必需文件
            has_index_html = False
            has_template_ini = False

            for file_name in file_list:
                # 检查是否有路径遍历攻击
                if '..' in file_name or file_name.startswith('/'):
                    return False, "非法文件路径"

                # 检查必需文件
                if file_name == 'index.html' or file_name.endswith('/index.html'):
                    has_index_html = True
                if file_name == 'template.ini' or file_name.endswith('/template.ini'):
                    has_template_ini = True

            # 检查是否包含必需文件
            if not (has_index_html and has_template_ini):
                return False, "缺少必需文件: index.html 或 template.ini"

            # 解压到目标目录
            extract_path = f'templates/theme/{theme_id}'
            if not os.path.exists(extract_path):
                os.makedirs(extract_path)

            # 解压文件
            for file_info in zip_ref.infolist():
                # 防止路径遍历攻击
                if '..' in file_info.filename or file_info.filename.startswith('/'):
                    continue
                zip_ref.extract(file_info, extract_path)

        return True, "主题验证通过并解压成功"

    except zipfile.BadZipFile:
        return False, "无效的ZIP文件"
    except Exception as e:
        return False, f"处理ZIP文件时出错: {str(e)}"
