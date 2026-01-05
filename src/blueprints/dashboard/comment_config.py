"""
Dashboard 评论配置模块
包含评论系统配置功能
"""
import inspect
import re
from datetime import datetime

from flask import request, render_template, jsonify

from src.auth_utils import admin_required
from src.extensions import limiter
from src.models import User, db, SystemSettings
from . import admin_bp


@admin_bp.route('/comment-config', methods=['GET', 'POST'])
@admin_required
@limiter.limit("10 per minute")
def admin_comment_config(user_id):
    """评论系统配置页面"""
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        if request.method == 'POST':
            # 处理表单提交
            try:
                # 检查是否有脚本输入，优先解析脚本
                giscus_script = request.form.get('giscus_script', '').strip()
                giscus_config = {}

                if giscus_script:
                    # 从脚本中解析配置
                    giscus_config = parse_giscus_script(giscus_script)

                # 获取表单中的其他配置值（可能覆盖脚本解析的值）
                form_config = {
                    'giscus_repo': request.form.get('giscus_repo', '').strip(),
                    'giscus_repo_id': request.form.get('giscus_repo_id', '').strip(),
                    'giscus_category': request.form.get('giscus_category', '').strip(),
                    'giscus_category_id': request.form.get('giscus_category_id', '').strip(),
                    'giscus_mapping': request.form.get('giscus_mapping', 'pathname'),
                    'giscus_strict': request.form.get('giscus_strict', '0'),
                    'giscus_reactions_enabled': request.form.get('giscus_reactions_enabled', '1'),
                    'giscus_emit_metadata': request.form.get('giscus_emit_metadata', '0'),
                    'giscus_input_position': request.form.get('giscus_input_position', 'top'),
                    'giscus_theme': request.form.get('giscus_theme', 'preferred_color_scheme'),
                    'giscus_lang': request.form.get('giscus_lang', 'zh-CN'),
                    'giscus_loading': request.form.get('giscus_loading', 'lazy')
                }

                # 合并配置：如果表单中有值则使用表单值，否则使用脚本解析的值
                for key, value in form_config.items():
                    if value:  # 如果表单中的值不为空，则使用表单值
                        giscus_config[key] = value
                    elif key not in giscus_config:  # 如果脚本中也没有该值，则使用默认值
                        giscus_config[key] = value

                # 自动纠错和验证
                corrected_config = auto_correct_giscus_config(giscus_config)

                # 保存配置到系统设置
                for key, value in corrected_config.items():
                    setting = db.session.query(SystemSettings).filter_by(key=key).first()
                    if setting:
                        setting.value = value
                        setting.updated_at = datetime.now()
                        setting.updated_by = user_id
                    else:
                        setting = SystemSettings(
                            key=key,
                            value=value,
                            updated_at=datetime.now(),
                            updated_by=user_id
                        )
                        db.session.add(setting)

                db.session.commit()

                # 刷新配置（如果需要）
                if any(key in ['giscus_repo', 'giscus_repo_id', 'giscus_category', 'giscus_category_id',
                               'giscus_mapping', 'giscus_strict', 'giscus_reactions_enabled', 'giscus_emit_metadata',
                               'giscus_input_position', 'giscus_theme', 'giscus_lang', 'giscus_loading'] for key in
                       corrected_config.keys()):
                    try:
                        print('评论配置已保存并更新')
                    except Exception as refresh_error:
                        print(f'评论配置刷新失败: {str(refresh_error)}')
                
                return jsonify({
                    'success': True,
                    'message': '评论配置保存成功'
                })

            except Exception as e:
                db.session.rollback()
                return jsonify({
                    'success': False,
                    'message': f'保存配置失败: {str(e)}'
                })

        # GET请求 - 显示配置页面
        # 获取现有配置
        system_settings = db.session.query(SystemSettings).all()
        settings_dict = {setting.key: setting.value for setting in system_settings}

        return render_template('dashboard/comment_config.html',
                               settings=settings_dict,
                               current_user=current_user)

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


def parse_giscus_script(script_content):
    """
    从Giscus脚本中解析配置参数
    """
    config = {}

    # 定义正则表达式模式来匹配data-属性
    patterns = {
        'giscus_repo': r'data-repo\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_repo_id': r'data-repo-id\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_category': r'data-category\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_category_id': r'data-category-id\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_mapping': r'data-mapping\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_theme': r'data-theme\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_lang': r'data-lang\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_loading': r'data-loading\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_strict': r'data-strict\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_reactions_enabled': r'data-reactions-enabled\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_emit_metadata': r'data-emit-metadata\s*=\s*[\'"]([^\'"]+)[\'"]',
        'giscus_input_position': r'data-input-position\s*=\s*[\'"]([^\'"]+)[\'"]'
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, script_content, re.IGNORECASE)
        if match:
            config[key] = match.group(1)

    return config


def auto_correct_giscus_config(config):
    """
    自动纠错Giscus配置
    """
    corrected = config.copy()

    # 验证和修正仓库名称格式
    repo = corrected.get('giscus_repo', '')
    if repo:
        # 检查是否包含斜杠
        if '/' not in repo:
            # 尝试智能修复 - 如果只有一个斜杠，添加默认仓库
            parts = repo.split('/')
            if len(parts) == 1:
                # 如果只有用户名，添加默认仓库名
                corrected['giscus_repo'] = f"{repo}/repo"  # 这里可以改为更有意义的默认值
                print(f"警告: 仓库名称格式不正确，已更正为: {corrected['giscus_repo']}")
        else:
            # 分割并清理仓库名
            parts = repo.split('/')
            if len(parts) >= 2:
                username = parts[0].strip()
                reponame = '/'.join(parts[1:]).strip()  # 处理仓库名中可能包含的斜杠
                corrected['giscus_repo'] = f"{username}/{reponame}"

    # 验证映射方式
    valid_mappings = ['pathname', 'url', 'title', 'og:title', 'specific', 'number']
    mapping = corrected.get('giscus_mapping', 'pathname')
    if mapping not in valid_mappings:
        corrected['giscus_mapping'] = 'pathname'  # 默认值

    # 验证严格模式值
    strict = corrected.get('giscus_strict', '0')
    if strict not in ['0', '1']:
        corrected['giscus_strict'] = '0'

    # 验证表情反应启用值
    reactions = corrected.get('giscus_reactions_enabled', '1')
    if reactions not in ['0', '1']:
        corrected['giscus_reactions_enabled'] = '1'

    # 验证发送元数据值
    emit_metadata = corrected.get('giscus_emit_metadata', '0')
    if emit_metadata not in ['0', '1']:
        corrected['giscus_emit_metadata'] = '0'

    # 验证输入框位置
    input_position = corrected.get('giscus_input_position', 'top')
    if input_position not in ['top', 'bottom']:
        corrected['giscus_input_position'] = 'top'

    # 验证主题
    valid_themes = ['light', 'dark', 'dark_dimmed', 'dark_high_contrast', 'preferred_color_scheme']
    theme = corrected.get('giscus_theme', 'preferred_color_scheme')
    if theme not in valid_themes:
        corrected['giscus_theme'] = 'preferred_color_scheme'

    # 验证语言
    valid_langs = ['zh-CN', 'zh-TW', 'en', 'es', 'fr', 'ja', 'ko', 'ru']
    lang = corrected.get('giscus_lang', 'zh-CN')
    if lang not in valid_langs:
        corrected['giscus_lang'] = 'zh-CN'

    # 验证加载方式
    loading = corrected.get('giscus_loading', 'lazy')
    if loading not in ['eager', 'lazy']:
        corrected['giscus_loading'] = 'lazy'

    return corrected