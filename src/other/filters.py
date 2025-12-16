import json
from datetime import datetime, timedelta
from functools import lru_cache

from flask import current_app as app
from pytz import UTC

from src.database import get_db
from src.models import Category
from src.user.profile.social import get_user_name_by_id


def json_filter(value):
    """将 JSON 字符串解析为 Python 对象"""
    # 如果已经是字典直接返回
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        # print(f"Unexpected type for value: {type(value)}. Expected a string.")
        return None

    try:
        result = json.loads(value)
        return result
    except (ValueError, TypeError) as e:
        app.logger.error(f"Error parsing JSON: {e}, Value: {value}")
        return None


def string_split(value, delimiter=','):
    """
    在模板中对字符串进行分割
    :param value: 要分割的字符串
    :param delimiter: 分割符，默认为逗号
    :return: 分割后的列表
    """
    if not isinstance(value, str):
        app.logger.error(f"Unexpected type for value: {type(value)}. Expected a string.")
        return []

    try:
        result = value.split(delimiter)
        return result
    except Exception as e:
        app.logger.error(f"Error splitting string: {e}, Value: {value}")
        return []


@lru_cache(maxsize=128)  # 设置缓存大小为128
def article_author(user_id):
    """通过 user_id 搜索作者名称"""
    return get_user_name_by_id(user_id)


import markdown


def md2html(markdown_text, **options):
    """
    专业的Markdown转HTML转换函数，支持多种扩展和配置

    Args:
        markdown_text: Markdown格式文本
        **options: 转换选项，包含以下可配置项：
            - style_theme: 样式主题 ('github', 'dark', 'minimal', 'academic', 'elegant')
            - pygments_style: 代码高亮样式 ('default', 'github', 'monokai', 'vs', 'colorful', 'autumn')
            - tab_length: 制表符长度 (默认4)
            - enable_tables: 启用表格 (默认True)
            - enable_fenced_code: 启用围栏代码块 (默认True)
            - enable_sane_lists: 启用智能列表 (默认True)
            - enable_footnotes: 启用脚注 (默认False)
            - enable_attr_list: 启用属性列表 (默认False)
            - enable_meta: 启用元数据 (默认False)
            - enable_nl2br: 启用换行转<br> (默认False)
            - enable_admonition: 启用警告框 (默认False)
            - enable_code_highlight: 启用代码高亮 (默认True)
            - enable_toc: 启用目录生成 (默认False)
            - enable_superfences: 启用超级围栏(图表支持) (默认True)
            - enable_tasklist: 启用任务列表 (默认True)
            - enable_magiclink: 启用智能链接 (默认False)
            - enable_emoji: 启用表情符号 (默认False)

    Returns:
        str: 转换后的HTML内容
    """

    # 默认选项
    default_options = {
        'style_theme': 'github',
        'pygments_style': 'default',
        'tab_length': 4,
        'enable_tables': True,
        'enable_fenced_code': True,
        'enable_sane_lists': True,
        'enable_footnotes': False,
        'enable_attr_list': False,
        'enable_meta': False,
        'enable_nl2br': False,
        'enable_admonition': False,
        'enable_code_highlight': True,
        'enable_toc': False,
        'enable_superfences': True,
        'enable_tasklist': True,
        'enable_magiclink': False,
        'enable_emoji': False,
        'toc_title': '目录',
        'toc_anchorlink': True,
        'toc_permalink': True,
        'toc_depth': 6,
    }

    # 合并用户选项
    opts = {**default_options, **options}

    # 构建扩展列表
    extensions = []
    extension_configs = {}

    # 基础扩展
    if opts['enable_tables']:
        extensions.append('tables')

    if opts['enable_fenced_code']:
        extensions.append('fenced_code')

    if opts['enable_sane_lists']:
        extensions.append('sane_lists')

    if opts['enable_footnotes']:
        extensions.append('footnotes')

    if opts['enable_attr_list']:
        extensions.append('attr_list')

    if opts['enable_meta']:
        extensions.append('meta')

    if opts['enable_nl2br']:
        extensions.append('nl2br')

    if opts['enable_admonition']:
        extensions.append('admonition')

    # 代码高亮
    if opts['enable_code_highlight']:
        extensions.append('codehilite')
        extension_configs['codehilite'] = {
            'use_pygments': True,
            'css_class': 'highlight',
            'pygments_style': opts['pygments_style']
        }

    # 目录生成
    if opts['enable_toc']:
        extensions.append('toc')
        extension_configs['toc'] = {
            'title': opts['toc_title'],
            'anchorlink': opts['toc_anchorlink'],
            'permalink': opts['toc_permalink'],
            'toc_depth': opts['toc_depth'],
            'marker': '[TOC]'
        }

    # PyMdown高级扩展
    if opts['enable_superfences']:
        extensions.append('pymdownx.superfences')
        extension_configs['pymdownx.superfences'] = {
            'custom_fences': [
                {
                    'name': 'mermaid',
                    'class': 'mermaid',
                    'format': lambda source, language, css_class, options, md:
                    f'<div class="{css_class}"><pre><code>{source}</code></pre></div>'
                }
            ]
        }

    if opts['enable_tasklist']:
        extensions.append('pymdownx.tasklist')
        extension_configs['pymdownx.tasklist'] = {
            'custom_checkbox': True,
            'clickable_checkbox': False
        }

    if opts['enable_magiclink']:
        extensions.append('pymdownx.magiclink')
        extension_configs['pymdownx.magiclink'] = {
            'repo_url_shorthand': True,
            'social_url_shorthand': True
        }

    if opts['enable_emoji']:
        extensions.append('pymdownx.emoji')
        extension_configs['pymdownx.emoji'] = {
            'emoji_index': lambda: None,
            'emoji_generator': lambda: None
        }

    # 创建Markdown实例并转换
    md = markdown.Markdown(
        extensions=extensions,
        extension_configs=extension_configs,
        tab_length=opts['tab_length']
    )

    html_content = md.convert(markdown_text)

    # 添加CSS样式
    css_style = _get_css_style(opts['style_theme'])
    pygments_css = _get_pygments_css(opts['pygments_style'])

    # 包装结果
    result = f"""
<style>
{css_style}
{pygments_css}
</style>
<div class="markdown-content">
{html_content}
</div>
"""

    return result.strip()


def _get_css_style(theme):
    """获取指定主题的CSS样式"""
    styles = {
        'github': '''
            .markdown-content { 
                font-family: -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif; 
                line-height: 1.6; color: #24292f; background-color: #ffffff; 
                max-width: 980px; margin: 0 auto; padding: 45px; 
            }
            .markdown-content h1,.markdown-content h2,.markdown-content h3,.markdown-content h4,.markdown-content h5,.markdown-content h6 { 
                margin-top: 24px; margin-bottom: 16px; font-weight: 600; line-height: 1.25; 
            }
            .markdown-content h1 { font-size: 2em; border-bottom: 1px solid #d0d7de; padding-bottom: .3em; }
            .markdown-content h2 { font-size: 1.5em; border-bottom: 1px solid #d0d7de; padding-bottom: .3em; }
            .markdown-content p { margin-bottom: 16px; }
            .markdown-content code { background-color: rgba(175,184,193,0.2); border-radius: 6px; font-size: 85%; margin: 0; padding: .2em .4em; }
            .markdown-content pre { background-color: #f6f8fa; border-radius: 6px; font-size: 85%; line-height: 1.45; overflow: auto; padding: 16px; }
            .markdown-content blockquote { border-left: .25em solid #d0d7de; color: #656d76; margin: 0; padding: 0 1em; }
            .markdown-content table { border-collapse: collapse; border-spacing: 0; width: 100%; margin-bottom: 16px; }
            .markdown-content td,.markdown-content th { border: 1px solid #d0d7de; padding: 6px 13px; }
            .markdown-content th { background-color: #f6f8fa; font-weight: 600; }
            .markdown-content ul,.markdown-content ol { padding-left: 2em; margin-bottom: 16px; }
            .markdown-content .toc { background-color: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 16px; margin: 16px 0; }
            .markdown-content .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .markdown-content .toc > ul { padding-left: 0; }
            .markdown-content .toc li { margin: 4px 0; }
            .markdown-content .toc a, .markdown-content .toc a:link, .markdown-content .toc a:visited, .markdown-content .toc a:hover, .markdown-content .toc a:active { 
                text-decoration: none !important; color: #0969da; font-weight: 500; 
                border: none !important; outline: none !important;
            }
            .markdown-content .toc a:hover { 
                color: #0550ae !important; background-color: rgba(9, 105, 218, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .markdown-content .toclink, .markdown-content .toclink:link, .markdown-content .toclink:visited, .markdown-content .toclink:hover, .markdown-content .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .markdown-content .headerlink { display: none !important; }
            .markdown-content .admonition { margin: 1em 0; padding: 12px; border-left: 4px solid #0969da; background-color: #ddf4ff; }
            .markdown-content .task-list-item { list-style-type: none; }
            .markdown-content .task-list-item input { margin-right: 8px; }
            .markdown-content .mermaid { background-color: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 16px; margin: 16px 0; }
            .markdown-content .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .markdown-content .mermaid code { background: transparent; padding: 0; font-size: 14px; }
        ''',
        'dark': '''
            .markdown-content { 
                font-family: -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif; 
                line-height: 1.6; color: #e6edf3; background-color: #0d1117; 
                max-width: 980px; margin: 0 auto; padding: 45px; 
            }
            .markdown-content h1,.markdown-content h2,.markdown-content h3,.markdown-content h4,.markdown-content h5,.markdown-content h6 { 
                margin-top: 24px; margin-bottom: 16px; font-weight: 600; line-height: 1.25; color: #f0f6fc; 
            }
            .markdown-content h1 { font-size: 2em; border-bottom: 1px solid #21262d; padding-bottom: .3em; }
            .markdown-content h2 { font-size: 1.5em; border-bottom: 1px solid #21262d; padding-bottom: .3em; }
            .markdown-content p { margin-bottom: 16px; }
            .markdown-content code { background-color: rgba(110,118,129,0.4); border-radius: 6px; font-size: 85%; margin: 0; padding: .2em .4em; }
            .markdown-content pre { background-color: #161b22; border-radius: 6px; font-size: 85%; line-height: 1.45; overflow: auto; padding: 16px; }
            .markdown-content blockquote { border-left: .25em solid #30363d; color: #8b949e; margin: 0; padding: 0 1em; }
            .markdown-content table { border-collapse: collapse; border-spacing: 0; width: 100%; margin-bottom: 16px; }
            .markdown-content td,.markdown-content th { border: 1px solid #30363d; padding: 6px 13px; }
            .markdown-content th { background-color: #161b22; font-weight: 600; }
            .markdown-content ul,.markdown-content ol { padding-left: 2em; margin-bottom: 16px; }
            .markdown-content .toc { background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 16px 0; }
            .markdown-content .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .markdown-content .toc > ul { padding-left: 0; }
            .markdown-content .toc li { margin: 4px 0; }
            .markdown-content .toc a, .markdown-content .toc a:link, .markdown-content .toc a:visited, .markdown-content .toc a:hover, .markdown-content .toc a:active { 
                text-decoration: none !important; color: #58a6ff; font-weight: 500; 
                border: none !important; outline: none !important;
            }
            .markdown-content .toc a:hover { 
                color: #79c0ff !important; background-color: rgba(88, 166, 255, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .markdown-content .toclink, .markdown-content .toclink:link, .markdown-content .toclink:visited, .markdown-content .toclink:hover, .markdown-content .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .markdown-content .headerlink { display: none !important; }
            .markdown-content .admonition { margin: 1em 0; padding: 12px; border-left: 4px solid #1f6feb; background-color: #0c2d6b; }
            .markdown-content .task-list-item { list-style-type: none; }
            .markdown-content .task-list-item input { margin-right: 8px; }
            .markdown-content .mermaid { background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 16px 0; }
            .markdown-content .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .markdown-content .mermaid code { background: transparent; padding: 0; font-size: 14px; color: #e6edf3; }
        ''',
        'minimal': '''
            .markdown-content { 
                font-family: Georgia, 'Times New Roman', serif; line-height: 1.8; color: #333; 
                max-width: 800px; margin: 0 auto; padding: 40px 20px; 
            }
            .markdown-content h1,.markdown-content h2,.markdown-content h3,.markdown-content h4,.markdown-content h5,.markdown-content h6 { 
                color: #000; margin-top: 2em; margin-bottom: 0.5em; 
            }
            .markdown-content h1 { font-size: 2.2em; }
            .markdown-content h2 { font-size: 1.8em; }
            .markdown-content p { margin-bottom: 1.2em; }
            .markdown-content code { background-color: #f5f5f5; padding: 2px 4px; border-radius: 3px; font-family: 'Courier New', monospace; }
            .markdown-content pre { background-color: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; }
            .markdown-content blockquote { border-left: 4px solid #ddd; margin: 1.5em 0; padding-left: 20px; font-style: italic; color: #666; }
            .markdown-content table { width: 100%; border-collapse: collapse; margin: 1.5em 0; }
            .markdown-content td,.markdown-content th { border: 1px solid #ddd; padding: 8px 12px; }
            .markdown-content th { background-color: #f9f9f9; font-weight: bold; }
            .markdown-content ul,.markdown-content ol { margin-bottom: 1.2em; }
            .markdown-content .toc { background-color: #f9f9f9; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 1.5em 0; }
            .markdown-content .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .markdown-content .toc > ul { padding-left: 0; }
            .markdown-content .toc li { margin: 4px 0; }
            .markdown-content .toc a, .markdown-content .toc a:link, .markdown-content .toc a:visited, .markdown-content .toc a:hover, .markdown-content .toc a:active { 
                text-decoration: none !important; color: #0066cc; font-weight: 500; 
                border: none !important; outline: none !important;
            }
            .markdown-content .toc a:hover { 
                color: #004499 !important; background-color: rgba(0, 102, 204, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .markdown-content .toclink, .markdown-content .toclink:link, .markdown-content .toclink:visited, .markdown-content .toclink:hover, .markdown-content .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .markdown-content .headerlink { display: none !important; }
            .markdown-content .admonition { margin: 1.5em 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9; }
            .markdown-content .mermaid { background-color: #f9f9f9; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 1.5em 0; }
            .markdown-content .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .markdown-content .mermaid code { background: transparent; padding: 0; font-size: 14px; }
        ''',
        'academic': '''
            .markdown-content { 
                font-family: "Times New Roman", Times, serif; line-height: 1.8; color: #2c3e50; background-color: #ffffff; 
                max-width: 900px; margin: 0 auto; padding: 60px 40px; 
            }
            .markdown-content h1,.markdown-content h2,.markdown-content h3,.markdown-content h4,.markdown-content h5,.markdown-content h6 { 
                font-family: "Georgia", serif; font-weight: bold; color: #1a252f; 
                margin-top: 2.5em; margin-bottom: 1em; 
            }
            .markdown-content h1 { font-size: 2.4em; text-align: center; border-bottom: 3px double #34495e; padding-bottom: 0.5em; }
            .markdown-content h2 { font-size: 1.8em; border-bottom: 1px solid #bdc3c7; padding-bottom: 0.3em; }
            .markdown-content h3 { font-size: 1.4em; }
            .markdown-content p { margin-bottom: 1.5em; text-align: justify; text-indent: 2em; }
            .markdown-content blockquote { 
                border-left: 4px solid #95a5a6; margin: 2em 0; padding: 1em 2em; 
                background-color: #f8f9fa; font-style: italic; color: #5d6d7e; 
            }
            .markdown-content code { 
                background-color: #ecf0f1; padding: 3px 6px; border-radius: 4px; 
                font-family: "Consolas", "Monaco", monospace; font-size: 0.9em; 
            }
            .markdown-content pre { 
                background-color: #f4f6f7; border: 1px solid #d5dbdb; border-radius: 6px; 
                padding: 20px; overflow-x: auto; margin: 2em 0; 
                font-family: "Consolas", "Monaco", monospace; line-height: 1.5; 
            }
            .markdown-content table { width: 100%; border-collapse: collapse; margin: 2em 0; font-size: 0.95em; }
            .markdown-content td,.markdown-content th { border: 1px solid #bdc3c7; padding: 12px 15px; text-align: left; }
            .markdown-content th { background-color: #34495e; color: white; font-weight: bold; }
            .markdown-content tr:nth-child(even) { background-color: #f8f9fa; }
            .markdown-content .toc { background-color: #f8f9fa; border: 2px solid #bdc3c7; border-radius: 6px; padding: 20px; margin: 2em 0; }
            .markdown-content .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .markdown-content .toc > ul { padding-left: 0; }
            .markdown-content .toc li { margin: 6px 0; }
            .markdown-content .toc a, .markdown-content .toc a:link, .markdown-content .toc a:visited, .markdown-content .toc a:hover, .markdown-content .toc a:active { 
                text-decoration: none !important; color: #2c3e50; font-weight: 600; 
                border: none !important; outline: none !important;
            }
            .markdown-content .toc a:hover { 
                color: #34495e !important; background-color: rgba(44, 62, 80, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .markdown-content .toclink, .markdown-content .toclink:link, .markdown-content .toclink:visited, .markdown-content .toclink:hover, .markdown-content .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .markdown-content .headerlink { display: none !important; }
            .markdown-content .task-list-item { list-style-type: none; margin-left: -1.5em; }
            .markdown-content .task-list-item input { margin-right: 8px; transform: scale(1.2); }
            .markdown-content .mermaid { background-color: #f8f9fa; border: 2px solid #bdc3c7; border-radius: 6px; padding: 20px; margin: 2em 0; }
            .markdown-content .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .markdown-content .mermaid code { background: transparent; padding: 0; font-size: 14px; }
        ''',
        'elegant': '''
            .markdown-content { 
                font-family: "Crimson Text", "Georgia", serif; line-height: 1.8; color: #2c3e50; background-color: #fdfcf8; 
                max-width: 850px; margin: 0 auto; padding: 60px 50px; 
            }
            .markdown-content h1,.markdown-content h2,.markdown-content h3,.markdown-content h4,.markdown-content h5,.markdown-content h6 { 
                font-family: "Playfair Display", "Georgia", serif; font-weight: 700; color: #1a252f; 
                margin-top: 3em; margin-bottom: 1em; 
            }
            .markdown-content h1 { 
                font-size: 3.2em; text-align: center; margin-bottom: 0.5em; 
                border-bottom: 2px solid #d4af37; padding-bottom: 0.3em; 
            }
            .markdown-content h2 { font-size: 2.4em; color: #8b4513; }
            .markdown-content h3 { font-size: 1.8em; color: #a0522d; }
            .markdown-content p { margin-bottom: 1.6em; text-align: justify; font-size: 1.1em; }
            .markdown-content blockquote { 
                border-left: 4px solid #d4af37; background-color: #f9f7f1; margin: 2.5em 0; 
                padding: 1.5em 2.5em; font-style: italic; font-size: 1.05em; color: #5d4e37; 
                border-radius: 0 8px 8px 0; 
            }
            .markdown-content code { 
                background-color: #f4f1eb; border: 1px solid #e8dcc6; padding: 3px 6px; 
                border-radius: 4px; font-family: "Source Code Pro", monospace; color: #8b4513; 
            }
            .markdown-content pre { 
                background-color: #f9f7f1; border: 1px solid #e8dcc6; border-radius: 8px; 
                padding: 25px; overflow-x: auto; margin: 2.5em 0; 
                box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.06); 
            }
            .markdown-content table { width: 100%; border-collapse: collapse; margin: 2.5em 0; font-size: 1em; }
            .markdown-content th { background-color: #8b4513; color: #fdfcf8; padding: 15px; font-weight: bold; border: 1px solid #a0522d; }
            .markdown-content td { padding: 12px 15px; border: 1px solid #d4af37; background-color: #fdfcf8; }
            .markdown-content tr:nth-child(even) td { background-color: #f9f7f1; }
            .markdown-content .toc { background-color: #f9f7f1; border: 2px solid #d4af37; border-radius: 8px; padding: 25px; margin: 2.5em 0; }
            .markdown-content .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .markdown-content .toc > ul { padding-left: 0; }
            .markdown-content .toc li { margin: 6px 0; }
            .markdown-content .toc a, .markdown-content .toc a:link, .markdown-content .toc a:visited, .markdown-content .toc a:hover, .markdown-content .toc a:active { 
                text-decoration: none !important; color: #8b4513; font-weight: 600; 
                font-family: "Playfair Display", "Georgia", serif;
                border: none !important; outline: none !important;
            }
            .markdown-content .toc a:hover { 
                color: #a0522d !important; background-color: rgba(139, 69, 19, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .markdown-content .toclink, .markdown-content .toclink:link, .markdown-content .toclink:visited, .markdown-content .toclink:hover, .markdown-content .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .markdown-content .headerlink { display: none !important; }
            .markdown-content .mermaid { background-color: #f9f7f1; border: 2px solid #d4af37; border-radius: 8px; padding: 25px; margin: 2.5em 0; }
            .markdown-content .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .markdown-content .mermaid code { background: transparent; padding: 0; font-size: 14px; color: #8b4513; }
        ''',
    }
    return styles.get(theme, styles['github'])


def _get_pygments_css(style):
    """获取Pygments代码高亮CSS样式"""
    try:
        from pygments.formatters import HtmlFormatter
        formatter = HtmlFormatter(style=style, cssclass='highlight')
        return formatter.get_style_defs()
    except:
        return ''


# 简化的便捷函数
def markdown_to_html(markdown_text, theme='github', enable_toc=True, **kwargs):
    """
    简化的Markdown转HTML函数

    Args:
        markdown_text: Markdown格式文本
        theme: 样式主题 ('github', 'dark', 'minimal', 'academic', 'elegant')
        enable_toc: 是否启用目录
        **kwargs: 其他选项传递给md2html

    Returns:
        str: 转换后的HTML
    """
    return md2html(
        markdown_text,
        style_theme=theme,
        enable_toc=enable_toc,
        **kwargs
    )


def relative_time_filter(dt):
    """改进的相对时间过滤器，处理各种时间输入"""
    if dt is None:
        return "未知时间"

    # 确保传入的时间是UTC时区感知的
    if dt.tzinfo is None:
        # 如果是朴素时间，假设它是UTC时间
        dt_utc = dt.replace(tzinfo=UTC)
    else:
        # 如果有时区信息，转换为UTC
        dt_utc = dt.astimezone(UTC)

    # 获取当前UTC时间
    now_utc = datetime.now(UTC)

    # 计算时间差
    if dt_utc > now_utc:
        # 如果是未来时间
        diff = dt_utc - now_utc
        if diff < timedelta(minutes=1):
            return "即将"
        elif diff < timedelta(hours=1):
            return f"{int(diff.seconds / 60)}分钟后"
        elif diff < timedelta(days=1):
            return f"{int(diff.seconds / 3600)}小时后"
        else:
            return dt_utc.strftime('%Y-%m-%d') if dt_utc is not None else "未知时间"
    else:
        # 如果是过去时间
        diff = now_utc - dt_utc

        if diff < timedelta(minutes=1):
            return "刚刚"
        elif diff < timedelta(hours=1):
            return f"{int(diff.seconds / 60)}分钟前"
        elif diff < timedelta(days=1):
            return f"{int(diff.seconds / 3600)}小时前"
        elif diff < timedelta(days=30):
            return f"{diff.days}天前"
        else:
            return dt_utc.strftime('%Y-%m-%d') if dt_utc is not None else "未知时间"


@lru_cache(maxsize=128)
def category_filter(category_id):
    with get_db() as db:
        category = db.query(Category).filter(Category.id == category_id).first()
        if category:
            return category.name
        return None


def f2list(input_value, delimiter=';'):
    """
    将分隔符分隔的字符串转换为列表
    """
    try:
        if input_value is None:
            return []

        # 如果已经是列表且不为空，直接返回
        if isinstance(input_value, list):
            if input_value and isinstance(input_value[0], str) and delimiter in input_value[0]:
                # 如果列表中的字符串包含分隔符，进行分割
                result = []
                for item in input_value:
                    if isinstance(item, str):
                        result.extend([tag.strip() for tag in item.split(delimiter) if tag.strip()])
                    else:
                        result.append(str(item).strip())
                return result
            return input_value

        # 处理字符串输入
        if isinstance(input_value, str):
            return [tag.strip() for tag in input_value.split(delimiter) if tag.strip()]

        # 处理其他类型
        return [str(input_value).strip()]


    except (ValueError, TypeError, AttributeError) as e:
        app.logger.warning(f"Error converting to list: {e}, Input: {input_value}")
        return [str(input_value)] if input_value else []
