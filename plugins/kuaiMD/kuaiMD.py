# coding=utf-8
"""
kuai: 1.0
python_version:
    - 3.11.0
os:
    - Windows 11
packages:
    - markdown
    - pygments
    - pymdown-extensions
name: Markdown转HTML转换器
description: 专业的Markdown转HTML转换工具，支持实时预览和多种主题
input_description: 通过Web界面输入Markdown文本和转换参数
output_description: 实时HTML预览，支持复制、下载HTML和浏览器打印
"""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

import markdown


class Params:
    """
    说明: 启动参数配置
    """

    def __init__(self):
        """
        label: 服务端口号
        input_method: IntInput
        unit: 端口
        max: 65535
        min: 12000
        description: HTTP服务器监听端口号
        """
        self.port: int = 12001

        """
        label: 自动打开浏览器
        input_method: ToggleSwitch
        description: 启动后是否自动打开默认浏览器
        """
        self.auto_open_browser: bool = True

        """
        label: 默认样式主题
        input_method: Dropdown
        options:
            - GitHub风格
            - 深色主题
            - 简约风格
            - 学术风格
            - 典雅风格
        description: 页面加载时的默认样式主题
        """
        self.default_theme: str = "GitHub风格"


# 全局参数实例
params = Params()


class MarkdownHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            html_content = get_main_page()
            self.wfile.write(html_content.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/convert' or self.path == 'kuaiMD/convert':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                data = json.loads(post_data.decode('utf-8'))
                markdown_text = data.get('markdown', '')
                options = data.get('options', {})

                html_result = convert_markdown_to_html(markdown_text, options)

                response = {
                    'success': True,
                    'html': html_result
                }

                self.send_response(200)
                self.send_header('Content-type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode('utf-8'))

            except Exception as e:
                response = {
                    'success': False,
                    'error': str(e)
                }
                self.send_response(500)
                self.send_header('Content-type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode('utf-8'))

    def log_message(self, format, *args):
        # 禁用默认访问日志
        pass


def convert_markdown_to_html(markdown_text, options):
    """转换Markdown为HTML"""
    extensions = []
    extension_configs = {}

    # 基础扩展
    if options.get('enable_tables', True):
        extensions.append('tables')

    if options.get('enable_fenced_code', True):
        extensions.append('fenced_code')

    if options.get('enable_sane_lists', True):
        extensions.append('sane_lists')

    if options.get('enable_footnotes', False):
        extensions.append('footnotes')

    if options.get('enable_attr_list', False):
        extensions.append('attr_list')

    if options.get('enable_meta', False):
        extensions.append('meta')

    if options.get('enable_nl2br', False):
        extensions.append('nl2br')

    if options.get('enable_admonition', False):
        extensions.append('admonition')

    # 代码高亮
    if options.get('enable_code_highlight', True):
        extensions.append('codehilite')
        extension_configs['codehilite'] = {
            'use_pygments': True,
            'css_class': 'highlight',
            'pygments_style': options.get('pygments_style', 'default')
        }

    # 目录生成
    if options.get('enable_toc', False):
        extensions.append('toc')
        extension_configs['toc'] = {
            'title': options.get('toc_title', '目录'),
            'anchorlink': options.get('toc_anchorlink', True),
            'permalink': options.get('toc_permalink', True),
            'toc_depth': options.get('toc_depth', 6),
            'marker': '[TOC]'
        }

    # PyMdown高级扩展
    if options.get('enable_superfences', True):
        extensions.append('pymdownx.superfences')
        extension_configs['pymdownx.superfences'] = {
            'custom_fences': [
                {
                    'name': 'mermaid',
                    'class': 'mermaid',
                    'format': lambda source, language, css_class, options,
                                     md: f'<div class="{css_class}"><pre><code>{source}</code></pre></div>'
                }
            ]
        }

    if options.get('enable_tasklist', True):
        extensions.append('pymdownx.tasklist')
        extension_configs['pymdownx.tasklist'] = {
            'custom_checkbox': True,
            'clickable_checkbox': False
        }

    if options.get('enable_magiclink', False):
        extensions.append('pymdownx.magiclink')
        extension_configs['pymdownx.magiclink'] = {
            'repo_url_shorthand': True,
            'social_url_shorthand': True
        }

    if options.get('enable_emoji', False):
        extensions.append('pymdownx.emoji')
        extension_configs['pymdownx.emoji'] = {
            'emoji_index': lambda: None,
            'emoji_generator': lambda: None
        }

    # 创建Markdown实例并转换
    md = markdown.Markdown(
        extensions=extensions,
        extension_configs=extension_configs,
        tab_length=options.get('tab_length', 4)
    )

    html = md.convert(markdown_text)

    # 生成完整HTML页面
    if options.get('full_page', False):
        css_style = get_css_style(options.get('style_theme', 'github'))
        pygments_css = get_pygments_css(options.get('pygments_style', 'default'))

        # PDF打印样式
        pdf_css = ""
        if options.get('pdf_mode', False):
            pdf_css = """
            @media print {
                body { margin: 0; padding: 15mm 20mm; background: white !important; color: black !important; }
                h1, h2, h3, h4, h5, h6 { page-break-after: avoid; color: black !important; }
                blockquote, pre, table { page-break-inside: avoid; border: 1px solid #ccc !important; background: #f9f9f9 !important; }
                img { max-width: 100% !important; }
                code, pre { background: #f5f5f5 !important; color: black !important; border: 1px solid #ddd !important; }
                a { color: blue !important; }
                .task-list-item input { -webkit-appearance: checkbox; appearance: checkbox; }
            }
            @page { size: A4; margin: 15mm 20mm; }
            """

        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Markdown转换结果</title>
    <style>
        {css_style}
        {pygments_css}
        {pdf_css}
    </style>
</head>
<body>
    {html}
</body>
</html>'''

    return html


def get_pygments_css(style):
    """获取Pygments代码高亮CSS样式"""
    try:
        from pygments.formatters import HtmlFormatter
        formatter = HtmlFormatter(style=style, cssclass='highlight')
        return formatter.get_style_defs()
    except:
        return ''


def get_css_style(theme):
    """获取指定主题的CSS样式"""
    styles = {
        'github': '''
            body { 
                font-family: -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif; 
                line-height: 1.6; color: #24292f; background-color: #ffffff; 
                max-width: 980px; margin: 0 auto; padding: 45px; 
            }
            h1,h2,h3,h4,h5,h6 { margin-top: 24px; margin-bottom: 16px; font-weight: 600; line-height: 1.25; }
            h1 { font-size: 2em; border-bottom: 1px solid #d0d7de; padding-bottom: .3em; }
            h2 { font-size: 1.5em; border-bottom: 1px solid #d0d7de; padding-bottom: .3em; }
            p { margin-bottom: 16px; }
            code { background-color: rgba(175,184,193,0.2); border-radius: 6px; font-size: 85%; margin: 0; padding: .2em .4em; }
            pre { background-color: #f6f8fa; border-radius: 6px; font-size: 85%; line-height: 1.45; overflow: auto; padding: 16px; }
            blockquote { border-left: .25em solid #d0d7de; color: #656d76; margin: 0; padding: 0 1em; }
            table { border-collapse: collapse; border-spacing: 0; width: 100%; margin-bottom: 16px; }
            td,th { border: 1px solid #d0d7de; padding: 6px 13px; }
            th { background-color: #f6f8fa; font-weight: 600; }
            ul,ol { padding-left: 2em; margin-bottom: 16px; }
            .toc { background-color: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 16px; margin: 16px 0; }
            .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .toc > ul { padding-left: 0; }
            .toc li { margin: 4px 0; }
            .toc a, .toc a:link, .toc a:visited, .toc a:hover, .toc a:active { 
                text-decoration: none !important; color: #0969da; font-weight: 500; 
                border: none !important; outline: none !important;
            }
            .toc a:hover { 
                color: #0550ae !important; background-color: rgba(9, 105, 218, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .toclink, .toclink:link, .toclink:visited, .toclink:hover, .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .headerlink { display: none !important; }
            .admonition { margin: 1em 0; padding: 12px; border-left: 4px solid #0969da; background-color: #ddf4ff; }
            .task-list-item { list-style-type: none; }
            .task-list-item input { margin-right: 8px; }
            .mermaid { background-color: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 16px; margin: 16px 0; }
            .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .mermaid code { background: transparent; padding: 0; font-size: 14px; }
        ''',
        'dark': '''
            body { 
                font-family: -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif; 
                line-height: 1.6; color: #e6edf3; background-color: #0d1117; 
                max-width: 980px; margin: 0 auto; padding: 45px; 
            }
            h1,h2,h3,h4,h5,h6 { margin-top: 24px; margin-bottom: 16px; font-weight: 600; line-height: 1.25; color: #f0f6fc; }
            h1 { font-size: 2em; border-bottom: 1px solid #21262d; padding-bottom: .3em; }
            h2 { font-size: 1.5em; border-bottom: 1px solid #21262d; padding-bottom: .3em; }
            p { margin-bottom: 16px; }
            code { background-color: rgba(110,118,129,0.4); border-radius: 6px; font-size: 85%; margin: 0; padding: .2em .4em; }
            pre { background-color: #161b22; border-radius: 6px; font-size: 85%; line-height: 1.45; overflow: auto; padding: 16px; }
            blockquote { border-left: .25em solid #30363d; color: #8b949e; margin: 0; padding: 0 1em; }
            table { border-collapse: collapse; border-spacing: 0; width: 100%; margin-bottom: 16px; }
            td,th { border: 1px solid #30363d; padding: 6px 13px; }
            th { background-color: #161b22; font-weight: 600; }
            ul,ol { padding-left: 2em; margin-bottom: 16px; }
            .toc { background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 16px 0; }
            .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .toc > ul { padding-left: 0; }
            .toc li { margin: 4px 0; }
            .toc a, .toc a:link, .toc a:visited, .toc a:hover, .toc a:active { 
                text-decoration: none !important; color: #58a6ff; font-weight: 500; 
                border: none !important; outline: none !important;
            }
            .toc a:hover { 
                color: #79c0ff !important; background-color: rgba(88, 166, 255, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .toclink, .toclink:link, .toclink:visited, .toclink:hover, .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .headerlink { display: none !important; }
            .admonition { margin: 1em 0; padding: 12px; border-left: 4px solid #1f6feb; background-color: #0c2d6b; }
            .task-list-item { list-style-type: none; }
            .task-list-item input { margin-right: 8px; }
            .mermaid { background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 16px 0; }
            .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .mermaid code { background: transparent; padding: 0; font-size: 14px; color: #e6edf3; }
        ''',
        'minimal': '''
            body { font-family: Georgia, 'Times New Roman', serif; line-height: 1.8; color: #333; max-width: 800px; margin: 0 auto; padding: 40px 20px; }
            h1,h2,h3,h4,h5,h6 { color: #000; margin-top: 2em; margin-bottom: 0.5em; }
            h1 { font-size: 2.2em; }
            h2 { font-size: 1.8em; }
            p { margin-bottom: 1.2em; }
            code { background-color: #f5f5f5; padding: 2px 4px; border-radius: 3px; font-family: 'Courier New', monospace; }
            pre { background-color: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; }
            blockquote { border-left: 4px solid #ddd; margin: 1.5em 0; padding-left: 20px; font-style: italic; color: #666; }
            table { width: 100%; border-collapse: collapse; margin: 1.5em 0; }
            td,th { border: 1px solid #ddd; padding: 8px 12px; }
            th { background-color: #f9f9f9; font-weight: bold; }
            ul,ol { margin-bottom: 1.2em; }
            .toc { background-color: #f9f9f9; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 1.5em 0; }
            .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .toc > ul { padding-left: 0; }
            .toc li { margin: 4px 0; }
            .toc a, .toc a:link, .toc a:visited, .toc a:hover, .toc a:active { 
                text-decoration: none !important; color: #0066cc; font-weight: 500; 
                border: none !important; outline: none !important;
            }
            .toc a:hover { 
                color: #004499 !important; background-color: rgba(0, 102, 204, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .toclink, .toclink:link, .toclink:visited, .toclink:hover, .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .headerlink { display: none !important; }
            .admonition { margin: 1.5em 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9; }
            .mermaid { background-color: #f9f9f9; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 1.5em 0; }
            .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .mermaid code { background: transparent; padding: 0; font-size: 14px; }
        ''',
        'academic': '''
            body { 
                font-family: "Times New Roman", Times, serif; line-height: 1.8; color: #2c3e50; background-color: #ffffff; 
                max-width: 900px; margin: 0 auto; padding: 60px 40px; 
            }
            h1,h2,h3,h4,h5,h6 { 
                font-family: "Georgia", serif; font-weight: bold; color: #1a252f; 
                margin-top: 2.5em; margin-bottom: 1em; 
            }
            h1 { font-size: 2.4em; text-align: center; border-bottom: 3px double #34495e; padding-bottom: 0.5em; }
            h2 { font-size: 1.8em; border-bottom: 1px solid #bdc3c7; padding-bottom: 0.3em; }
            h3 { font-size: 1.4em; }
            p { margin-bottom: 1.5em; text-align: justify; text-indent: 2em; }
            blockquote { 
                border-left: 4px solid #95a5a6; margin: 2em 0; padding: 1em 2em; 
                background-color: #f8f9fa; font-style: italic; color: #5d6d7e; 
            }
            code { 
                background-color: #ecf0f1; padding: 3px 6px; border-radius: 4px; 
                font-family: "Consolas", "Monaco", monospace; font-size: 0.9em; 
            }
            pre { 
                background-color: #f4f6f7; border: 1px solid #d5dbdb; border-radius: 6px; 
                padding: 20px; overflow-x: auto; margin: 2em 0; 
                font-family: "Consolas", "Monaco", monospace; line-height: 1.5; 
            }
            table { width: 100%; border-collapse: collapse; margin: 2em 0; font-size: 0.95em; }
            td,th { border: 1px solid #bdc3c7; padding: 12px 15px; text-align: left; }
            th { background-color: #34495e; color: white; font-weight: bold; }
            tr:nth-child(even) { background-color: #f8f9fa; }
            .toc { background-color: #f8f9fa; border: 2px solid #bdc3c7; border-radius: 6px; padding: 20px; margin: 2em 0; }
            .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .toc > ul { padding-left: 0; }
            .toc li { margin: 6px 0; }
            .toc a, .toc a:link, .toc a:visited, .toc a:hover, .toc a:active { 
                text-decoration: none !important; color: #2c3e50; font-weight: 600; 
                border: none !important; outline: none !important;
            }
            .toc a:hover { 
                color: #34495e !important; background-color: rgba(44, 62, 80, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .toclink, .toclink:link, .toclink:visited, .toclink:hover, .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .headerlink { display: none !important; }
            .task-list-item { list-style-type: none; margin-left: -1.5em; }
            .task-list-item input { margin-right: 8px; transform: scale(1.2); }
            .mermaid { background-color: #f8f9fa; border: 2px solid #bdc3c7; border-radius: 6px; padding: 20px; margin: 2em 0; }
            .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .mermaid code { background: transparent; padding: 0; font-size: 14px; }
        ''',
        'elegant': '''
            body { 
                font-family: "Crimson Text", "Georgia", serif; line-height: 1.8; color: #2c3e50; background-color: #fdfcf8; 
                max-width: 850px; margin: 0 auto; padding: 60px 50px; 
            }
            h1,h2,h3,h4,h5,h6 { 
                font-family: "Playfair Display", "Georgia", serif; font-weight: 700; color: #1a252f; 
                margin-top: 3em; margin-bottom: 1em; 
            }
            h1 { 
                font-size: 3.2em; text-align: center; margin-bottom: 0.5em; 
                border-bottom: 2px solid #d4af37; padding-bottom: 0.3em; 
            }
            h2 { font-size: 2.4em; color: #8b4513; }
            h3 { font-size: 1.8em; color: #a0522d; }
            p { margin-bottom: 1.6em; text-align: justify; font-size: 1.1em; }
            blockquote { 
                border-left: 4px solid #d4af37; background-color: #f9f7f1; margin: 2.5em 0; 
                padding: 1.5em 2.5em; font-style: italic; font-size: 1.05em; color: #5d4e37; 
                border-radius: 0 8px 8px 0; 
            }
            code { 
                background-color: #f4f1eb; border: 1px solid #e8dcc6; padding: 3px 6px; 
                border-radius: 4px; font-family: "Source Code Pro", monospace; color: #8b4513; 
            }
            pre { 
                background-color: #f9f7f1; border: 1px solid #e8dcc6; border-radius: 8px; 
                padding: 25px; overflow-x: auto; margin: 2.5em 0; 
                box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.06); 
            }
            table { width: 100%; border-collapse: collapse; margin: 2.5em 0; font-size: 1em; }
            th { background-color: #8b4513; color: #fdfcf8; padding: 15px; font-weight: bold; border: 1px solid #a0522d; }
            td { padding: 12px 15px; border: 1px solid #d4af37; background-color: #fdfcf8; }
            tr:nth-child(even) td { background-color: #f9f7f1; }
            .toc { background-color: #f9f7f1; border: 2px solid #d4af37; border-radius: 8px; padding: 25px; margin: 2.5em 0; }
            .toc ul { margin: 0; padding-left: 1.5em; list-style-type: none; }
            .toc > ul { padding-left: 0; }
            .toc li { margin: 6px 0; }
            .toc a, .toc a:link, .toc a:visited, .toc a:hover, .toc a:active { 
                text-decoration: none !important; color: #8b4513; font-weight: 600; 
                font-family: "Playfair Display", "Georgia", serif;
                border: none !important; outline: none !important;
            }
            .toc a:hover { 
                color: #a0522d !important; background-color: rgba(139, 69, 19, 0.1) !important;
                padding: 2px 4px; border-radius: 3px;
            }
            .toclink, .toclink:link, .toclink:visited, .toclink:hover, .toclink:active {
                text-decoration: none !important; border-bottom: none !important;
                border: none !important; outline: none !important;
            }
            .headerlink { display: none !important; }
            .mermaid { background-color: #f9f7f1; border: 2px solid #d4af37; border-radius: 8px; padding: 25px; margin: 2.5em 0; }
            .mermaid pre { background: transparent; border: none; padding: 0; margin: 0; }
            .mermaid code { background: transparent; padding: 0; font-size: 14px; color: #8b4513; }
        ''',
    }
    return styles.get(theme, styles['github'])


def get_main_page(your_content=''):
    """生成主页面HTML"""
    kuaiMD_api_url = '/kuaiMD/convert'
    js_code = f'''
        let currentHtml = '';
        let updateTimeout = null;
        
        function getAllOptions() {{
            return {{
                style_theme: document.getElementById('style-theme').value,
                pygments_style: document.getElementById('pygments-style').value,
                tab_length: parseInt(document.getElementById('tab-length').value),
                enable_tables: document.getElementById('enable-tables').checked,
                enable_fenced_code: document.getElementById('enable-fenced-code').checked,
                enable_code_highlight: document.getElementById('enable-code-highlight').checked,
                enable_toc: document.getElementById('enable-toc').checked,
                enable_footnotes: document.getElementById('enable-footnotes').checked,
                enable_attr_list: document.getElementById('enable-attr-list').checked,
                enable_admonition: document.getElementById('enable-admonition').checked,
                enable_meta: document.getElementById('enable-meta').checked,
                enable_nl2br: document.getElementById('enable-nl2br').checked,
                enable_sane_lists: document.getElementById('enable-sane-lists').checked,
                enable_superfences: document.getElementById('enable-superfences').checked,
                enable_tasklist: document.getElementById('enable-tasklist').checked,
                enable_magiclink: document.getElementById('enable-magiclink').checked,
                enable_emoji: document.getElementById('enable-emoji').checked,
                full_page: document.getElementById('full-page').checked,
                toc_title: '目录',
                toc_anchorlink: true,
                toc_permalink: true
            }};
        }}
        
        function showOptionsPanel(panelId) {{
            const currentPanel = document.querySelector('.floating-panel[style*="block"]');
            const targetPanel = document.getElementById(panelId);
            
            if (currentPanel && currentPanel.id === panelId) {{
                hideAllPanels();
                return;
            }}
            
            hideAllPanels();
            
            if (targetPanel) {{
                targetPanel.style.display = 'block';
            }}
        }}
        
        function hideAllPanels() {{
            const panels = document.querySelectorAll('.floating-panel');
            panels.forEach(panel => panel.style.display = 'none');
        }}
        
        document.addEventListener('click', function(e) {{
            if (!e.target.closest('.option-button') && !e.target.closest('.floating-panel')) {{
                hideAllPanels();
            }}
        }});
        
        function updatePreview() {{
            if (updateTimeout) {{
                clearTimeout(updateTimeout);
            }}
            
            updateTimeout = setTimeout(function() {{
                const startTime = Date.now();
                const markdownText = document.getElementById('markdown-input').value;
                updateStats(markdownText);
                const options = getAllOptions();
                
                fetch(`{kuaiMD_api_url}`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ markdown: markdownText, options: options }})
                }})
                .then(function(response) {{ return response.json(); }})
                .then(function(data) {{
                    const endTime = Date.now();
                    document.getElementById('conversion-time').textContent = '转换耗时: ' + (endTime - startTime) + 'ms';
                    
                    if (data.success) {{
                        currentHtml = data.html;
                        
                        if (options.full_page) {{
                            const previewArea = document.getElementById('preview-area');
                            previewArea.innerHTML = '';
                            
                            const iframe = document.createElement('iframe');
                            iframe.style.width = '100%';
                            iframe.style.height = '100%';
                            iframe.style.border = 'none';
                            iframe.style.display = 'block';
                            iframe.srcdoc = currentHtml;
                            previewArea.appendChild(iframe);
                        }} else {{
                            const previewContent = document.getElementById('preview-content');
                            if (previewContent) {{
                                previewContent.innerHTML = currentHtml;
                            }} else {{
                                document.getElementById('preview-area').innerHTML = '<div class="preview-content" id="preview-content">' + currentHtml + '</div>';
                            }}
                        }}
                        
                        const htmlSize = new Blob([currentHtml]).size;
                        document.getElementById('html-size').textContent = 'HTML大小: ' + formatBytes(htmlSize);
                        
                    }} else {{
                        const errorContent = '<div style="color: red; padding: 20px;"><h3>转换错误</h3><p>' + data.error + '</p></div>';
                        const previewContent = document.getElementById('preview-content');
                        if (previewContent) {{
                            previewContent.innerHTML = errorContent;
                        }} else {{
                            document.getElementById('preview-area').innerHTML = '<div class="preview-content" id="preview-content">' + errorContent + '</div>';
                        }}
                    }}
                }})
                .catch(function(error) {{
                    console.error('转换失败:', error);
                    const errorContent = '<div style="color: red; padding: 20px;"><h3>网络错误</h3><p>无法连接到转换服务</p></div>';
                    const previewContent = document.getElementById('preview-content');
                    if (previewContent) {{
                        previewContent.innerHTML = errorContent;
                    }} else {{
                        document.getElementById('preview-area').innerHTML = '<div class="preview-content" id="preview-content">' + errorContent + '</div>';
                    }}
                }});
            }}, 300);
        }}
        
        function updateStats(text) {{
            const charCount = text.length;
            const wordCount = text.trim() ? text.trim().split(/\\s+/).length : 0;
            const lineCount = text.split('\\n').length;
            
            document.getElementById('char-count').textContent = '字符: ' + charCount;
            document.getElementById('word-count').textContent = '单词: ' + wordCount;
            document.getElementById('line-count').textContent = '行数: ' + lineCount;
            document.getElementById('last-update').textContent = '最后更新: ' + new Date().toLocaleTimeString();
        }}
        
        function formatBytes(bytes) {{
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }}
        
        function copyHtml() {{
            if (currentHtml) {{
                navigator.clipboard.writeText(currentHtml).then(function() {{
                    alert('HTML已复制到剪贴板！');
                }}).catch(function(err) {{
                    console.error('复制失败:', err);
                    alert('复制失败，请手动复制');
                }});
            }} else {{
                alert('没有可复制的HTML内容');
            }}
        }}
        
        function downloadHtml() {{
            if (currentHtml) {{
                const blob = new Blob([currentHtml], {{ type: 'text/html' }});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'markdown-' + Date.now() + '.html';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }} else {{
                alert('没有可下载的HTML内容');
            }}
        }}
        
        function previewInNewWindow() {{
            if (!currentHtml) {{
                alert('没有可预览的HTML内容');
                return;
            }}
            
            const previewWindow = window.open('', '_blank');
            previewWindow.document.write(currentHtml);
            previewWindow.document.close();
            previewWindow.document.title = 'HTML预览 - ' + new Date().toLocaleTimeString();
        }}
        
        function forceReconvert() {{
            updatePreview();
        }}
        
        document.addEventListener('DOMContentLoaded', function() {{
            // 设置默认主题
            const themeMapping = {{
                "GitHub风格": "github",
                "深色主题": "dark", 
                "简约风格": "minimal",
                "学术风格": "academic",
                "典雅风格": "elegant"
            }};
            const defaultThemeCode = themeMapping["{params.default_theme}"] || 'github';
            document.getElementById('style-theme').value = defaultThemeCode;
            updatePreview();
        }});
    '''

    return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>阅读模式</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; }}
        .container {{ max-width: 1600px; margin: 0 auto; padding: 20px; }}
        .header {{ text-align: center; margin-bottom: 15px; }}
        .header h1 {{ color: #2c3e50; margin-bottom: 5px; font-size: 2em; }}
        .header p {{ color: #7f8c8d; font-size: 1em; }}
        
        /* 选项面板 */
        .options-panel {{ 
            background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); 
            margin-bottom: 15px; padding: 15px; position: relative;
        }}
        
        .options-row {{ 
            display: flex; gap: 10px; align-items: center; flex-wrap: wrap; justify-content: center;
        }}
        
        .option-button {{ 
            background: linear-gradient(135deg, #6c7ae0, #7c6ce0); color: white; border: none; 
            border-radius: 8px; padding: 10px 16px; cursor: pointer; font-size: 14px; font-weight: 500;
            transition: all 0.2s; position: relative;
        }}
        
        .option-button:hover {{ transform: translateY(-2px); box-shadow: 0 4px 15px rgba(108, 122, 224, 0.3); }}
        
        .floating-panel {{ 
            display: none; position: absolute; top: 60px; left: 50%; transform: translateX(-50%);
            background: white; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.15); 
            padding: 20px; z-index: 1000; min-width: 300px; max-width: 400px;
        }}
        
        .panel-title {{ 
            font-weight: 600; color: #2c3e50; margin-bottom: 15px; font-size: 1.1em; 
            border-bottom: 2px solid #eee; padding-bottom: 8px; 
        }}
        
        .panel-item {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
        .panel-item:last-child {{ margin-bottom: 0; }}
        .panel-item input[type="checkbox"] {{ transform: scale(1.2); accent-color: #6c7ae0; }}
        .panel-item label {{ font-size: 14px; color: #495057; cursor: pointer; user-select: none; }}
        .panel-item select {{ padding: 8px 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 14px; }}
        .panel-item input[type="number"] {{ padding: 8px 10px; border: 1px solid #ddd; border-radius: 5px; width: 80px; }}
        
        /* 主内容区域 */
        .main-content {{ display: flex; gap: 20px; height: calc(100vh - 200px); min-height: 700px; }}
        
        .input-panel, .output-panel {{ 
            flex: 1; background: white; border-radius: 12px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.08); display: flex; flex-direction: column; 
        }}
        
        /* 面板头部 */
        .panel-header {{ 
            padding: 15px 20px; border-bottom: 2px solid #e9ecef; background: #f8f9fa; 
            border-radius: 12px 12px 0 0; display: flex; justify-content: space-between; align-items: center;
        }}
        
        .panel-title-text {{ font-weight: 600; color: #2c3e50; font-size: 1.1em; margin: 0; }}
        .panel-buttons {{ display: flex; gap: 8px; align-items: center; }}
        
        .panel-btn {{ 
            padding: 6px 12px; border: none; border-radius: 6px; cursor: pointer; 
            font-size: 12px; font-weight: 500; transition: all 0.2s; outline: none;
        }}
        
        .btn-primary {{ background: linear-gradient(135deg, #007bff, #0056b3); color: white; }}
        .btn-success {{ background: linear-gradient(135deg, #28a745, #1e7e34); color: white; }}
        .btn-warning {{ background: linear-gradient(135deg, #ffc107, #e0a800); color: #212529; }}
        .btn-secondary {{ background: #6c757d; color: white; }}
        .btn-info {{ background: linear-gradient(135deg, #17a2b8, #138496); color: white; }}
        .btn-danger {{ background: linear-gradient(135deg, #dc3545, #c82333); color: white; }}
        
        .panel-btn:hover {{ transform: translateY(-1px); box-shadow: 0 3px 8px rgba(0,0,0,0.15); }}
        
        .panel-content {{ flex: 1; padding: 0; }}
        
        textarea {{ 
            width: 100%; height: 100%; border: none; padding: 20px; 
            font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace; 
            font-size: 14px; resize: none; outline: none; line-height: 1.6; 
        }}
        
        .preview-area {{ width: 100%; height: 100%; padding: 20px; overflow-y: auto; background: white; }}
        
        .stats {{ 
            padding: 10px 20px; background: #f8f9fa; border-top: 1px solid #e9ecef; 
            font-size: 12px; color: #6c757d; display: flex; justify-content: space-between; 
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="options-panel">
                    <div class="panel-buttons">
                        <button class="option-button" onclick="showOptionsPanel('theme-panel')">🎨 主题设置</button>
                <!--<button class="option-button" onclick="showOptionsPanel('basic-panel')">🔧 基础扩展</button>-->
                <button class="option-button" onclick="showOptionsPanel('code-panel')">💻 代码高亮</button>
                <!--<button class="option-button" onclick="showOptionsPanel('advanced-panel')">🚀 高级功能</button>-->
                <!--<button class="option-button" onclick="showOptionsPanel('other-panel')">⚙️ 其他选项</button>-->
                        <!--<button class="panel-btn btn-info" onclick="forceReconvert()">🔄 重新转换</button>-->
                        <!--<button class="panel-btn btn-primary" onclick="copyHtml()">📋 复制</button>-->
                        <!--<button class="panel-btn btn-success" onclick="downloadHtml()">💾 下载</button>-->
                        <button class="panel-btn btn-secondary" onclick="previewInNewWindow()">👁️ 沉浸式</button>
                    </div>
            <!-- 浮动面板 -->
            <div id="theme-panel" class="floating-panel">
                <div class="panel-title">🎨 主题设置</div>
                <div class="panel-item">
                    <label for="style-theme">样式主题：</label>
                    <select id="style-theme" onchange="updatePreview()">
                        <option value="github">GitHub风格</option>
                        <option value="dark">深色主题</option>
                        <option value="minimal">简约风格</option>
                        <option value="academic">学术风格</option>
                        <option value="elegant">典雅风格</option>
                    </select>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="full-page" checked onchange="updatePreview()">
                    <label for="full-page">生成完整HTML页面</label>
                </div>
                <div class="panel-item">
                    <label for="tab-length">制表符长度：</label>
                    <input type="number" id="tab-length" value="4" min="1" max="8" onchange="updatePreview()">
                </div>
            </div>
            
            <div id="basic-panel" class="floating-panel">
                <div class="panel-title">🔧 基础扩展</div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-tables" checked onchange="updatePreview()">
                    <label for="enable-tables">表格支持</label>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-fenced-code" checked onchange="updatePreview()">
                    <label for="enable-fenced-code">围栏代码块</label>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-sane-lists" checked onchange="updatePreview()">
                    <label for="enable-sane-lists">智能列表处理</label>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-footnotes" checked onchange="updatePreview()">
                    <label for="enable-footnotes">脚注支持</label>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-attr-list" checked onchange="updatePreview()">
                    <label for="enable-attr-list">属性列表</label>
                </div>
            </div>
            
            <div id="code-panel" class="floating-panel">
                <div class="panel-title">💻 代码高亮</div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-code-highlight" checked onchange="updatePreview()">
                    <label for="enable-code-highlight">启用代码高亮</label>
                </div>
                <div class="panel-item">
                    <label for="pygments-style">高亮样式：</label>
                    <select id="pygments-style" onchange="updatePreview()">
                        <option value="default">默认</option>
                        <option value="github">GitHub</option>
                        <option value="monokai">Monokai</option>
                        <option value="vs">Visual Studio</option>
                        <option value="colorful">彩色</option>
                        <option value="autumn">秋天</option>
                    </select>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-superfences" checked onchange="updatePreview()">
                    <label for="enable-superfences">超级围栏(图表支持)</label>
                </div>
            </div>
            
            <div id="advanced-panel" class="floating-panel">
                <div class="panel-title">🚀 高级功能</div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-toc" checked onchange="updatePreview()">
                    <label for="enable-toc">目录生成</label>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-tasklist" checked onchange="updatePreview()">
                    <label for="enable-tasklist">任务列表</label>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-admonition" checked onchange="updatePreview()">
                    <label for="enable-admonition">警告框</label>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-magiclink" checked onchange="updatePreview()">
                    <label for="enable-magiclink">智能链接</label>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-emoji" checked onchange="updatePreview()">
                    <label for="enable-emoji">表情符号</label>
                </div>
            </div>
            
            <div id="other-panel" class="floating-panel">
                <div class="panel-title">⚙️ 其他选项</div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-meta" checked onchange="updatePreview()">
                    <label for="enable-meta">元数据支持</label>
                </div>
                <div class="panel-item">
                    <input type="checkbox" id="enable-nl2br" checked onchange="updatePreview()">
                    <label for="enable-nl2br">换行转换</label>
                </div>
            </div>
        </div>

        <div class="main-content">
            <div class="input-panel" style="display: None">
                <div class="panel-header">
                    <span class="panel-title-text">📝 Markdown格式原文</span>
                    <div class="panel-buttons">
                    </div>
                </div>
                <div class="panel-content">
                    <textarea id="markdown-input" placeholder="在此输入您的Markdown内容..." oninput="updatePreview()">{your_content}</textarea>
                </div>
                <div class="stats">
                    <div>
                        <span id="char-count">字符: 0</span> |
                        <span id="word-count">单词: 0</span> |
                        <span id="line-count">行数: 0</span>
                    </div>
                    <div id="last-update">最后更新: --</div>
                </div>
            </div>
            
            <div class="output-panel">
                <div class="panel-content">
                    <div id="preview-area" class="preview-area">
                        <div id="preview-content" class="preview-content">
                            <div style="text-align: center; color: #999; padding: 50px;"><h1>正在加载中...请稍候</h1></div>
                        </div>
                    </div>
                </div>
                <div class="stats">
                    <div><span id="html-size">HTML大小: 0 字节</span></div>
                    <div><span id="conversion-time">转换耗时: 0ms</span></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        {js_code}
    </script>
</body>
</html>'''


def start_server(port=12001):
    """启动HTTP服务器"""
    try:
        server = HTTPServer(('localhost', port), MarkdownHandler)
        print(f"🚀 Markdown转HTML服务器已启动")
        print(f"📡 已代理端口: {port},可通过 /kuaiMD 访问")
        print(f"🎨 默认主题: {params.default_theme}")
        server.serve_forever()

    except KeyboardInterrupt:
        print("\n🛑 服务器已停止")
    except Exception as e:
        print(f"❌ 服务器启动失败: {e}")


if __name__ == "__main__":
    start_server()
