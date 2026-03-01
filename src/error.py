import logging

from flask import render_template

logger = logging.getLogger(__name__)

def error(message, status_code):
    try:
        # 尝试渲染错误页面
        return render_template('inform.html', error=message, status_code=status_code), status_code
    except Exception as e:
        # 如果错误页面渲染失败，记录错误并返回简单响应
        logger.error(f"Error rendering error page: {str(e)}")

        # 返回简单的HTML错误页面，避免循环错误
        simple_error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error {status_code}</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>Error {status_code}</h1>
            <p>{message}</p>
        </body>
        </html>
        """
        return simple_error_html, status_code
