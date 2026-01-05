"""
Vercel兼容的入口文件
用于在Vercel上部署Flask应用
"""
import os
from pathlib import Path

from src.app import create_app

# 设置环境变量以适应Vercel环境
if os.environ.get('VERCEL'):
    # 在Vercel环境中，使用环境变量或默认值
    os.environ.setdefault('DB_ENGINE', os.environ.get('DB_ENGINE', 'postgresql'))
    os.environ.setdefault('DB_HOST', os.environ.get('DB_HOST', 'localhost'))
    os.environ.setdefault('DB_PORT', os.environ.get('DB_PORT', '5432'))
    os.environ.setdefault('DB_NAME', os.environ.get('DB_NAME', 'flask_blog'))
    os.environ.setdefault('DB_USER', os.environ.get('DB_USER', 'fb_user'))
    os.environ.setdefault('DB_PASSWORD', os.environ.get('DB_PASSWORD', '123456'))
    os.environ.setdefault('DB_SSLMODE', os.environ.get('DB_SSLMODE', 'prefer'))
    os.environ.setdefault('FLASK_ENV', 'production')
    
    # 在Vercel环境中，使用临时目录存储上传文件
    temp_dir = '/tmp'
    os.environ.setdefault('TEMP_FOLDER', temp_dir)

# 在Vercel环境下，需要使用正确的静态文件路径
# 由于Vercel的文件系统限制，我们使用项目根目录下的static文件夹
base_dir = Path(__file__).parent
static_folder = base_dir / 'static'
templates_folder = base_dir / 'templates'

# 创建Flask应用实例
app = create_app()

# Vercel期望名为application的WSGI应用
application = app

if __name__ == "__main__":
    app.run(debug=True)