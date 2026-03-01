"""
Vercel兼容的入口文件
用于在Vercel上部署Flask应用
"""
import os
from pathlib import Path

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

    # 设置安全密钥
    os.environ.setdefault('SECRET_KEY', os.environ.get('SECRET_KEY', 'your-vercel-secret-key'))

    # 邮件配置
    os.environ.setdefault('MAIL_SERVER', os.environ.get('MAIL_SERVER', 'smtp.gmail.com'))
    os.environ.setdefault('MAIL_PORT', os.environ.get('MAIL_PORT', '587'))
    os.environ.setdefault('MAIL_USE_TLS', os.environ.get('MAIL_USE_TLS', 'True'))
    os.environ.setdefault('MAIL_USERNAME', os.environ.get('MAIL_USERNAME', ''))
    os.environ.setdefault('MAIL_PASSWORD', os.environ.get('MAIL_PASSWORD', ''))

    # S3存储配置
    os.environ.setdefault('S3_ENABLED', os.environ.get('S3_ENABLED', 'True'))
    os.environ.setdefault('S3_ENDPOINT_URL', os.environ.get('S3_ENDPOINT_URL', ''))
    os.environ.setdefault('S3_ACCESS_KEY', os.environ.get('S3_ACCESS_KEY', ''))
    os.environ.setdefault('S3_SECRET_KEY', os.environ.get('S3_SECRET_KEY', ''))
    os.environ.setdefault('S3_BUCKET_NAME', os.environ.get('S3_BUCKET_NAME', 'media-bucket'))
    os.environ.setdefault('S3_REGION', os.environ.get('S3_REGION', 'us-east-1'))
    os.environ.setdefault('S3_USE_SSL', os.environ.get('S3_USE_SSL', 'True'))
    os.environ.setdefault('S3_SIGNATURE_VERSION', os.environ.get('S3_SIGNATURE_VERSION', 's3v4'))

# 在Vercel环境下，需要使用正确的静态文件路径
# 由于Vercel的文件系统限制，我们使用项目根目录下的static文件夹
base_dir = Path(__file__).parent
static_folder = base_dir / 'static'
templates_folder = base_dir / 'templates'


def create_app_with_conditional_imports():
    """条件导入以减少函数大小"""
    # 在函数内部导入，避免全局导入大库
    from src.app import create_app
    return create_app()


# 创建Flask应用实例（仅在首次调用时创建，利用Vercel的缓存机制）
if 'application' not in globals():
    application = create_app_with_conditional_imports()


# Vercel期望名为application的WSGI应用
application = application

if __name__ == "__main__":
    application.run(debug=True)
