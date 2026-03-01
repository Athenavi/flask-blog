"""
配置管理器，用于动态更新和刷新系统配置
"""
import json
from typing import Dict, Any

from flask import current_app
from flask_mail import Mail

from src.extensions import db
from src.models import SystemSettings
from src.utils.storage.s3_storage import s3_storage


class ConfigManager:
    def __init__(self):
        self.mail = Mail()
        self.s3_storage = s3_storage

    def load_config_from_db(self) -> Dict[str, Any]:
        """从数据库加载配置"""
        settings = db.session.query(SystemSettings).all()
        config = {}
        for setting in settings:
            if setting.value is None:
                config[setting.key] = None
            else:
                try:
                    # 尝试将值反序列化为JSON对象
                    config[setting.key] = json.loads(setting.value)
                except (json.JSONDecodeError, TypeError):
                    # 如果不是JSON格式，则直接使用原始值
                    config[setting.key] = setting.value
        return config

    def refresh_mail_config(self, app=None):
        """刷新邮件配置"""
        if app is None:
            try:
                # 检查是否在应用上下文中
                if not current_app:
                    print("错误: 无法在应用上下文外刷新邮件配置")
                    return
                app = current_app
            except RuntimeError:
                # 如果不在应用上下文中，返回而不执行操作
                print("错误: 当前不在应用上下文中，无法刷新邮件配置")
                return

        # 从数据库加载邮件配置
        config = self.load_config_from_db()

        # 获取邮件配置
        mail_host = config.get('mail_host', app.config.get('MAIL_HOST'))
        mail_port = config.get('mail_port', app.config.get('MAIL_PORT'))
        mail_user = config.get('mail_user', app.config.get('MAIL_USERNAME'))
        mail_password = config.get('mail_password', app.config.get('MAIL_PASSWORD'))

        # 更新应用配置
        if mail_host:
            app.config['MAIL_SERVER'] = mail_host
        if mail_port:
            app.config['MAIL_PORT'] = int(mail_port)
        if mail_user:
            app.config['MAIL_USERNAME'] = mail_user
        if mail_password:
            app.config['MAIL_PASSWORD'] = mail_password

        # 使用STARTTLS而不是SSL
        app.config['MAIL_USE_TLS'] = True
        app.config['MAIL_USE_SSL'] = False
        app.config['MAIL_DEFAULT_SENDER'] = mail_user

        # 重新初始化邮件扩展
        try:
            # 从app.extensions中移除旧的mail实例
            if 'mail' in app.extensions:
                del app.extensions['mail']
            self.mail.init_app(app)
            print("邮件配置已刷新")
        except Exception as e:
            print(f"邮件配置刷新失败: {e}")

    def refresh_s3_config(self, app=None):
        """刷新S3配置"""
        if app is None:
            try:
                # 检查是否在应用上下文中
                if not current_app:
                    print("错误: 无法在应用上下文外刷新S3配置")
                    return
                app = current_app
            except RuntimeError:
                # 如果不在应用上下文中，返回而不执行操作
                print("错误: 当前不在应用上下文中，无法刷新S3配置")
                return

        try:
            config = self.load_config_from_db()

            # 获取S3配置
            s3_enabled = config.get('s3_enabled', True)
            s3_endpoint = config.get('s3_endpoint', app.config.get('S3_ENDPOINT_URL'))
            s3_access_key = config.get('s3_access_key', app.config.get('S3_ACCESS_KEY'))
            s3_secret_key = config.get('s3_secret_key', app.config.get('S3_SECRET_KEY'))
            s3_bucket_name = config.get('s3_bucket', app.config.get('S3_BUCKET_NAME', 'media-bucket'))
            s3_region = config.get('s3_region', app.config.get('S3_REGION', 'us-east-1'))
            s3_use_ssl = config.get('s3_use_ssl', app.config.get('S3_USE_SSL', True))

            # 更新应用配置
            app.config['S3_ENABLED'] = s3_enabled
            if s3_endpoint:
                app.config['S3_ENDPOINT_URL'] = s3_endpoint
            if s3_access_key:
                app.config['S3_ACCESS_KEY'] = s3_access_key
            if s3_secret_key:
                app.config['S3_SECRET_KEY'] = s3_secret_key
            app.config['S3_BUCKET_NAME'] = s3_bucket_name
            app.config['S3_REGION'] = s3_region
            app.config['S3_USE_SSL'] = s3_use_ssl

            # 重新初始化S3存储
            self.s3_storage.init_app(app)
            print("S3配置已刷新")
        except Exception as e:
            print(f"S3配置刷新失败: {e}")

    def refresh_all_configs(self, app=None):
        """刷新所有配置"""
        print("开始刷新所有配置...")
        if app is None:
            try:
                # 检查是否在应用上下文中
                if not current_app:
                    print("错误: 无法在应用上下文外刷新配置")
                    return
                app = current_app
            except RuntimeError:
                # 如果不在应用上下文中，返回而不执行操作
                print("错误: 当前不在应用上下文中，无法刷新配置")
                return
        
        self.refresh_mail_config(app)
        self.refresh_s3_config(app)
        print("所有配置已刷新完成")


# 创建全局配置管理器实例
config_manager = ConfigManager()