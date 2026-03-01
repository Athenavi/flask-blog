"""
Dashboard 配置管理模块
包含邮件、Redis、S3等配置的管理功能
"""
import inspect
import json
from datetime import datetime

from flask import jsonify, render_template, request

from src.auth_utils import admin_required
from src.extensions import limiter
from src.models import User, db, SystemSettings
from src.utils.config_manager import config_manager
from . import admin_bp


@admin_bp.route('/config-manager', methods=['GET'])
@admin_required
@limiter.limit("10 per minute")
def admin_config_manager(user_id):
    """配置管理页面"""
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        # 获取系统设置
        system_settings = db.session.query(SystemSettings).all()
        settings_dict = {}
        for setting in system_settings:
            if setting.value is None:
                settings_dict[setting.key] = None
            else:
                try:
                    # 尝试将值反序列化为JSON对象
                    settings_dict[setting.key] = json.loads(setting.value)
                except (json.JSONDecodeError, TypeError):
                    # 如果不是JSON格式，则直接使用原始值
                    settings_dict[setting.key] = setting.value

        return render_template('dashboard/config_manager.html',
                               settings=settings_dict,
                               current_user=current_user)
    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/config-manager', methods=['POST'])
@admin_required
@limiter.limit("10 per minute")
def save_config_manager(user_id):
    """保存配置管理"""
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        # 获取POST数据
        settings_data = request.form.get('settings')
        if settings_data:
            settings = json.loads(settings_data)
            for key, value in settings.items():
                # 将值序列化为JSON字符串以存储到数据库
                # 处理 None、空字典和其他特殊值
                if value is None:
                    serialized_value = None
                elif isinstance(value, (dict, list)):
                    serialized_value = json.dumps(value, ensure_ascii=False)
                else:
                    serialized_value = str(value)
                setting = db.session.query(SystemSettings).filter_by(key=key).first()
                if setting:
                    setting.value = serialized_value
                    setting.updated_at = datetime.now()
                    setting.updated_by = user_id
                else:
                    setting = SystemSettings(
                        key=key,
                        value=serialized_value,
                        updated_at=datetime.now(),
                        updated_by=user_id
                    )
                    db.session.add(setting)
            db.session.commit()

            # 刷新配置（如果需要）
            config_keys = ['mail_host', 'mail_port', 'mail_user', 'mail_password',
                           'redis_host', 'redis_port', 'redis_password', 'redis_db',
                           's3_enabled', 's3_endpoint', 's3_access_key', 's3_secret_key',
                           's3_bucket', 's3_region', 's3_use_ssl']

            if any(key in config_keys for key in settings.keys()):
                try:
                    config_manager.refresh_all_configs()
                    print('配置已实时更新')
                except Exception as refresh_error:
                    print(f'配置刷新失败: {str(refresh_error)}')

        return jsonify({'success': True, 'message': '配置已保存'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'保存失败: {str(e)}'})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/refresh-config', methods=['POST'])
@admin_required
@limiter.limit("5 per minute")
def refresh_config(user_id):
    """刷新配置接口 - 用于在应用上下文中刷新配置"""
    try:
        from flask import current_app
        app = current_app

        # 调用配置管理器刷新所有配置
        config_manager.refresh_all_configs(app)
        return jsonify({'success': True, 'message': '配置刷新成功'})
    except Exception as e:
        print(f'配置刷新失败: {str(e)}')
        return jsonify({'success': False, 'message': f'配置刷新失败: {str(e)}'})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        print(f"==>{current_func_name}, User ID: {user_id}")
