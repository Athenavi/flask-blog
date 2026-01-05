"""
Dashboard Blueprint Package@admin_bp.
"""
from flask import Blueprint

# 创建主蓝图实例
admin_bp = Blueprint('admin', __name__, template_folder='templates', url_prefix='/admin')

# 导入所有子模块的路由
from . import (
    main,  # 主要的管理功能（用户、文章、分类等）
    settings,  # 系统设置相关
    media,  # 媒体管理
    backup,  # 备份功能
    misc,  # 杂项管理（事件、举报、短链接、搜索历史等）
    comment_config,  # 评论配置
    config_manager  # 配置管理
)
