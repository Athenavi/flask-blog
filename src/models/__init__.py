from flask_sqlalchemy import SQLAlchemy

# 创建共享的 db 实例
db = SQLAlchemy()

# 导入所有模型
from .user import User, OAuthConnection, CustomField, EmailSubscription
from .role import Role, Permission, UserRole, RolePermission
from .article import Article, ArticleContent, ArticleI18n
from .comment import Comment
from .media import Media, FileHash
from .category import Category, CategorySubscription
from .notification import Notification
from .subscription import UserSubscription
from .misc import Event, Report, Url
from .vip import VIPPlan, VIPSubscription, VIPFeature

__all__ = [
    'db',
    'User', 'OAuthConnection', 'CustomField', 'EmailSubscription',
    'Role', 'Permission', 'UserRole', 'RolePermission',
    'Article', 'ArticleContent', 'ArticleI18n',
    'Comment',
    'Media', 'FileHash',
    'Category', 'CategorySubscription',
    'Notification',
    'UserSubscription',
    'Event', 'Report', 'Url',
    'VIPPlan', 'VIPSubscription', 'VIPFeature'
]
