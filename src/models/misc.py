from sqlalchemy.orm import relationship

from . import db


class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_date = db.Column(db.TIMESTAMP, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'event_date': self.event_date.isoformat() if self.event_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    reported_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 报告者ID
    target_type = db.Column(db.String(50), nullable=False)  # 目标类型 (e.g., 'article', 'comment', 'user')
    target_id = db.Column(db.Integer, nullable=False)  # 目标ID
    reason = db.Column(db.String(255), nullable=False)  # 报告原因
    description = db.Column(db.Text)  # 详细描述
    status = db.Column(db.String(20), default='pending')  # 状态: pending, reviewed, resolved
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    # 关系
    user = relationship("User", back_populates="reports")

    def to_dict(self):
        return {
            'id': self.id,
            'reported_by': self.reported_by,
            'target_type': self.target_type,
            'target_id': self.target_id,
            'reason': self.reason,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Url(db.Model):
    __tablename__ = 'urls'
    id = db.Column(db.Integer, primary_key=True)
    long_url = db.Column(db.String(255), nullable=False)
    short_url = db.Column(db.String(10), nullable=False, unique=True)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # 关系定义
    user = db.relationship('User', back_populates='urls')

    __table_args__ = (
        db.Index('idx_user_id_url', 'user_id'),
        db.UniqueConstraint('user_id', 'long_url', name='uq_user_long_url')
    )

    def to_dict(self):
        return {
            'id': self.id,
            'long_url': self.long_url,
            'short_url': self.short_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'user_id': self.user_id
        }


class SearchHistory(db.Model):
    __tablename__ = 'search_history'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, nullable=False)
    keyword = db.Column(db.String(255), nullable=False)
    results_count = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'keyword': self.keyword,
            'results_count': self.results_count,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class PageView(db.Model):
    __tablename__ = 'page_views'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, nullable=True)  # 可选的用户ID，未登录用户为NULL
    session_id = db.Column(db.String(255), nullable=True)  # 会话ID，用于追踪未登录用户
    page_url = db.Column(db.String(500), nullable=False)  # 访问的页面URL
    page_title = db.Column(db.String(500), nullable=True)  # 页面标题
    referrer = db.Column(db.String(500), nullable=True)  # 来源页面
    user_agent = db.Column(db.String(500), nullable=True)  # 用户代理
    ip_address = db.Column(db.String(45), nullable=True)  # IP地址（支持IPv6）
    device_type = db.Column(db.String(50), nullable=True)  # 设备类型
    browser = db.Column(db.String(100), nullable=True)  # 浏览器类型
    platform = db.Column(db.String(100), nullable=True)  # 操作系统平台
    country = db.Column(db.String(100), nullable=True)  # 国家
    city = db.Column(db.String(100), nullable=True)  # 城市
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())  # 访问时间

    # 为常用查询创建索引
    __table_args__ = (
        db.Index('idx_page_views_user_id', 'user_id'),
        db.Index('idx_page_views_page_url', 'page_url'),
        db.Index('idx_page_views_created_at', 'created_at'),
        db.Index('idx_page_views_session_id', 'session_id'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'page_url': self.page_url,
            'page_title': self.page_title,
            'referrer': self.referrer,
            'user_agent': self.user_agent,
            'ip_address': self.ip_address,
            'device_type': self.device_type,
            'browser': self.browser,
            'platform': self.platform,
            'country': self.country,
            'city': self.city,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class UserActivity(db.Model):
    __tablename__ = 'user_activities'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 用户ID
    activity_type = db.Column(db.String(100), nullable=False)  # 活动类型 (e.g., 'view', 'like', 'comment', 'share')
    target_type = db.Column(db.String(50), nullable=False)  # 目标类型 (e.g., 'article', 'comment')
    target_id = db.Column(db.Integer, nullable=False)  # 目标ID
    details = db.Column(db.Text)  # 活动详细信息
    ip_address = db.Column(db.String(45), nullable=True)  # IP地址
    user_agent = db.Column(db.String(500), nullable=True)  # 用户代理
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())  # 活动时间

    # 关系
    user = relationship("User", back_populates="activities")

    # 为常用查询创建索引
    __table_args__ = (
        db.Index('idx_user_activities_user_id', 'user_id'),
        db.Index('idx_user_activities_type', 'activity_type'),
        db.Index('idx_user_activities_target', 'target_type', 'target_id'),
        db.Index('idx_user_activities_created_at', 'created_at'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'activity_type': self.activity_type,
            'target_type': self.target_type,
            'target_id': self.target_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
