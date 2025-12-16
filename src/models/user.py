from datetime import datetime

import bcrypt
from flask_login import UserMixin
from sqlalchemy.sql.functions import current_timestamp

from . import db
from .userSession import UserSession


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, doc='用户ID')
    username = db.Column(db.String(255), nullable=False, unique=True, doc='用户名')
    password = db.Column(db.String(255), nullable=False, doc='密码')
    email = db.Column(db.String(255), nullable=False, unique=True, doc='邮箱')
    created_at = db.Column(db.TIMESTAMP, server_default=current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=current_timestamp(), onupdate=current_timestamp())
    profile_picture = db.Column(db.String(255), doc='头像')
    bio = db.Column(db.Text, doc='个人简介')
    register_ip = db.Column(db.String(45), nullable=False, doc='注册IP')
    is_2fa_enabled = db.Column(db.Boolean, default=False, doc='是否启用双因子认证')
    totp_secret = db.Column(db.String(32), doc='双因子认证密钥')
    backup_codes = db.Column(db.Text, doc='备用验证码')
    profile_private = db.Column(db.Boolean, default=False, doc='是否私密资料')
    vip_level = db.Column(db.Integer, default=0)  # VIP等级，0表示非VIP
    vip_expires_at = db.Column(db.TIMESTAMP)  # VIP过期时间
    last_login_at = db.Column(db.TIMESTAMP, doc='上次登录时间')
    last_login_ip = db.Column(db.String(45), doc='上次登录IP')
    locale = db.Column(db.String(10), default='zh_CN', doc='语言')

    # 关系定义
    media = db.relationship('Media', back_populates='user', lazy=True, cascade='all, delete')
    comments = db.relationship('Comment', back_populates='author', lazy='dynamic', cascade='all, delete')
    articles = db.relationship('Article', back_populates='author', lazy='dynamic', cascade='all, delete')
    notifications = db.relationship('Notification', back_populates='user', lazy='dynamic', cascade='all, delete')
    custom_fields = db.relationship('CustomField', back_populates='user', lazy='dynamic', cascade='all, delete')
    email_subscription = db.relationship('EmailSubscription', back_populates='user', uselist=False,
                                         cascade='all, delete')
    reports = db.relationship('Report', back_populates='reporter', lazy='dynamic', cascade='all, delete')
    urls = db.relationship('Url', back_populates='user', lazy='dynamic', cascade='all, delete')

    # 订阅关系
    subscriptions = db.relationship('UserSubscription', foreign_keys='UserSubscription.subscriber_id',
                                    back_populates='subscriber', lazy='dynamic', cascade='all, delete')
    subscribers = db.relationship('UserSubscription', foreign_keys='UserSubscription.subscribed_user_id',
                                  back_populates='subscribed_user', lazy='dynamic', cascade='all, delete')
    category_subscriptions = db.relationship('CategorySubscription', back_populates='subscriber', lazy='dynamic',
                                             cascade='all, delete')

    # 角色关系
    roles = db.relationship('Role', secondary='user_roles', back_populates='users', cascade='all')

    social_profiles = db.relationship('SocialAccount', backref='user_profile', overlaps="social_accounts")
    vip_subscriptions = db.relationship('VIPSubscription', back_populates='user',
                                        lazy='dynamic', cascade='all, delete')

    # 用户会话关系
    sessions = db.relationship('UserSession', back_populates='user', lazy='dynamic', cascade='all, delete')

    def __repr__(self):
        return f'<User {self.username}>'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'profile_picture': self.profile_picture,
            'bio': self.bio,
            'vip_level': self.vip_level or 0,
            'is_vip': self.is_vip() or False,
            'vip_expires_at': self.vip_expires_at.isoformat() if self.vip_expires_at else None
        }

    def __init__(self, username, email, password, bio, locale, profile_private, register_ip):
        self.username = username
        self.email = email
        self.password = password
        self.bio = bio
        self.locale = locale
        self.profile_private = profile_private
        self.register_ip = register_ip

    def set_password(self, new_password):
        # 哈希新密码
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        self.password = hashed_password.decode('utf-8')
        # 更新密码
        return True

    def check_password(self, password):
        check_result = bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
        return check_result

    def is_vip(self):
        """检查用户是否为VIP"""
        if self.vip_level and self.vip_level > 0:
            if self.vip_expires_at and self.vip_expires_at > datetime.now():
                return True
        return False

    def has_role(self, role_name):
        """检查用户是否拥有指定角色"""
        return any(role.name == role_name for role in self.roles)

    def has_permission(self, permission_code):
        """检查用户是否拥有指定权限"""
        for role in self.roles:
            if any(perm.code == permission_code for perm in role.permissions):
                return True
        return False

    def get_all_permissions(self):
        """获取用户所有权限代码"""
        permissions = set()
        for role in self.roles:
            for perm in role.permissions:
                permissions.add(perm.code)
        return list(permissions)

    def get_current_session(self):
        """获取当前会话"""
        return UserSession.query.filter_by(user_id=self.id, is_current=True).first()

    def logout_session(self, session_id):
        """退出特定会话"""
        session = UserSession.query.filter_by(
            user_id=self.id,
            session_id=session_id
        ).first()

        if session:
            session.deactivate()
            return True
        return False

    def logout_all_other_sessions(self, exclude_session_id=None):
        """退出除当前会话外的所有其他会话"""
        query = UserSession.query.filter_by(
            user_id=self.id,
            is_active=True
        )

        if exclude_session_id:
            query = query.filter(UserSession.session_id != exclude_session_id)

        other_sessions = query.all()
        for session in other_sessions:
            session.deactivate()

        db.session.commit()
        return len(other_sessions)

    def get_active_sessions_count(self):
        """获取活跃会话数量"""
        return UserSession.query.filter_by(
            user_id=self.id,
            is_active=True
        ).filter(
            UserSession.expiry_time > datetime.now()
        ).count()


class CustomField(db.Model):
    __tablename__ = 'custom_fields'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    field_name = db.Column(db.String(100), nullable=False, unique=True)
    field_value = db.Column(db.Text, nullable=False, doc='自定义字段值')

    # 关系定义
    user = db.relationship('User', back_populates='custom_fields')

    __table_args__ = (
        db.Index('idx_user_id_cf', 'user_id'),
        db.UniqueConstraint('user_id', 'field_name', name='uq_user_custom_fields')
    )


class EmailSubscription(db.Model):
    __tablename__ = 'email_subscriptions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    subscribed = db.Column(db.Boolean, default=True, nullable=False, doc='是否订阅邮件')
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    # 关系定义
    user = db.relationship('User', back_populates='email_subscription')

    __table_args__ = (
        db.Index('idx_user_id_es', 'user_id'),
    )