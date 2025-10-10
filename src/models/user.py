from sqlalchemy.sql.functions import current_timestamp

from . import db


class User(db.Model):
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
    vip_expires_at = db.Column(db.DateTime)  # VIP过期时间

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

    oauth_connections = db.relationship('OAuthConnection', back_populates='user', lazy='dynamic',
                                        cascade='all, delete')
    vip_subscriptions = db.relationship('VIPSubscription', back_populates='user',
                                        lazy='dynamic', cascade='all, delete')

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


class OAuthConnection(db.Model):
    __tablename__ = 'oauth_connections'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    provider = db.Column(db.String(50), nullable=False, doc='第三方平台名称')
    provider_user_id = db.Column(db.String(255), nullable=False, doc='第三方平台用户ID')
    access_token = db.Column(db.String(512), doc='访问令牌')
    refresh_token = db.Column(db.String(512), doc='刷新令牌')
    expires_at = db.Column(db.DateTime)

    user = db.relationship('User', back_populates='oauth_connections')

    __table_args__ = (
        db.UniqueConstraint('provider', 'provider_user_id'),
        db.Index('idx_oauth_user', 'user_id', 'provider')
    )


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
