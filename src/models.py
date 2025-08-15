from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(),
                           onupdate=db.func.current_timestamp())
    profile_picture = db.Column(db.String(255))
    bio = db.Column(db.Text)
    register_ip = db.Column(db.String(45), nullable=False)

    # 关系定义
    media = db.relationship('Media', back_populates='user', lazy=True)
    comments = db.relationship('Comment', back_populates='author', lazy='dynamic')
    articles = db.relationship('Article', back_populates='author', lazy='dynamic')
    notifications = db.relationship('Notification', back_populates='user', lazy='dynamic')
    custom_fields = db.relationship('CustomField', back_populates='user', lazy='dynamic')
    email_subscription = db.relationship('EmailSubscription', back_populates='user', uselist=False)
    reports = db.relationship('Report', back_populates='reporter', lazy='dynamic')
    urls = db.relationship('Url', back_populates='user', lazy='dynamic')

    # 订阅关系
    subscriptions = db.relationship('UserSubscription', foreign_keys='UserSubscription.subscriber_id',
                                    back_populates='subscriber', lazy='dynamic')
    subscribers = db.relationship('UserSubscription', foreign_keys='UserSubscription.subscribed_user_id',
                                  back_populates='subscribed_user', lazy='dynamic')
    category_subscriptions = db.relationship('CategorySubscription', back_populates='subscriber', lazy='dynamic')

    # 角色关系
    roles = db.relationship('Role', secondary='user_roles', back_populates='users')


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=False)

    # 关系定义
    users = db.relationship('User', secondary='user_roles', back_populates='roles')
    permissions = db.relationship('Permission', secondary='role_permissions', back_populates='roles')


class Permission(db.Model):
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=False)

    # 关系定义
    roles = db.relationship('Role', secondary='role_permissions', back_populates='permissions')


class UserRole(db.Model):
    __tablename__ = 'user_roles'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), primary_key=True)

    __table_args__ = (
        db.Index('idx_role_id', 'role_id'),
    )


class RolePermission(db.Model):
    __tablename__ = 'role_permissions'
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id'), primary_key=True)

    __table_args__ = (
        db.Index('permission_id', 'permission_id'),
    )


class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(db.Integer, db.ForeignKey('articles.article_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=True, default=None)
    content = db.Column(db.Text, nullable=False)
    ip = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(),
                           onupdate=db.func.current_timestamp())

    # 关系定义
    author = db.relationship('User', back_populates='comments')
    article = db.relationship('Article', back_populates='comments')
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]),
                              lazy='dynamic', cascade='all, delete-orphan')

    __table_args__ = (
        db.Index('idx_article_created', 'article_id', 'created_at'),
        db.Index('idx_parent_created', 'parent_id', 'created_at'),
        db.Index('user_id', 'user_id'),
    )


class FileHash(db.Model):
    __tablename__ = 'file_hashes'
    id = db.Column(db.BigInteger, primary_key=True)
    hash = db.Column(db.String(64), nullable=False, unique=True)
    filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    reference_count = db.Column(db.Integer, default=1)
    file_size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    storage_path = db.Column(db.String(512), nullable=False)

    media = db.relationship('Media', back_populates='file_hash')


class Media(db.Model):
    __tablename__ = 'media'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(),
                           onupdate=db.func.current_timestamp())
    hash = db.Column(db.String(64), db.ForeignKey('file_hashes.hash'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)

    user = db.relationship('User', back_populates='media')
    file_hash = db.relationship('FileHash', back_populates='media')


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # 关系定义
    subscriptions = db.relationship('CategorySubscription', back_populates='category', lazy='dynamic')


class CategorySubscription(db.Model):
    __tablename__ = 'category_subscriptions'
    id = db.Column(db.Integer, primary_key=True)
    subscriber_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    # 关系定义
    subscriber = db.relationship('User', back_populates='category_subscriptions')
    category = db.relationship('Category', back_populates='subscriptions')

    __table_args__ = (
        db.Index('idx_subscriber', 'subscriber_id'),
        db.Index('idx_category', 'category_id'),
    )


class Article(db.Model):
    __tablename__ = 'articles'
    article_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    hidden = db.Column(db.Boolean, default=False, nullable=False)
    views = db.Column(db.BigInteger, default=0, nullable=False)
    likes = db.Column(db.BigInteger, default=0, nullable=False)
    status = db.Column(db.Enum('Draft', 'Published', 'Deleted'), default='Draft')
    cover_image = db.Column(db.String(255))
    article_type = db.Column(db.String(50))
    excerpt = db.Column(db.Text)
    is_featured = db.Column(db.Boolean, default=False)
    tags = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # 关系定义
    author = db.relationship('User', back_populates='articles')
    comments = db.relationship('Comment', back_populates='article', lazy=True)
    i18n_versions = db.relationship('ArticleI18n', backref='article', lazy=True)
    content = db.relationship('ArticleContent', backref='article', uselist=False)

    __table_args__ = (
        db.Index('idx_views', 'views'),
        db.UniqueConstraint('user_id', 'title', name='idx_user_title_unique'),
    )

    @property
    def comment_count(self):
        return db.session.query(Comment).filter(Comment.article_id == self.article_id).count()


class ArticleContent(db.Model):
    __tablename__ = 'article_content'
    aid = db.Column(db.Integer, db.ForeignKey('articles.article_id'), primary_key=True)
    passwd = db.Column(db.String(128))
    content = db.Column(db.Text)
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    language_code = db.Column(db.String(10), default='zh-CN', nullable=False)


class ArticleI18n(db.Model):
    __tablename__ = 'article_i18n'
    i18n_id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(db.Integer, db.ForeignKey('articles.article_id'), nullable=False)
    language_code = db.Column(db.String(10), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    excerpt = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('article_id', 'language_code', name='uq_article_language'),
        db.UniqueConstraint('article_id', 'language_code', 'slug', name='idx_article_lang_slug'),
    )


class CustomField(db.Model):
    __tablename__ = 'custom_fields'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    field_name = db.Column(db.String(100), nullable=False)
    field_value = db.Column(db.Text, nullable=False)

    # 关系定义
    user = db.relationship('User', back_populates='custom_fields')

    __table_args__ = (
        db.Index('idx_user_id', 'user_id'),
    )


class EmailSubscription(db.Model):
    __tablename__ = 'email_subscriptions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    subscribed = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    # 关系定义
    user = db.relationship('User', back_populates='email_subscription')

    __table_args__ = (
        db.Index('idx_user_id', 'user_id'),
    )


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(),
                           onupdate=db.func.current_timestamp())

    # 关系定义
    user = db.relationship('User', back_populates='notifications')

    __table_args__ = (
        db.Index('idx_user_id', 'user_id'),
    )


class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    reported_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_type = db.Column(db.Enum('Article', 'Comment'), nullable=False)
    content_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    # 关系定义
    reporter = db.relationship('User', back_populates='reports')

    __table_args__ = (
        db.Index('idx_reported_by', 'reported_by'),
    )


class Url(db.Model):
    __tablename__ = 'urls'
    id = db.Column(db.Integer, primary_key=True)
    long_url = db.Column(db.String(255), nullable=False)
    short_url = db.Column(db.String(10), nullable=False, unique=True)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # 关系定义
    user = db.relationship('User', back_populates='urls')


class UserSubscription(db.Model):
    __tablename__ = 'user_subscriptions'
    id = db.Column(db.Integer, primary_key=True)
    subscriber_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subscribed_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    # 关系定义
    subscriber = db.relationship('User', foreign_keys=[subscriber_id], back_populates='subscriptions')
    subscribed_user = db.relationship('User', foreign_keys=[subscribed_user_id], back_populates='subscribers')

    __table_args__ = (
        db.Index('idx_subscriber', 'subscriber_id'),
        db.Index('idx_subscribed_user', 'subscribed_user_id'),
    )
