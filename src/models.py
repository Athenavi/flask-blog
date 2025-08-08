from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    profile_picture = db.Column(db.String(255))
    bio = db.Column(db.Text)
    register_ip = db.Column(db.String(45), nullable=False)

    articles = db.relationship('Article', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))


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

    comments = db.relationship('Comment', backref='article', lazy=True)
    i18n_versions = db.relationship('ArticleI18n', backref='article', lazy=True)

    @property
    def comment_count(self):
        return len(self.comments)


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


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(db.Integer, db.ForeignKey('articles.article_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))


class FileHash(db.Model):
    __tablename__ = 'file_hashes'
    id = db.Column(db.BigInteger, primary_key=True)
    hash = db.Column(db.String(64), nullable=False, unique=True)
    filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    reference_count = db.Column(db.Integer, default=1)
    file_size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    storage_path = db.Column(db.String(255), nullable=False)