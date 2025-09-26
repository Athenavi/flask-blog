from datetime import datetime, timezone

from . import db

article_status = db.Enum('Draft', 'Published', 'Deleted', name='article_status', create_type=False)


class Article(db.Model):
    __tablename__ = 'articles'
    article_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    hidden = db.Column(db.Boolean, default=False, nullable=False)
    views = db.Column(db.BigInteger, default=0, nullable=False)
    likes = db.Column(db.BigInteger, default=0, nullable=False)
    status = db.Column(article_status, default='Draft')
    cover_image = db.Column(db.String(255))
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)
    excerpt = db.Column(db.Text)
    is_featured = db.Column(db.Boolean, default=False)
    tags = db.Column(db.String(255), nullable=False)
    article_ad = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # 关系定义
    author = db.relationship('User', back_populates='articles')
    comments = db.relationship('Comment', back_populates='article', cascade='all, delete-orphan')
    category = db.relationship('Category', back_populates='articles')

    def __repr__(self):
        return f'<Article {self.title}>'

    def to_dict(self):
        return {
            'article_id': self.article_id,
            'title': self.title,
            'slug': self.slug,
            'user_id': self.user_id,
            'hidden': self.hidden,
            'views': self.views,
            'likes': self.likes,
            'status': self.status,
            'cover_image': self.cover_image,
            'article_type': self.article_type,
            'excerpt': self.excerpt,
            'is_featured': self.is_featured,
            'tags': self.tags.split(',') if self.tags else [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


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
