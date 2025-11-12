from . import db

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
    hidden = db.Column(db.Integer, nullable=False, default=0)

    # 关系定义
    author = db.relationship('User', back_populates='comments')
    article = db.relationship('Article', back_populates='comments')
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]),
                              lazy='dynamic', cascade='all, delete-orphan')

    __table_args__ = (
        db.Index('idx_comments_article_created', 'article_id', 'created_at'),
        db.Index('idx_comments_parent_created', 'parent_id', 'created_at'),
        db.Index('idx_comments_user_id', 'user_id'),
    )