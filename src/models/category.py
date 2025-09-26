from datetime import datetime, timezone

from . import db


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # 关系定义
    subscriptions = db.relationship('CategorySubscription', back_populates='category', lazy='dynamic')
    articles = db.relationship('Article', back_populates='category', lazy='dynamic')


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
        db.Index('idx_category_subscriptions_subscriber', 'subscriber_id'),
        db.Index('idx_category_subscriptions_category', 'category_id'),
        db.UniqueConstraint('subscriber_id', 'category_id', name='uq_category_subscriptions')
    )
