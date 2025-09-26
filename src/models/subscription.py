from . import db

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
        db.Index('idx_user_subscriptions_subscriber', 'subscriber_id'),
        db.Index('idx_user_subscriptions_subscribed_user', 'subscribed_user_id'),
        db.UniqueConstraint('subscriber_id', 'subscribed_user_id', name='uq_user_subscriptions')
    )
