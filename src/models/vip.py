from datetime import datetime, timezone

from . import db


# vip_status = db.Enum('pending_payment：0', 'active：1', 'expired：-1', 'cancelled：-2', name='vip_status', create_type=True)


class VIPPlan(db.Model):
    """VIP套餐表"""
    __tablename__ = 'vip_plans'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # 套餐名称
    description = db.Column(db.Text)  # 套餐描述
    price = db.Column(db.Numeric(10, 2), nullable=False)  # 价格
    original_price = db.Column(db.Numeric(10, 2))  # 原价，用于显示折扣
    duration_days = db.Column(db.Integer, nullable=False)  # 有效期天数
    level = db.Column(db.Integer, default=1, nullable=False)  # VIP等级
    features = db.Column(db.Text)  # 特权功能JSON
    is_active = db.Column(db.Boolean, default=True)  # 是否激活
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<VIPPlan {self.name}>'


class VIPSubscription(db.Model):
    """VIP订阅记录表"""
    __tablename__ = 'vip_subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('vip_plans.id'), nullable=False)
    starts_at = db.Column(db.TIMESTAMP, nullable=False)  # 开始时间
    expires_at = db.Column(db.TIMESTAMP, nullable=False)  # 过期时间
    status = db.Column(db.Integer, default=0, nullable=False)
    payment_amount = db.Column(db.Numeric(10, 2))  # 实际支付金额
    transaction_id = db.Column(db.String(255))  # 支付交易ID
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))

    # 关系定义
    user = db.relationship('User', back_populates='vip_subscriptions')
    plan = db.relationship('VIPPlan')

    __table_args__ = (
        db.Index('idx_vip_subscriptions_user_id', 'user_id'),
        db.Index('idx_vip_subscriptions_expires_at', 'expires_at'),
        db.Index('idx_vip_subscriptions_transaction_id', 'transaction_id'),
        db.Index('idx_vip_subscriptions_status', 'status'),
    )

    def __repr__(self):
        return f'<VIPSubscription user_id={self.user_id} plan_id={self.plan_id}>'


class VIPFeature(db.Model):
    """VIP功能特权表"""
    __tablename__ = 'vip_features'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), nullable=False, unique=True)  # 功能代码
    name = db.Column(db.String(100), nullable=False)  # 功能名称
    description = db.Column(db.Text)  # 功能描述
    required_level = db.Column(db.Integer, default=1)  # 所需VIP等级
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<VIPFeature {self.name}>'