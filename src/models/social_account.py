from sqlalchemy.sql.functions import current_timestamp
from . import db


class SocialAccount(db.Model):
    """社交账号绑定模型"""
    __tablename__ = 'social_accounts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    provider = db.Column(db.String(50), nullable=False, doc='第三方平台名称')
    provider_uid = db.Column(db.String(255), nullable=False, doc='第三方平台用户ID')
    access_token = db.Column(db.String(512), doc='访问令牌')
    refresh_token = db.Column(db.String(512), doc='刷新令牌')
    expires_at = db.Column(db.DateTime, doc='令牌过期时间')
    created_at = db.Column(db.TIMESTAMP, server_default=current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=current_timestamp(), onupdate=current_timestamp())

    __table_args__ = (
        db.UniqueConstraint('provider', 'provider_uid', name='uq_provider_uid'),
        db.Index('idx_user_provider', 'user_id', 'provider'),
        db.Index('idx_provider_uid', 'provider', 'provider_uid')
    )

    def __repr__(self):
        return f'<SocialAccount {self.provider}:{self.provider_uid}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'provider': self.provider,
            'provider_uid': self.provider_uid,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
