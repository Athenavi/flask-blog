import logging
from datetime import datetime

from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from src.extensions import db

logger = logging.getLogger(__name__)


class UserSession(db.Model):
    __tablename__ = 'user_sessions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    access_token = Column(String(512), unique=True, nullable=False)
    refresh_token = Column(String(512), unique=True, nullable=True)
    device_type = Column(String(50), nullable=True)
    browser = Column(String(100), nullable=True)
    platform = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)  # 支持IPv6
    location = Column(String(255), nullable=True)
    created_at = Column(db.TIMESTAMP, default=datetime.now, nullable=False)
    last_activity = Column(db.TIMESTAMP, default=datetime.now, nullable=False)
    expiry_time = Column(db.TIMESTAMP, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # 关联关系
    user = relationship("User", back_populates="sessions")

    def __repr__(self):
        return f"<UserSession(id={self.id}, user_id={self.user_id}, session_id='{self.session_id}')>"

    def to_dict(self):
        """将对象转换为字典"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'device_type': self.device_type,
            'browser': self.browser,
            'platform': self.platform,
            'ip_address': self.ip_address,
            'location': self.location,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'expiry_time': self.expiry_time.isoformat() if self.expiry_time else None,
            'is_active': self.is_active
        }

    def update_last_activity(self):
        """更新最后活动时间"""
        self.last_activity = datetime.now()
        db.session.commit()

    def deactivate(self):
        """停用会话"""
        self.is_active = False
        db.session.commit()

    @classmethod
    def create_session(cls, user_id, session_id, access_token, refresh_token=None,
                       ip_address=None, device_type=None, browser=None, platform=None,
                       location=None, expiry_time=None):
        """创建新会话"""
        try:
            # 创建会话对象
            session = cls(
                user_id=user_id,
                session_id=session_id,
                access_token=access_token,
                refresh_token=refresh_token,
                device_type=device_type,
                browser=browser,
                platform=platform,
                ip_address=ip_address,
                location=location,
                expiry_time=expiry_time,
                last_activity=datetime.now()
            )

            # 保存到数据库
            db.session.add(session)
            db.session.commit()

            return session
        except Exception as e:
            db.session.rollback()
            raise e

    @classmethod
    def get_active_sessions(cls, user_id):
        """获取用户所有活跃会话"""
        return cls.query.filter_by(
            user_id=user_id,
            is_active=True
        ).filter(
            cls.expiry_time > datetime.now()
        ).order_by(cls.last_activity.desc()).all()

    @classmethod
    def get_by_session_id(cls, session_id):
        """根据session_id获取会话"""
        return cls.query.filter_by(session_id=session_id).first()

    @classmethod
    def get_by_access_token(cls, access_token):
        """根据access_token获取会话"""
        return cls.query.filter_by(access_token=access_token).first()

    @classmethod
    def cleanup_expired_sessions(cls, batch_size=1000):
        """清理过期会话"""
        expired_count = 0
        try:
            # 分批删除过期会话，避免锁表
            while True:
                expired_sessions = cls.query.filter(
                    (cls.expiry_time <= datetime.now()) | (cls.is_active == False)
                ).limit(batch_size).all()

                if not expired_sessions:
                    break

                for session in expired_sessions:
                    db.session.delete(session)
                    expired_count += 1

                db.session.commit()
                logger.info(f"已清理 {len(expired_sessions)} 个过期会话")

        except Exception as e:
            db.session.rollback()
            logger.error(f"清理过期会话时出错: {e}")

        return expired_count