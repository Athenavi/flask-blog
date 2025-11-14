import uuid
from datetime import datetime, timedelta

from user_agents import parse

from . import db


class UserSession(db.Model):
    __tablename__ = 'user_sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # 会话唯一标识（与Flask-Session中的session_id对应）
    session_id = db.Column(db.String(255), nullable=False, unique=True, index=True)

    # 访问令牌（如果需要）
    access_token = db.Column(db.String(512), unique=True, index=True)
    refresh_token = db.Column(db.String(512), unique=True, index=True)

    # 设备信息
    device_type = db.Column(db.String(50))  # web, mobile, tablet, etc.
    browser = db.Column(db.String(100))
    platform = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))  # 支持IPv6

    # 位置信息（可选）
    location = db.Column(db.String(255))

    # 时间信息
    last_activity = db.Column(db.DateTime, nullable=False, default=datetime.now)
    expiry_time = db.Column(db.DateTime, nullable=False)

    # 会话状态
    is_active = db.Column(db.Boolean, default=True)

    # 关系定义
    user = db.relationship('User', backref=db.backref('sessions', lazy='dynamic', cascade='all, delete-orphan'))

    def __init__(self, user_id, session_id=None, device_info=None, ip_address=None,
                 access_token=None, refresh_token=None, expiry_hours=24):
        self.user_id = user_id
        self.session_id = session_id or str(uuid.uuid4())
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.ip_address = ip_address
        self.last_activity = datetime.now()
        self.expiry_time = datetime.now() + timedelta(hours=expiry_hours)
        self.is_active = True

        # 解析设备信息
        if device_info:
            self._parse_device_info(device_info)

    def _parse_device_info(self, user_agent_string):
        """使用 user_agents 库解析用户代理字符串获取设备信息"""
        try:
            if not user_agent_string:
                self.device_type = 'unknown'
                self.browser = 'unknown'
                self.platform = 'unknown'
                return

            parsed_ua = parse(user_agent_string)

            # 设备类型
            if parsed_ua.is_mobile:
                self.device_type = 'mobile'
            elif parsed_ua.is_tablet:
                self.device_type = 'tablet'
            else:
                self.device_type = 'desktop'

            # if parsed_ua.is_bot:
            #    bot_info = parsed_ua.get_bot()
            # 浏览器信息
            self.browser = f"{parsed_ua.browser.family} {parsed_ua.browser.version_string}"

            # 平台信息
            self.platform = f"{parsed_ua.os.family} {parsed_ua.os.version_string}"

        except Exception as e:
            # 如果解析失败，设置默认值
            print(f"解析 User-Agent 失败: {e}")
            self.device_type = 'unknown'
            self.browser = 'unknown'
            self.platform = 'unknown'

    def update_activity(self):
        """更新最后活动时间"""
        self.last_activity = datetime.now()
        db.session.commit()

    def extend_expiry(self, hours=24):
        """延长会话过期时间"""
        self.expiry_time = datetime.now() + timedelta(hours=hours)
        db.session.commit()

    def deactivate(self):
        """停用会话"""
        self.is_active = False
        self.expiry_time = datetime.now()  # 立即过期
        db.session.commit()

    def is_expired(self):
        """检查会话是否过期"""
        return datetime.now() > self.expiry_time or not self.is_active

    def is_current(self, request):
        zb_session = request.session.get('zb_session')
        if zb_session == self.id:
            return True
        else:
            return False

    @property
    def duration(self):
        """获取会话持续时间"""
        if self.is_active:
            return datetime.now() - self.last_activity
        return self.last_activity

    def to_dict(self):
        """转换为字典格式，用于API响应"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'device_type': self.device_type,
            'browser': self.browser,
            'platform': self.platform,
            'ip_address': self.ip_address,
            'location': self.location,
            'last_activity': self.last_activity.isoformat(),
            'expiry_time': self.expiry_time.isoformat(),
            'is_active': self.is_active,
            'duration_seconds': int(self.duration.total_seconds())
        }

    @classmethod
    def get_active_sessions(cls, user_id):
        """获取用户的所有活跃会话"""
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
                print(f"已清理 {len(expired_sessions)} 个过期会话")

        except Exception as e:
            db.session.rollback()
            print(f"清理过期会话时出错: {e}")

        return expired_count
