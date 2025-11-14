import atexit
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from src.models import db, UserSession

# 配置日志
logging.basicConfig()
logging.getLogger('apscheduler').setLevel(logging.INFO)


class SessionScheduler:
    def __init__(self, app=None):
        self.scheduler = BackgroundScheduler()
        self.app = app

    def init_app(self, app):
        self.app = app
        self._init_scheduler()

    def _init_scheduler(self):
        """初始化计划任务"""
        # 清理过期会话，每30分钟执行一次
        self.scheduler.add_job(
            func=self.cleanup_expired_sessions,
            trigger=IntervalTrigger(minutes=30),
            id='cleanup_expired_sessions',
            name='清理过期用户会话',
            replace_existing=True
        )

        # 清理过期access_token，每小时执行一次
        self.scheduler.add_job(
            func=self.cleanup_expired_tokens,
            trigger=IntervalTrigger(hours=1),
            id='cleanup_expired_tokens',
            name='清理过期访问令牌',
            replace_existing=True
        )

        # 更新会话统计，每天凌晨2点执行
        self.scheduler.add_job(
            func=self.update_session_stats,
            trigger='cron',
            hour=2,
            minute=0,
            id='update_session_stats',
            name='更新会话统计信息',
            replace_existing=True
        )

        # 启动调度器
        self.scheduler.start()

        # 注册关闭钩子
        atexit.register(lambda: self.scheduler.shutdown())

        print("会话管理计划任务已启动")

    def cleanup_expired_sessions(self):
        """清理过期会话"""
        with self.app.app_context():
            try:
                count = UserSession.cleanup_expired_sessions()
                if count > 0:
                    print(f"{datetime.now()}: 已清理 {count} 个过期会话")
                else:
                    print(f"{datetime.now()}: 没有需要清理的过期会话")

            except Exception as e:
                print(f"{datetime.now()}: 清理过期会话时出错: {e}")

    def cleanup_expired_tokens(self):
        """清理过期的access_token"""
        with self.app.app_context():
            try:
                # 清理过期access_token（假设access_token有过期时间）
                # 这里可以根据你的token实现逻辑进行调整
                expired_tokens_count = UserSession.query.filter(
                    UserSession.access_token.isnot(None),
                    UserSession.expiry_time <= datetime.now()
                ).update({
                    'access_token': None,
                    'refresh_token': None
                })

                db.session.commit()

                if expired_tokens_count > 0:
                    print(f"{datetime.now()}: 已清理 {expired_tokens_count} 个过期token")

            except Exception as e:
                db.session.rollback()
                print(f"{datetime.now()}: 清理过期token时出错: {e}")

    def update_session_stats(self):
        """更新会话统计信息"""
        with self.app.app_context():
            try:
                # 这里可以添加会话统计逻辑
                # 例如：记录每日活跃用户数、平均会话时长等
                print(f"{datetime.now()}: 会话统计信息已更新")

            except Exception as e:
                print(f"{datetime.now()}: 更新会话统计时出错: {e}")


# 创建全局调度器实例
session_scheduler = SessionScheduler()
