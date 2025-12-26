import atexit
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from src.extensions import db
from src.models import UserSession, Article

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

        # 同步文章浏览量，每5分钟执行一次
        self.scheduler.add_job(
            func=self.sync_article_views,
            trigger=IntervalTrigger(minutes=5),
            id='sync_article_views',
            name='同步文章浏览量',
            replace_existing=True
        )

        # 启动调度器
        if not self.scheduler.running:
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

    def sync_article_views(self):
        """同步文章浏览量"""
        with self.app.app_context():
            try:
                # 延迟导入 cache 以避免循环导入
                from src.extensions import cache

                # 获取所有带缓存的文章浏览量
                # 使用缓存的keys()方法而不是直接访问内部缓存
                try:
                    # 尝试使用缓存的keys方法，如果不可用则跳过
                    if hasattr(cache.cache, 'keys'):
                        keys = cache.cache.keys()
                    else:
                        # 如果缓存后端不支持keys()方法，可以使用其他方式获取
                        # 这里使用一个安全的默认值，避免直接访问内部缓存
                        keys = []
                    
                    article_keys = [key for key in keys if str(key).startswith('article_views_')]
                except Exception:
                    # 如果无法获取缓存键，则跳过同步
                    article_keys = []

                updated_count = 0
                for key in article_keys:
                    # 从键名中提取文章ID
                    article_id = int(key.split('_')[-1])

                    # 获取缓存中的浏览量
                    cached_views = cache.get(key)

                    if cached_views is not None:
                        # 更新文章的浏览量
                        article = db.session.query(Article).filter_by(article_id=article_id).first()
                        if article:
                            article.views = cached_views
                            updated_count += 1

                # 提交事务
                db.session.commit()

                # 清除已同步的缓存
                for key in article_keys:
                    cache.delete(key)

                if updated_count > 0:
                    print(f"{datetime.now()}: 成功同步 {updated_count} 篇文章的浏览量")

            except Exception as e:
                db.session.rollback()
                print(f"{datetime.now()}: 同步文章浏览量时出错: {e}")


# 创建全局调度器实例
session_scheduler = SessionScheduler()


def init_scheduler(app):
    """初始化调度器"""
    session_scheduler.init_app(app)
