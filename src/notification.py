import smtplib
from datetime import timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# import flask_socketio
from flask import Flask, jsonify
from flask_caching import Cache

from src.database import get_db, redis_client, get_cache_status
from src.models import Notification
from src.setting import app_config
from src.utils.config.mail import get_mail_conf

noti = Flask(__name__, template_folder='../templates')
# socketio = flask_socketio.SocketIO(noti, cors_allowed_origins='*')
noti.secret_key = app_config.SECRET_KEY
noti.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=3)
noti.config['SESSION_COOKIE_NAME'] = 'zb_session'

cache = Cache(config={'CACHE_TYPE': 'simple'})
cache.init_app(noti)


def send_email(sender_email, password, receiver_email, smtp_server, smtp_port, subject, body):
    # 创建邮件对象
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    # 添加邮件正文
    msg.attach(MIMEText(body, 'plain'))

    try:
        # 连接到SMTP服务器，使用SMTP_SSL
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(sender_email, password)  # 登录
            server.sendmail(sender_email, receiver_email, msg.as_string())  # 发送邮件
        print("邮件发送成功!")
    except Exception as e:
        print(f"邮件发送失败: {e}")


def send_change_mail(content, kind):
    try:
        if content and kind:
            subject = "数据变化通知"
            body = f"来自{kind}新的内容: {content}"
            smtp_server, stmp_port, sender_email, password = get_mail_conf()
            receiver_email = sender_email
            send_email(sender_email, password, receiver_email, smtp_server, smtp_port=int(stmp_port),
                       subject=subject,
                       body=body)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        pass


def read_all_notifications(user_id):
    success = False
    with get_db() as session:
        try:
            # 批量更新所有未读通知
            updated_count = session.query(Notification).filter(Notification.user_id == user_id,
                                                               Notification.is_read == False).update(
                {Notification.is_read: True})
            session.commit()
            success = True
        except Exception as e:
            print(f"批量更新已读状态失败: {e}")
            session.rollback()

    response = jsonify({"success": success, "updated_count": updated_count if success else 0})
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response


def get_notifications(user_id):
    messages = []
    with get_db() as session:
        try:
            # 获取用户的所有通知
            notifications = session.query(Notification).filter(Notification.user_id == user_id).all()
            messages = [{"id": n.id, "user_id": n.user_id, "message": n.message, "is_read": n.is_read,
                         "created_at": n.created_at.strftime("%Y-%m-%d %H:%M:%S"), 'type': n.type} for n in
                        notifications]
        except Exception as e:
            print(f"获取消息时发生错误: {e}")

    response = jsonify(messages)
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response


def read_current_notification(user_id, notification_id):
    success = False
    with get_db() as session:
        try:
            # 更新特定通知的已读状态
            updated_count = session.query(Notification).filter(Notification.id == notification_id,
                                                               Notification.user_id == user_id).update(
                {Notification.is_read: True})
            session.commit()
            success = True
        except Exception as e:
            print(f"更新通知已读状态失败: {e}")
            session.rollback()

    response = jsonify({"success": success})
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response, 200


import json
from datetime import datetime, timedelta
import threading


# 内存缓存实现
class NotificationCache:
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()
        self.cleanup_interval = 100  # 每100次操作清理一次过期缓存
        self.operation_count = 0

    def get(self, key):
        with self.lock:
            self.operation_count += 1
            if self.operation_count >= self.cleanup_interval:
                self.cleanup_expired()
                self.operation_count = 0

            if key in self.cache:
                data, expiry = self.cache[key]
                if datetime.now() < expiry:
                    return data
                else:
                    del self.cache[key]
            return None

    def set(self, key, data, ttl_seconds):
        with self.lock:
            expiry = datetime.now() + timedelta(seconds=ttl_seconds)
            self.cache[key] = (data, expiry)

    def cleanup_expired(self):
        """清理过期缓存"""
        current_time = datetime.now()
        expired_keys = [k for k, (_, expiry) in self.cache.items() if current_time >= expiry]
        for key in expired_keys:
            del self.cache[key]
        if expired_keys:
            print(f"清理了 {len(expired_keys)} 个过期内存缓存")


# 全局内存缓存实例
memory_cache = NotificationCache()


# Redis操作函数
def _should_send_notification_redis(parent_comment_id, article_title, user_id):
    """Redis版本的防轰炸检查"""
    cache_key = f"notification:{parent_comment_id}:{user_id}"

    cached_data = redis_client.get(cache_key)
    if cached_data is None:
        return True, 1
    else:
        data = json.loads(cached_data)
        last_time = datetime.fromisoformat(data['last_time'])
        count = data['count']
        current_time = datetime.now()

        if current_time - last_time >= timedelta(hours=3):
            return True, count + 1
        else:
            data['count'] = count + 1
            data['last_time'] = last_time.isoformat()  # 保持原来的时间
            redis_client.setex(cache_key, 3 * 3600, json.dumps(data))
            return False, data['count']


def _update_notification_cache_redis(parent_comment_id, user_id, count=1):
    """Redis版本的缓存更新"""
    cache_key = f"notification:{parent_comment_id}:{user_id}"
    current_time = datetime.now()

    cache_data = {
        'last_time': current_time.isoformat(),
        'count': count
    }
    redis_client.setex(cache_key, 3 * 3600, json.dumps(cache_data))


# 内存操作函数
def _should_send_notification_memory(parent_comment_id, article_title, user_id):
    """内存版本的防轰炸检查"""
    cache_key = f"{parent_comment_id}:{user_id}"

    cached_data = memory_cache.get(cache_key)
    if cached_data is None:
        return True, 1
    else:
        last_time = datetime.fromisoformat(cached_data['last_time'])
        count = cached_data['count']
        current_time = datetime.now()

        if current_time - last_time >= timedelta(hours=3):
            return True, count + 1
        else:
            cached_data['count'] = count + 1
            memory_cache.set(cache_key, cached_data, 3 * 3600)
            return False, cached_data['count']


def _update_notification_cache_memory(parent_comment_id, user_id, count=1):
    """内存版本的缓存更新"""
    cache_key = f"{parent_comment_id}:{user_id}"
    current_time = datetime.now()

    cache_data = {
        'last_time': current_time.isoformat(),
        'count': count
    }
    memory_cache.set(cache_key, cache_data, 3 * 3600)


# 统一接口 - 优先Redis，异常时降级到内存
def should_send_notification(parent_comment_id, article_title, user_id):
    """
    统一的防轰炸检查接口
    优先使用Redis，异常时自动降级到内存缓存
    返回: (should_send, count) - 是否发送通知和累积的回复数量
    """
    # 优先尝试Redis
    if redis_client is not None:
        try:
            result = _should_send_notification_redis(parent_comment_id, article_title, user_id)
            print("使用Redis缓存进行检查")
            return result
        except Exception as e:
            print(f"Redis操作失败，降级到内存缓存: {e}")

    # Redis不可用或操作失败，使用内存缓存
    print("使用内存缓存进行检查")
    return _should_send_notification_memory(parent_comment_id, article_title, user_id)


def update_notification_cache(parent_comment_id, user_id, count=1):
    """
    统一的缓存更新接口
    优先使用Redis，异常时自动降级到内存缓存
    """
    # 优先尝试Redis
    if redis_client is not None:
        try:
            _update_notification_cache_redis(parent_comment_id, user_id, count)
            print("使用Redis缓存进行更新")
            return
        except Exception as e:
            print(f"Redis操作失败，降级到内存缓存: {e}")

    # Redis不可用或操作失败，使用内存缓存
    print("使用内存缓存进行更新")
    _update_notification_cache_memory(parent_comment_id, user_id, count)


# 测试函数
def test_notification_system():
    """测试通知系统"""
    test_cases = [
        ("comment_123", "测试文章1", "1"),
        ("comment_123", "测试文章1", "1"),  # 重复测试
        ("comment_789", "测试文章2", "1"),
    ]

    for i, (parent_id, title, user_id) in enumerate(test_cases, 1):
        print(f"\n测试用例 {i}:")
        print(f"父评论: {parent_id}, 用户: {user_id}")

        should_send, count = should_send_notification(parent_id, title, user_id)
        print(f"是否发送通知: {should_send}, 累计数量: {count}")

        if should_send:
            update_notification_cache(parent_id, user_id, count)
            print("通知已发送，缓存已更新")

        print(f"当前缓存类型: {get_cache_status()}")


if __name__ == "__main__":
    # 运行测试
    test_notification_system()
