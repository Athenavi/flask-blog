"""通知模块"""
import json
from datetime import datetime
from typing import Optional, Dict, Any

from flask import current_app

from src.extensions import db
from src.models.notification import Notification as NotificationModel
from src.models.user import User


def create_notification(
        recipient_id: int,
        title: str,
        content: str,
        notification_type: str = 'info',
        related_id: Optional[int] = None,
        data: Optional[Dict[str, Any]] = None
) -> NotificationModel:
    """
    创建通知
    
    Args:
        recipient_id: 接收者ID
        title: 通知标题
        content: 通知内容
        notification_type: 通知类型 ('info', 'warning', 'error', 'success')
        related_id: 相关对象ID
        data: 额外数据
    
    Returns:
        NotificationModel: 创建的通知对象
    """
    notification = NotificationModel(
        recipient_id=recipient_id,
        title=title,
        content=content,
        type=notification_type,
        related_id=related_id,
        data=json.dumps(data) if data else None
    )

    db.session.add(notification)
    db.session.commit()

    # 发送邮件通知（如果用户设置了邮件通知偏好）
    user = User.query.get(recipient_id)
    # if user and user.email and user.settings.get('email_notifications', True):
    #    send_notification_email(user, title, content)

    # 尝试通过WebSocket发送实时通知
    try:
        from src.extensions import socketio, SOCKETIO_AVAILABLE
        if SOCKETIO_AVAILABLE:
            # 发送实时通知到客户端
            socketio.emit('notification', {
                'id': notification.id,
                'title': title,
                'content': content,
                'type': notification_type,
                'timestamp': notification.created_at.isoformat(),
                'read': False
            }, room=f'user_{recipient_id}')
    except Exception as e:
        # 在serverless环境中，WebSocket可能不可用，记录警告但不抛出错误
        current_app.logger.warning(f"无法发送实时通知: {str(e)}")

    return notification


def get_user_notifications(user_id: int, unread_only: bool = False, limit: int = 20):
    """
    获取用户通知
    
    Args:
        user_id: 用户ID
        unread_only: 是否只获取未读通知
        limit: 限制数量
    
    Returns:
        Query结果
    """
    query = NotificationModel.query.filter_by(recipient_id=user_id).order_by(
        NotificationModel.created_at.desc()
    )

    if unread_only:
        query = query.filter_by(is_read=False)

    if limit:
        query = query.limit(limit)

    return query.all()


def mark_notification_as_read(notification_id: int, user_id: int) -> bool:
    """
    标记通知为已读
    
    Args:
        notification_id: 通知ID
        user_id: 用户ID
    
    Returns:
        bool: 是否成功
    """
    notification = NotificationModel.query.filter_by(
        id=notification_id,
        recipient_id=user_id
    ).first()

    if notification and not notification.is_read:
        notification.is_read = True
        notification.read_at = datetime.now()
        db.session.commit()
        return True

    return False


def mark_all_notifications_as_read(user_id: int) -> int:
    """
    标记所有通知为已读
    
    Args:
        user_id: 用户ID
    
    Returns:
        int: 更新的通知数量
    """
    unread_count = NotificationModel.query.filter_by(
        recipient_id=user_id,
        is_read=False
    ).update({
        'is_read': True,
        'read_at': datetime.now()
    })

    db.session.commit()
    return unread_count


def delete_notification(notification_id: int, user_id: int) -> bool:
    """
    删除通知
    
    Args:
        notification_id: 通知ID
        user_id: 用户ID
    
    Returns:
        bool: 是否成功
    """
    notification = NotificationModel.query.filter_by(
        id=notification_id,
        recipient_id=user_id
    ).first()

    if notification:
        db.session.delete(notification)
        db.session.commit()
        return True

    return False


def get_unread_count(user_id: int) -> int:
    """
    获取未读通知数量
    
    Args:
        user_id: 用户ID
    
    Returns:
        int: 未读通知数量
    """
    return NotificationModel.query.filter_by(
        recipient_id=user_id,
        is_read=False
    ).count()
