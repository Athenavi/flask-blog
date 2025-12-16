import logging

from flask import render_template, current_app, abort
from flask import request, jsonify

from src.models import Comment, Article, Notification, db
from src.notification import should_send_notification, update_notification_cache

logger = logging.getLogger(__name__)


def create_comment_with_anti_spam(user_id, article_id):
    """
    带有防轰炸功能的评论创建函数
    """
    data = request.get_json()
    logger.debug(data)
    user_agent_str = str(request.user_agent)

    try:
        parent_id = data['parent_id'] if 'parent_id' in data and data['parent_id'] else None
        new_comment = Comment(
            user_id=int(user_id),
            article_id=int(article_id),
            content=data['content'],
            ip=request.remote_addr,
            user_agent=user_agent_str,
            parent_id=parent_id
        )
        db.session.add(new_comment)

        if parent_id:
            comment = db.session.query(Comment).filter_by(id=int(parent_id)).first()
            if comment:
                # 检查是否应该发送通知
                should_send, reply_count = should_send_notification(
                    parent_id,
                    comment.article.title,
                    comment.user_id
                )

                if should_send:
                    # 发送通知
                    if reply_count == 1:
                        message = f"您在《{comment.article.title}》的评论有新的回复"
                    else:
                        message = f"您在《{comment.article.title}》的评论有新的回复 +{reply_count}"

                    notification = Notification(
                        user_id=comment.user_id,
                        type='system',
                        message=message,
                        is_read=False
                    )
                    db.session.add(notification)

                    # 更新缓存（重置计数）
                    update_notification_cache(parent_id, comment.user_id, 1)
                else:
                    # 不发送通知，只更新缓存（计数已在should_send_notification中更新）
                    logger.info(f"3小时内已有{reply_count}条回复，暂不发送通知")

        db.session.commit()
        return jsonify({"message": "评论成功"}), 201

    except Exception as e:
        logger.error(f'Error: {e}')
        db.session.rollback()
        return jsonify({"message": "评论失败"}), 500


from sqlalchemy.orm import joinedload


def comment_page_get(article_id):
    article = Article.query.filter_by(article_id=article_id).first()
    if not article:
        abort(404, "Article not found")
    try:
        # 获取评论树（不序列化）
        comments = Comment.query.filter_by(article_id=article_id) \
            .options(joinedload(Comment.author)) \
            .order_by(Comment.parent_id, Comment.created_at.asc()) \
            .all()

        # logger.debug(comments_tree)
        return render_template('comment/main.html',
                               article=article,
                               comments_tree=comments)

    except Exception as e:
        current_app.logger.error(f"加载评论失败: {str(e)}")
        return render_template('comment/main.html',
                               article=article,
                               comments_tree=[],
                               error="加载评论失败")