from flask import request, jsonify, render_template, current_app, abort

from src.database import get_db_connection
from src.models import Comment, db, Article


def create_comment(user_id, article_id):
    data = request.get_json()
    print(data)
    user_agent_str = str(request.user_agent)
    query = "INSERT INTO `comments` (`user_id`, `article_id`, `content`, `ip`, `user_agent`) VALUES (%s, %s, %s, %s, %s)"

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute(query,
                               (int(user_id), int(article_id), data['content'], request.remote_addr, user_agent_str))
                db.commit()
                return jsonify({"message": "评论成功"}), 201
    except Exception as e:
        print(f'Error: {e}')
        return jsonify({"message": "评论失败"}), 500


def delete_comment(user_id, comment_id):
    db = get_db_connection()
    comment_deleted = False
    try:
        with db.cursor() as cursor:
            query = "DELETE FROM `comments` WHERE `id` = %s AND `user_id` = %s;"
            cursor.execute(query, (int(comment_id), int(user_id)))
            db.commit()
            comment_deleted = True
    except Exception as e:
        print(f'Error: {e}')
    finally:
        db.close()
        return comment_deleted


def comment_page_get(user_id, article_id):
    article = Article.query.filter_by(article_id=article_id).first()
    if not article:
        abort(404, "Article not found")

    try:
        # 获取评论树（不序列化）
        comments = Comment.query.filter_by(article_id=article_id) \
            .options(db.joinedload(Comment.author)) \
            .order_by(Comment.parent_id, Comment.created_at.asc()) \
            .all()

        # 构建评论树结构
        comments_map = {c.id: {"comment": c, "replies": []} for c in comments}
        comments_tree = []

        for comment in comments:
            if comment.parent_id is None:
                comments_tree.append(comments_map[comment.id])
            else:
                parent = comments_map.get(comment.parent_id)
                if parent:
                    parent["replies"].append(comments_map[comment.id])
        # print(comments_tree)
        return render_template('comment.html',
                               article=article,
                               comments_tree=comments_tree)

    except Exception as e:
        current_app.logger.error(f"加载评论失败: {str(e)}")
        return render_template('comment.html',
                               article=article,
                               comments_tree=[],
                               error="加载评论失败")
