from flask import request, jsonify, render_template, current_app, abort

from src.database import get_db_connection
from src.models import Comment, db, Article


def get_comments(aid, page=1, per_page=30):
    comments = []
    try:
        db = get_db_connection()
        with db:
            with db.cursor() as cursor:
                offset = (page - 1) * per_page
                query = "SELECT * FROM `comments` WHERE `article_id` = %s LIMIT %s OFFSET %s"
                cursor.execute(query, (int(aid), per_page, offset))
                comments = cursor.fetchall()

                # 查询评论的总数以判断是否有下一页和上一页
                count_query = "SELECT COUNT(*) FROM `comments` WHERE `article_id` = %s"
                cursor.execute(count_query, (int(aid),))
                total_comments = cursor.fetchone()[0]

                has_next_page = (page * per_page) < total_comments
                has_previous_page = page > 1
    except Exception as e:
        print(f'Error: {e}')

    return comments, has_next_page, has_previous_page


def create_comment(user_id,article_id):
    data = request.get_json()
    #print(data)
    new_comment = Comment(
        article_id=article_id,
        user_id=user_id,
        parent_id=data.get('parent_id'),
        content=data['content'],
        ip=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )

    db.session.add(new_comment)
    db.session.commit()
    return jsonify({'message': '评论已发送', 'comment_id': new_comment.id}), 201


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


def delete_comment_back(user_id):
    try:
        comment_id = int(request.json.get('comment_id'))
    except (TypeError, ValueError):
        return jsonify({"message": "Invalid Comment ID"}), 400

    result = delete_comment(user_id, comment_id)

    if result:
        return jsonify({"message": "删除成功"}), 201
    else:
        return jsonify({"message": "操作失败"}), 500


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
