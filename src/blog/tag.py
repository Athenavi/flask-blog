from flask import request, jsonify

from src.database import get_db_connection
from src.user.entities import auth_by_uid


# from pymysql import DatabaseError

def get_unique_article_tags():
    unique_tags = []

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = "SELECT Tags FROM articles"
                cursor.execute(query)
                results = cursor.fetchall()
                for result in results:
                    tags_str = result[0]
                    if tags_str:
                        tags_list = tags_str.split(';')
                        unique_tags.extend(tag for tag in tags_list if tag)
                unique_tags = list(set(unique_tags))

    except Exception as e:
        return f"未知错误: {e}"

    return unique_tags


def get_articles_by_tag(tag_name):
    tag_articles = []

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = "SELECT Title FROM articles WHERE hidden = 0 AND `Status` = 'Published' AND `Tags` LIKE %s"
                cursor.execute(query, ('%' + tag_name + '%',))
                results = cursor.fetchall()
                for result in results:
                    tag_articles.append(result[0])

    except Exception as e:
        return f"未知错误: {e}"

    return tag_articles


def query_article_tags(article_name):
    db = get_db_connection()
    cursor = db.cursor()
    unique_tags = []
    aid = 0

    try:
        query = "SELECT article_id, Tags FROM articles WHERE Title = %s"
        cursor.execute(query, (article_name,))

        result = cursor.fetchone()
        if result:
            aid = result[0] or 0
            tags_str = result[1]
            if tags_str:
                tags_list = tags_str.split(';')
                unique_tags = list(set(tags_list))
    except Exception as e:  # 捕获其他异常
        # 记录其他错误
        print(f"发生了一个错误: {e}")
        return aid, []
    finally:
        cursor.close()
        db.close()
        return aid, unique_tags


def update_article_tags(aid, tags_list):
    tags_str = ';'.join(tags_list)

    db = get_db_connection()
    cursor = db.cursor()

    try:
        # 检查文章是否存在
        query = "SELECT * FROM articles WHERE article_id = %s"
        cursor.execute(query, (int(aid),))
        result = cursor.fetchone()

        if result:
            # 如果文章存在，则更新标签
            update_query = "UPDATE articles SET Tags = %s WHERE article_id = %s"
            cursor.execute(update_query, (tags_str, int(aid)))
            db.commit()

    except Exception as e:
        print(f"An error occurred during database operation: {e}")
        pass

    finally:
        cursor.close()
        db.close()


def update_tags_back(user_id, aid):
    auth = auth_by_uid(aid, user_id)
    if not auth:
        return jsonify({
            'code': -1,
            'message': '权限不足'
        }), 403
    try:
        # 从表单数据获取标签，并将中文逗号替换为英文逗号
        tags_str = request.form.get('tags', '').replace('，', ',')
        tag_list = [tag.strip() for tag in tags_str.split(',') if tag.strip()]

        # 清理标签：移除所有空格和尾部的‘x’
        tag_list = [tag.replace(' ', '') for tag in tag_list]

        # 去重标签
        tag_list = list(set(tag_list))

        # 验证标签数量
        if len(tag_list) > 10:
            return jsonify({
                'code': -1,
                'message': '标签数量不能超过10个'
            }), 400

        # 更新数据库
        update_article_tags(aid, tag_list)

        # 返回新的标签HTML片段
        tags_html = ''.join([f'<span class="tag-badge">{tag}</span>' for tag in tag_list])
        return tags_html
    except Exception as e:
        # app.logger.error(f"更新标签失败: {str(e)}")
        return jsonify({
            'code': -1,
            'message': '服务器内部错误'
        }), 500
