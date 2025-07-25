from flask import jsonify

from src.database import get_db_connection
from src.user.entities import authorize_by_aid_deleted


def fetch_articles(query, params):
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            cursor.execute(query, params)
            article_info = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) FROM `articles` WHERE `Hidden`=0 AND `Status`='Published'")
            total_articles = cursor.fetchone()[0]

    except Exception as e:
        print(f"Error getting articles: {e}")
        raise

    finally:
        if db is not None:
            db.close()
        return article_info, total_articles


def get_articles_by_owner(owner_id=None):
    db = get_db_connection()
    articles = []

    try:
        with db.cursor() as cursor:
            if owner_id:
                query = """
                        SELECT a.article_id, a.Title
                        FROM articles AS a
                        WHERE a.user_id = %s
                          and a.`Status` != 'Deleted'; \
                        """
                cursor.execute(query, (owner_id,))
                articles.extend((result[0], result[1]) for result in cursor.fetchall())
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        db.close()
        return articles


def get_articles_recycle(user_id):
    articles = []

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                if user_id:
                    query = """
                            SELECT a.article_id, a.Title
                            FROM articles AS a
                            WHERE a.user_id = %s
                              AND a.`Status` = 'Deleted';
                            """
                    cursor.execute(query, (user_id,))
                    articles.extend((result[0], result[1]) for result in cursor.fetchall())
    except Exception as e:
        print(f"An error occurred: {e}")

    return articles


def delete_db_article(user_id, aid):
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute("UPDATE `articles` SET Hidden=1, `Status`=%s WHERE `article_id`=%s", ('Deleted', aid))
                db.commit()
        return jsonify({'show_edit_code': "deleted"}), 201
    except Exception as e:
        return jsonify({'show_edit_code': 'error', 'message': f'删除文章失败{e}'}), 500


def post_blog_detail(title):
    query = """
            SELECT *
            FROM `articles`
            WHERE `Hidden` = 0
              AND `Status` = 'Published'
              AND `title` = %s
            ORDER BY `article_id` DESC
            LIMIT 1; \
            """
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute(query, (title,))
                result = cursor.fetchone()
                if result:
                    return jsonify(result)
                else:
                    return jsonify({"error": "Article not found"}), 404
    except Exception as e:
        # app.logger.error(e)
        return jsonify({"error": "Internal server error"}), 500


def blog_restore(aid, user_id):
    auth = authorize_by_aid_deleted(aid, user_id)
    if auth is False:
        return jsonify({"message": f"操作失败"}), 503
    try:
        with get_db_connection() as connection:
            with connection.cursor(dictionary=True) as cursor:
                query = "UPDATE `articles` SET `status` = 'Draft' WHERE `articles`.`article_id` = %s;"
                cursor.execute(query, (aid,))
                connection.commit()
        return jsonify({"message": "操作成功"}), 200
    except Exception as e:
        return jsonify({"message": f"操作失败{e}"}), 500


def blog_delete(aid, user_id):
    auth = authorize_by_aid_deleted(aid, user_id)
    if auth is False:
        jsonify({"message": f"操作失败"}), 503
    try:
        with get_db_connection() as connection:
            with connection.cursor(dictionary=True) as cursor:
                query = "DELETE FROM `articles` WHERE `articles`.`article_id` = %s;"
                cursor.execute(query, (aid,))
                connection.commit()
        return jsonify({"message": "操作成功"}), 200
    except Exception as e:
        return jsonify({"message": f"操作失败{e}"}), 500


def get_aid_by_title(title):
    """根据标题获取文章ID（带缓存）"""
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = """
                        SELECT `article_id`
                        FROM `articles`
                        WHERE `title` = %s
                          AND `Hidden` = 0
                          AND `Status` = 'Published' \
                        """
                cursor.execute(query, (title,))
                result = cursor.fetchone()
                return result[0] if result else None
    except Exception as e:
        # app.logger.error(f"Failed to get ID for title '{title}': {str(e)}",exc_info=True)
        return None


def blog_update(aid, content):
    try:
        # 更新文章内容
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute("UPDATE `article_content` SET `Content` = %s WHERE `aid` = %s", (content, aid))
                db.commit()
                return True
    except Exception as e:
        # app.logger.error(f"Error updating article content for article id {aid}: {e}")
        return False
