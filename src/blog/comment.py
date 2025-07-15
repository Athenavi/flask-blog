import json

from src.database import get_db_connection


def get_comments(aid, page=1, per_page=30):
    comments = []
    db = get_db_connection()
    try:
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
    finally:
        db.close()

    return comments, has_next_page, has_previous_page


def create_comment(aid, user_id, pid, comment_content, ip, ua):
    c_json = {'content': comment_content, 'pid': pid, 'ip': ip, 'ua': ua}
    comment_json = json.dumps(c_json)
    db = get_db_connection()
    comment_added = False
    try:
        with db.cursor() as cursor:
            query = "INSERT INTO `comments` (`article_id`, `user_id`, `content`) VALUES (%s, %s, %s);"
            cursor.execute(query, (int(aid), int(user_id), comment_json))
            db.commit()
            comment_added = True
    except Exception as e:
        print(f'Error: {e}')
    finally:
        db.close()
        return comment_added


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
