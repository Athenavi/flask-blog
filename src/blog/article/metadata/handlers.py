import datetime
from contextlib import closing

from pymysql import DatabaseError

from src.database import get_db_connection


def upsert_article_metadata(a_title, user_id):
    try:
        with closing(get_db_connection()) as db:
            with db.cursor() as cursor:
                current_year = datetime.datetime.now().year

                # 插入或更新文章信息
                cursor.execute("""
                               INSERT INTO articles (Title, user_id, tags)
                               VALUES (%s, %s, %s)
                               ON DUPLICATE KEY UPDATE user_id = VALUES(user_id),
                                                       tags   = VALUES(tags);
                               """, (a_title, user_id, current_year))

                # 记录事件信息
                cursor.execute("""
                               INSERT INTO events (title, description, event_date, created_at)
                               VALUES (%s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
                               """, ('article update', f'{user_id} updated {a_title}'))

                # 提交事务
                db.commit()
                return True

    except Exception as e:
        print(f"数据库操作期间发生错误: {e}")
        db.rollback()
        return False


def get_article_metadata(aid):
    result = (None,) * 13
    db = get_db_connection()
    cursor = db.cursor()
    try:
        query = "SELECT * FROM articles WHERE article_id = %s"
        cursor.execute(query, (int(aid),))
        fetched_result = cursor.fetchone()
        if fetched_result:
            result = fetched_result
    except DatabaseError as db_err:
        print(f"数据库错误: {db_err}")
    except Exception as e:
        print(f"发生了一个错误: {e}")
    finally:
        cursor.close()
        db.close()
    return result
