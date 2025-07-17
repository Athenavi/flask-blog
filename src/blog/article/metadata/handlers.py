import datetime

# from pymysql import DatabaseError

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
                                                       tags    = VALUES(tags);
                               """, (a_title, user_id, current_year))

                # 获取最近插入或更新的 article_id
                cursor.execute("SELECT LAST_INSERT_ID();")
                article_id = cursor.fetchone()[0]

                # 记录事件信息
                cursor.execute("""
                               INSERT INTO events (title, description, event_date, created_at)
                               VALUES (%s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
                               """, ('article update', f'{user_id} updated {a_title}'))

                # 提交事务
                db.commit()
                return article_id

    except Exception as e:
        print(f"数据库操作期间发生错误: {e}")
        db.rollback()
        return None


def get_article_metadata(aid):
    result = (None,) * 13

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = "SELECT * FROM articles WHERE article_id = %s"
                cursor.execute(query, (int(aid),))
                fetched_result = cursor.fetchone()
                if fetched_result:
                    result = fetched_result

    except Exception as e:
        print(f"发生了一个错误: {e}")

    return result


import os
from contextlib import closing


def upsert_article_content(aid, file, upload_folder):
    try:
        # 确保上传文件夹存在
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        file_path = os.path.join(upload_folder, file.filename)

        with closing(get_db_connection()) as db:
            with db.cursor() as cursor:
                # 以二进制模式打开文件，并确保文件在使用后会被关闭
                with open(file_path, 'rb') as f:
                    content = f.read()

                # 使用REPLACE INTO语句来更新或插入数据
                query = "REPLACE INTO article_content (aid, content) VALUES (%s, %s);"
                cursor.execute(query, (aid, content))
                db.commit()

            # 删除临时文件
            os.remove(file_path)
            return True

    except Exception as e:
        print(f"数据库操作期间发生错误: {e}")
        # 只有在db已经被正确初始化后才进行回滚
        if 'db' in locals():
            db.rollback()
        # 如果文件存在，删除它以避免留下不完整的文件
        if os.path.exists(file_path):
            os.remove(file_path)
        return False


import threading
import time
from collections import defaultdict

# 全局计数器和锁
view_counts = defaultdict(int)
counter_lock = threading.Lock()

stop_event = threading.Event()
PERSIST_INTERVAL = 60  # 每60秒持久化一次


def persist_views():
    """定时将内存中的浏览量持久化到数据库"""
    while not stop_event.is_set():
        time.sleep(PERSIST_INTERVAL)

        try:
            # 创建计数器快照并清空
            with counter_lock:
                if not view_counts:
                    continue

                counts_snapshot = view_counts.copy()
                view_counts.clear()

            # 批量更新数据库
            update_success = False
            try:
                with get_db_connection() as db:
                    with db.cursor() as cursor:
                        for blog_id, count in counts_snapshot.items():
                            query = """
                                    UPDATE `articles`
                                    SET `views` = `views` + %s
                                    WHERE `article_id` = %s \
                                    """
                            cursor.execute(query, (count, blog_id))
                        db.commit()
                        update_success = True

            except Exception as db_error:
                # app.logger.error(f"Database update failed: {str(db_error)}",exc_info=True)
                db.rollback()

            # 如果更新失败，恢复计数器
            if not update_success:
                with counter_lock:
                    for blog_id, count in counts_snapshot.items():
                        view_counts[blog_id] += count

        except Exception as e:
            # app.logger.error(f"View persistence error: {str(e)}",exc_info=True)
            pass

    # 程序关闭时执行最后一次持久化
    final_persist()


def final_persist():
    """应用关闭时执行最终持久化"""
    with counter_lock:
        if not view_counts:
            return

        counts_snapshot = view_counts.copy()
        view_counts.clear()

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                for blog_id, count in counts_snapshot.items():
                    cursor.execute(
                        "UPDATE `articles` SET `views` = `views` + %s WHERE `article_id` = %s",
                        (count, blog_id)
                    )
                db.commit()
    except Exception as e:
        # app.logger.error(f"Final persist failed: {str(e)}",exc_info=True)
        db.rollback()
