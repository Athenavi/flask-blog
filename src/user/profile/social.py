from src.database import get_db_connection


def get_subscriber_ids(uid):
    db = get_db_connection()
    cursor = db.cursor()

    try:
        # 查询用户的订阅信息和对应的用户名，合并两个查询
        query = """
                SELECT u.id, u.username
                FROM user_subscriptions s
                         JOIN users u ON s.subscribed_user_id = u.id
                WHERE s.subscriber_id = %s;
                """
        cursor.execute(query, (uid,))
        subscribers = cursor.fetchall()

        # 如果没有找到订阅者，返回空列表
        if not subscribers:
            return []

        # 创建（ID, 用户名）元组列表
        subscriber_ids_list = [(sub[0], sub[1]) for sub in subscribers]
        print(subscriber_ids_list)
        return subscriber_ids_list

    except Exception as e:
        return f"未知错误{e}", False, False

    finally:
        cursor.close()
        db.close()


def get_following_count(user_id, subscribe_type='User'):
    db = get_db_connection()
    count = 0
    try:
        with db.cursor() as cursor:
            if subscribe_type == 'User':
                query = "SELECT COUNT(*) FROM user_subscriptions WHERE `subscriber_id` = %s;"
                cursor.execute(query, (int(user_id),))
            else:
                query = "SELECT COUNT(*) FROM category_subscriptions WHERE `subscriber_id` = %s;"
                cursor.execute(query, (int(user_id),))

            count = cursor.fetchone()[0]
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        db.close()
        return count


def get_follower_count(user_id, subscribe_type='User'):
    db = get_db_connection()
    count = 0
    try:
        with db.cursor() as cursor:
            if subscribe_type == 'User':
                query = "SELECT COUNT(*) FROM user_subscriptions WHERE `subscribed_user_id` = %s;"
                cursor.execute(query, (int(user_id),))
            else:
                query = "SELECT COUNT(*) FROM category_subscriptions WHERE `category_id` = %s;"
                cursor.execute(query, (int(user_id),))

            count = cursor.fetchone()[0]
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        db.close()
        return count


def can_follow_user(user_id, target_id):
    db = get_db_connection()
    can_follow = 1
    try:
        with db.cursor() as cursor:
            query = "SELECT COUNT(*) FROM `user_subscriptions` WHERE `subscriber_id` = %s AND `subscribed_user_id` = %s;"
            cursor.execute(query, (int(user_id), int(target_id)))
            count = cursor.fetchone()[0]
            if count:
                can_follow = 0
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        db.close()
        return can_follow


def get_user_info(user_id):
    if not user_id:
        return []
    info_list = []
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            query = "SELECT * FROM users WHERE `id` = %s;"
            params = (user_id,)
            cursor.execute(query, params)
            info = cursor.fetchone()

            if info:
                info_list = list(info)
                if len(info_list) > 2:
                    del info_list[2]
    except Exception as e:
        # app.logger.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")
    finally:
        db.close()
        return info_list


def get_user_name_by_id(user_id):
    author_name = '未知作者'
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute("SELECT `username` FROM `users` WHERE `id` = %s", (user_id,))
                result = cursor.fetchone()
                if result:
                    author_name = result[0]
    except (ValueError, TypeError) as e:
        pass
        # app.logger.error(f"Error getting author name for user_id {user_id}: {e}")
    finally:
        return author_name
