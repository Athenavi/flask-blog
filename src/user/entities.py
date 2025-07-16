from src.database import get_db_connection


def authorize_by_aid(article_id, user_id):
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = "SELECT 1 FROM articles WHERE article_id = %s AND `Status` != 'Deleted' AND user_id = %s"
                cursor.execute(query, (article_id, user_id))
                return cursor.fetchone() is not None
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def authorize_by_aid_deleted(article_id, user_id):
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = "SELECT 1 FROM articles WHERE article_id = %s AND `Status` = 'Deleted' AND user_id = %s"
                cursor.execute(query, (article_id, user_id))
                return cursor.fetchone() is not None
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def get_user_id(user_name):
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = "SELECT `id` FROM `users` WHERE `username` = %s;"
                cursor.execute(query, (user_name,))
                result = cursor.fetchone()
                if result:
                    return result[0]
    except Exception as e:
        print(f"An error occurred: {e}")

    return 0


def get_user_sub_info(query, user_id):
    db = None
    user_sub_info = []
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute(query, (int(user_id),))
            user_sub = cursor.fetchall()
            subscribe_ids = [sub[0] for sub in user_sub]
            if subscribe_ids:
                placeholders = ', '.join(['%s'] * len(subscribe_ids))
                query = f"SELECT `id`, `username` FROM `users` WHERE `id` IN ({placeholders});"
                cursor.execute(query, tuple(subscribe_ids))
                user_sub_info = cursor.fetchall()
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if db is not None:
            db.close()
    return user_sub_info


def check_user_conflict(zone, value):
    if zone == 'username':
        query = "SELECT username FROM users"
    elif zone == 'email':
        query = "SELECT email FROM users"
    else:
        return False
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute(query)
                if value not in [row[0] for row in cursor.fetchall()]:
                    return False
        return False
    except Exception as e:
        print(f"Error getting user list: {e}")
        return False


def db_save_avatar(user_id, avatar_uuid):
    db = None
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            query = "UPDATE users SET profile_picture = %s WHERE id = %s"
            cursor.execute(query, (avatar_uuid, user_id))
            db.commit()
    except Exception as e:
        print(f"Error saving avatar: {e} by user {user_id} avatar uuid: {avatar_uuid}")
    finally:
        if db is not None:
            db.close()


def db_save_bio(user_id, bio):
    db = None
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            query = "UPDATE users SET bio = %s WHERE id = %s"
            cursor.execute(query, (bio, user_id))
            db.commit()
    except Exception as e:
        print(f"Error saving bio: {e} by user {user_id} bio: {bio}")
    finally:
        if db is not None:
            db.close()


def db_change_username(user_id, new_username):
    # 修改用户名将可能导致资料被意外删除,建议先导出您的资料再进行下一步操作
    # 导出资料: 点击右上角头像 -> 点击设置 -> 点击导出资料
    db = None
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            query = "UPDATE users SET username = %s WHERE id = %s"
            cursor.execute(query, (new_username, user_id))
            db.commit()
    except Exception as e:
        print(f"Error changing username: {e} by user {user_id} new username: {new_username}")
    finally:
        if db is not None:
            db.close()


def db_bind_email(user_id, param):
    check_user_conflict('email', param)
    db = None
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            query = "UPDATE users SET email = %s WHERE id = %s"
            cursor.execute(query, (param, user_id))
            db.commit()
    except Exception as e:
        print(f"Error binding email: {e} by user {user_id} email: {param}")
    finally:
        if db is not None:
            db.close()

def username_exists(username):
    user_id = None
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            query = "SELECT `id` FROM `users` WHERE `username` = %s;"
            params = (username,)
            cursor.execute(query, params)
            result = cursor.fetchone()
            if result:
                user_id = str(result[0])
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        db.close()
        return user_id