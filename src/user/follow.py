import threading

from flask import request, jsonify, render_template

from src.database import get_db_connection
from src.user.entities import get_user_sub_info

userFollow_lock = threading.Lock()


# 自定义LRU缓存管理器
class FollowCache:
    def __init__(self, max_size=2048):
        self.max_size = max_size
        self.cache = {}

    def get(self, user_id):
        with userFollow_lock:
            # 获取并更新最近使用
            if user_id in self.cache:
                value = self.cache.pop(user_id)
                self.cache[user_id] = value
                return value.copy()  # 返回副本防止外部修改
            return None

    def set(self, user_id, value):
        with userFollow_lock:
            if len(self.cache) >= self.max_size:
                # 移除最久未使用的条目
                self.cache.pop(next(iter(self.cache)))
            self.cache[user_id] = set(value) if value else set()

    def delete(self, user_id):
        with userFollow_lock:
            if user_id in self.cache:
                del self.cache[user_id]


follow_cache = FollowCache(max_size=2048)


def follow_user(user_id):
    current_user_id = user_id
    follow_id = request.args.get('fid')

    # 参数校验
    if not follow_id:
        return jsonify({'code': 'failed', 'message': '参数错误'}), 400

    try:
        current_user_id = int(current_user_id)
        follow_id = int(follow_id)
    except ValueError:
        return jsonify({'code': 'failed', 'message': '参数类型错误'}), 400

    # 检查自我关注
    if current_user_id == follow_id:
        return jsonify({'code': 'failed', 'message': '不能关注自己'}), 400

    db = None
    try:
        db = get_db_connection()
        cursor = db.cursor()

        # 检查是否已关注（缓存 -> 数据库）
        cached_follows = follow_cache.get(current_user_id)
        if cached_follows is not None:
            is_following = follow_id in cached_follows
        else:
            cursor.execute(
                "SELECT subscribed_user_id FROM user_subscriptions WHERE subscriber_id = %s",
                (current_user_id,)
            )
            follows = {row[0] for row in cursor.fetchall()}
            follow_cache.set(current_user_id, follows)
            is_following = follow_id in follows

        # 如果已存在关注关系
        if is_following:
            return jsonify({'code': 'success', 'message': '已关注'})

        # 执行关注操作
        cursor.execute(
            "INSERT INTO user_subscriptions (subscriber_id, subscribed_user_id) VALUES (%s, %s)",
            (current_user_id, follow_id)
        )
        db.commit()

        # 更新缓存
        if follow_cache.get(current_user_id) is not None:
            follow_cache.get(current_user_id).add(follow_id)
        else:
            follow_cache.delete(current_user_id)

        return jsonify({'code': 'success'})

    except Exception as e:
        # app.logger.error(f"系统异常: {e}")
        if db: db.rollback()
        return jsonify({'code': 'failed', 'message': '服务异常'}), 500

    finally:
        if db: db.close()


def unfollow_user(user_id):
    unfollow_id = request.args.get('fid')

    if not unfollow_id:
        return jsonify({'code': 'failed', 'message': '参数错误'})

    try:
        user_id = int(user_id)
        unfollow_id = int(unfollow_id)
    except ValueError as e:
        # app.logger.error(f"ID类型转换失败: {e}")
        return jsonify({'code': 'failed', 'message': '非法用户ID'})

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                delete_query = """
                               DELETE \
                               FROM user_subscriptions
                               WHERE subscriber_id = %s \
                                 AND subscribed_user_id = %s \
                               """
                cursor.execute(delete_query, (user_id, unfollow_id))
                affected_rows = cursor.rowcount  # 正确获取影响行数
                db.commit()

                if affected_rows > 0:
                    # 更新缓存
                    cached_data = follow_cache.get(user_id)
                    if cached_data is not None:
                        try:
                            cached_data.remove(unfollow_id)  # 使用remove确保数据一致性
                            follow_cache.set(user_id, cached_data)
                        except KeyError:
                            pass
                    else:
                        follow_cache.delete(user_id)

                    return jsonify({'code': 'success', 'message': '取关成功'})
                else:
                    return jsonify({'code': 'failed', 'message': '未找到关注关系'})

    except Exception as e:
        db.rollback()
        # app.logger.error(f"取关操作失败: {e}, 用户: {user_id}, 目标: {unfollow_id}")
        return jsonify({'code': 'failed', 'message': '服务器错误'})


def fans_follow_back(user_id, user_avatar, user_bio):
    query = "SELECT `subscribed_user_id` FROM `user_subscriptions` WHERE `subscriber_id` = %s;"
    user_sub_info = get_user_sub_info(query, user_id)
    return render_template('fans.html', sub_info=user_sub_info, avatar_url=user_avatar,
                           userBio=user_bio, page_title="我的关注")


def fans_fans_back(user_id, user_avatar, user_bio):
    query = "SELECT `subscriber_id` FROM `user_subscriptions` WHERE `subscribed_user_id` = %s"
    user_sub_info = get_user_sub_info(query, user_id)
    return render_template('fans.html', sub_info=user_sub_info, avatar_url=user_avatar,
                           userBio=user_bio, page_title="粉丝")
