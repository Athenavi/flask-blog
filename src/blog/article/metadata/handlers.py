import datetime

from flask import jsonify, current_app, request

from src.blog.article.core.content import save_article_changes
from src.blog.article.core.crud import delete_db_article, blog_update
from src.database import get_db_connection
from src.user.entities import auth_by_uid


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
                # current_app.logger.error(f"Database update failed: {str(db_error)}",exc_info=True)
                db.rollback()

            # 如果更新失败，恢复计数器
            if not update_success:
                with counter_lock:
                    for blog_id, count in counts_snapshot.items():
                        view_counts[blog_id] += count

        except Exception as e:
            # current_app.logger.error(f"View persistence error: {str(e)}",exc_info=True)
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
        # current_app.logger.error(f"Final persist failed: {str(e)}",exc_info=True)
        db.rollback()


def api_edit_back(user_id, aid):
    # 权限验证
    if not auth_by_uid(aid, user_id):
        current_app.logger.warning(f"用户 {user_id} 尝试编辑无权限的文章 {aid}")
        return jsonify({
            'code': -1,
            'message': '无权限操作此文章',
            'show_edit_code': 'failed'
        }), 403

    try:
        # 获取并验证参数
        content = request.form.get('content', '').strip()
        if not content:
            return jsonify({
                'code': -1,
                'message': '文章内容不能为空',
                'show_edit_code': 'failed'
            }), 400

        status = request.form.get('status', 'Draft').strip()
        if status not in ['Draft', 'Published', 'Deleted']:
            return jsonify({
                'code': -1,
                'message': '无效的文章状态',
                'show_edit_code': 'failed'
            }), 400

        excerpt = (request.form.get('excerpt', '')[:145]).strip()
        hidden_status = request.form.get('hiddenStatus', '0').strip()
        if hidden_status not in ['0', '1']:
            return jsonify({
                'code': -1,
                'message': '无效的可见性设置',
                'show_edit_code': 'failed'
            }), 400

        title = request.form.get('title', '').strip() or None
        cover_image = request.files.get('coverImage')

        # 处理删除操作
        if status == 'Deleted':
            if not delete_db_article(user_id, aid):
                current_app.logger.error(f"删除文章 {aid} 的数据库记录失败")
                return jsonify({
                    'code': -1,
                    'message': '删除文章失败',
                    'show_edit_code': 'failed'
                }), 500

            current_app.logger.info(f"用户 {user_id} 成功删除文章 {aid}")
            return jsonify({
                'code': 0,
                'message': '文章已删除',
                'show_edit_code': 'deleted',
                'redirect': '/profile'
            })

        # 处理封面图片
        cover_image_path = None
        if cover_image:
            if not cover_image.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                return jsonify({
                    'code': -1,
                    'message': '仅支持PNG/JPG格式的封面图片',
                    'show_edit_code': 'failed'
                }), 400

            try:
                # 创建封面目录
                cover_image_path = os.path.join('cover', f"{aid}.png")
                os.makedirs(os.path.dirname(cover_image_path), exist_ok=True)
                with open(cover_image_path, 'wb') as f:
                    cover_image.save(f)
                current_app.logger.info(f"文章 {aid} 封面图片保存成功: {cover_image_path}")
            except Exception as e:
                current_app.logger.error(f"保存文章 {aid} 封面图片失败: {str(e)}")
                return jsonify({
                    'code': -1,
                    'message': '封面图片保存失败',
                    'show_edit_code': 'failed'
                }), 500

        # 保存文章修改
        if not save_article_changes(aid, int(hidden_status), status, cover_image_path, excerpt):
            current_app.logger.error(f"保存文章 {aid} 的基本信息失败")
            return jsonify({
                'code': -1,
                'message': '保存文章信息失败',
                'show_edit_code': 'failed'
            }), 500

        if blog_update(aid, content):
            current_app.logger.info(f"文章 {aid} 内容保存成功")

        current_app.logger.info(f"用户 {user_id} 成功编辑文章 {aid}")
        return jsonify({'show_edit_code': 'success'
                        }), 201

    except Exception as e:
        current_app.logger.error(f"保存文章 {aid} 时出错: {str(e)}", exc_info=True)
        return jsonify({
            'code': -1,
            'message': '服务器内部错误',
            'show_edit_code': 'failed'
        }), 500
