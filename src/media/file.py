import os
from pathlib import Path

from flask import jsonify, send_file

from src.database import get_db_connection
from src.media.permissions import verify_file_permissions


def get_file(base_dir: str, file_name: str, title: str):
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                # 1. 通过文章标题获取用户ID（元组索引访问）
                cursor.execute(
                    "SELECT user_id FROM articles WHERE title = %s LIMIT 1",
                    (title,)
                )
                article = cursor.fetchone()
                if not article or not article[0]:  # 使用索引[0]访问user_id
                    return jsonify({"error": "Article not found"}), 404

                # 2. 通过用户ID+文件名获取hash（元组索引访问）
                cursor.execute(
                    """SELECT hash
                       FROM media
                       WHERE user_id = %s
                         AND original_filename = %s
                       ORDER BY id DESC
                       LIMIT 1""",
                    (article[0], file_name)  # 使用article[0]
                )
                media = cursor.fetchone()
                if not media:
                    return jsonify({"error": "File not found"}), 404

                # 3. 通过hash获取文件路径（元组索引访问）
                cursor.execute(
                    "SELECT storage_path, mime_type FROM file_hashes WHERE hash = %s LIMIT 1",
                    (media[0],)  # 使用media[0]
                )
                file_record = cursor.fetchone()
                if not file_record:
                    return jsonify({"error": "File path not found"}), 404

                file_path = Path(base_dir) / file_record[0]
                return send_file(file_path, mimetype=file_record[1], max_age=7200)  # mime_type在索引1

    except Exception as e:
        # app.logger.error(e)
        return jsonify({"error": "Internal server error"}), 500

def delete_file(arg_type: str, filename: str, user_id: int, user_name: str, base_dir: str):
    if arg_type == 'article':
        db = get_db_connection()
        try:
            with db.cursor() as cursor:
                cursor.execute("DELETE FROM `articles` WHERE `Title` = %s AND `user_id` = %s", (filename, user_id))
                db.commit()
                article_path = os.path.join(base_dir, 'articles', f"{filename}.md")
                if os.path.exists(article_path):
                    os.remove(article_path)
                return jsonify({'Deleted': True}), 200
        except Exception as e:
            db.rollback()
            #app.logger.error(f"Error deleting article {filename}: {str(e)}")
            return jsonify({'Deleted': False}), 500
        finally:
            db.close()
            return None

    file_path = os.path.join('media', user_name, filename)
    if verify_file_permissions(file_path, user_name):
        os.remove(file_path) if os.path.exists(file_path) else None
        return jsonify({'filename': filename, 'Deleted': True}), 201
    else:
        #app.logger.info(f'Delete error for {filename} by user {user_id}')
        return jsonify({'filename': filename, 'Deleted': False}), 503