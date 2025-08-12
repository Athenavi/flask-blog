import os
from datetime import datetime
from pathlib import Path
from threading import Thread

import humanize
from flask import Blueprint, request, render_template, url_for, abort, jsonify, send_file
from sqlalchemy import func

from src.database import get_db_connection
from src.media.permissions import get_media_db
from src.media.processing import generate_video_thumbnail, generate_thumbnail
from src.models import Media, FileHash, db
from src.user.authz.decorators import jwt_required
from src.utils.security.safe import is_valid_hash

media_bp = Blueprint('media', __name__, template_folder='templates')


def create_media_blueprint(cache_instance, domain, base_dir):
    @cache_instance.memoize(6)
    def get_media_cached(user_id, page=1, per_page=20):
        return get_media_db(user_id, page, per_page)

    @media_bp.route('/thumbnail', methods=['GET'])
    def media_thumbnail():
        f_hash = request.args.get('data')
        f_type = request.args.get('type')
        if not is_valid_hash(64, f_hash):
            return "Invalid file hash", 400
        thumb_path = Path(base_dir) / f"thumbnails/{f_hash}.jpg"
        thumb_dir = Path(base_dir) / "thumbnails"
        if not thumb_dir.exists():
            thumb_dir.mkdir(parents=True, exist_ok=True)

        if not thumb_path.exists():
            try:
                result = fetch_file_info_from_db(f_hash)
                if not result:
                    print("No result found for the given f_hash")
                    return "File not found", 404
                file_path = Path(base_dir) / result[3]
                thumb_path = Path(base_dir) / f"thumbnails/{f_hash}.jpg"
                if not os.path.exists(thumb_path):
                    if f_type == "video":
                        generate_video_thumbnail(file_path, thumb_path)
                    else:
                        generate_thumbnail(file_path, thumb_path)
            finally:
                return send_file(thumb_path, as_attachment=False, mimetype='image/jpeg', max_age=2592000)
        return send_file(thumb_path)

    @media_bp.route('/shared')
    def get_image_path(f_hash=None):
        if f_hash is None:
            f_hash = request.args.get('data')
        if f_hash is None:
            return "File hash not provided", 400
        if not is_valid_hash(64, f_hash):
            return "Invalid file hash", 400
        try:
            result = fetch_file_info_from_db(f_hash)
            if not result:
                print("No result found for the given f_hash")
                return "File not found", 404
            file_path = Path(base_dir) / result[3]
            return send_file(file_path, as_attachment=False, mimetype=result[2], max_age=2592000)
        except FileNotFoundError:
            abort(404)

    @cache_instance.memoize(600)
    def fetch_file_info_from_db(f_hash):
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("""
                       SELECT hash, filename, mime_type, storage_path
                       FROM file_hashes
                       WHERE hash = %s;
                       """, (f_hash,))
        return cursor.fetchone()

    @media_bp.route('/media', methods=['GET'])
    @jwt_required
    def media_v2(user_id):
        # 调试点1
        print(f"[DEBUG1] media_type: {request.args.get('type')}")

        try:
            # 确保user_id是整数
            user_id = int(user_id)
            print(f"[DEBUG2] user_id converted to int: {user_id}")

            # 构建基础查询
            base_query = Media.query.filter(Media.user_id == user_id)
            print(f"[DEBUG3] Base query created")

            # 添加join
            query = base_query.join(FileHash, Media.hash == FileHash.hash)
            print(f"[DEBUG4] Join added to query")

            # 类型过滤
            media_type = request.args.get('type') or 'all'
            if media_type == 'image':
                query = query.filter(FileHash.mime_type.startswith('image'))
            elif media_type == 'video':
                query = query.filter(FileHash.mime_type.startswith('video'))
            print(f"[DEBUG5] Type filter applied: {media_type}")

            # 分页
            page = request.args.get('page', 1, type=int)
            per_page = 20
            pagination = query.order_by(Media.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )
            media_files = pagination.items
            print(f"[DEBUG6] Pagination complete. Items: {len(media_files)}")

            # 统计信息
            storage_used_query = db.session.query(func.sum(FileHash.file_size)) \
                                     .join(Media, Media.hash == FileHash.hash) \
                                     .filter(Media.user_id == user_id) \
                                     .scalar() or 0

            storage_total_bytes = 50 * 1024 * 1024 * 1024
            storage_percentage = min(100, int(storage_used_query / storage_total_bytes * 100))

            stats = {
                'image_count': Media.query.filter_by(user_id=user_id)
                .join(FileHash)
                .filter(FileHash.mime_type.startswith('image'))
                .count(),
                'video_count': Media.query.filter_by(user_id=user_id)
                .join(FileHash)
                .filter(FileHash.mime_type.startswith('video'))
                .count(),
                'storage_used': humanize.naturalsize(storage_used_query),
                'storage_total': '50 GB',
                'storage_percentage': storage_percentage
            }

            print(f"[DEBUG7] Stats calculated")
            return render_template('media.html',
                                   title='媒体库',
                                   media_files=media_files,
                                   pagination=pagination,
                                   media_type=media_type,
                                   stats=stats,
                                   current_year=datetime.now().year)

        except Exception as e:
            import traceback
            print(f"[FATAL ERROR] {str(e)}\n{traceback.format_exc()}")
            return f"Server Error: {str(e)}", 500

    @media_bp.route('/media', methods=['DELETE'])
    @jwt_required
    def media_delete(user_id, file_ids):
        try:
            if not file_ids:
                file_ids = request.args.get('file-id-list', '')
            if not file_ids:
                return jsonify({"message": "缺少文件ID列表"}), 400
            id_list = [int(media_id) for media_id in file_ids.split(',') if media_id.isdigit()]
            if len(id_list) != len(file_ids.split(',')):
                return jsonify({"message": "文件ID格式错误"}), 400

            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    conn.autocommit = False

                    try:
                        # 1. 查询要删除的文件信息（加锁）
                        placeholders = ', '.join(['%s'] * len(id_list))
                        cursor.execute(f"""
                            SELECT m.id, m.hash, fh.storage_path 
                            FROM media m
                            JOIN file_hashes fh ON m.hash = fh.hash
                            WHERE m.id IN ({placeholders}) AND m.user_id = %s
                            FOR UPDATE
                        """, id_list + [user_id])

                        target_files = cursor.fetchall()
                        if len(target_files) != len(id_list):
                            conn.rollback()
                            return jsonify({"message": "部分文件不存在或无权操作"}), 400

                        # 2. 执行删除操作
                        cursor.execute(f"""
                            DELETE FROM media 
                            WHERE id IN ({placeholders}) AND user_id = %s
                        """, id_list + [user_id])
                        deleted_count = cursor.rowcount

                        # 3. 减少引用计数（不等待检查结果）
                        file_hashes_to_check = set()
                        for file in target_files:
                            file_id, file_hash, storage_path = file
                            cursor.execute("""
                                           UPDATE file_hashes
                                           SET reference_count = GREATEST(0, reference_count - 1)
                                           WHERE hash = %s
                                           """, (file_hash,))
                            file_hashes_to_check.add((file_hash, storage_path))

                        # 提交主事务
                        conn.commit()

                        # 启动后台清理线程
                        if file_hashes_to_check:
                            Thread(target=async_file_cleanup, args=(file_hashes_to_check,)).start()

                        return jsonify({
                            "message": "删除请求已接受",
                            "deleted_records": deleted_count,
                            "note": "文件清理将在后台执行"
                        }), 202  # 202 Accepted

                    except Exception as e:
                        conn.rollback()
                        print(f"数据库操作失败: {str(e)}")
                        return jsonify({"message": "服务器错误", "error": str(e)}), 500

        except Exception as e:
            print(f"请求处理异常: {str(e)}")
            return jsonify({"message": "服务器错误", "error": str(e)}), 500

    def async_file_cleanup(file_hashes_to_check):
        """后台线程执行的清理任务"""
        try:
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    pending_file_deletions = []

                    # 检查需要物理删除的文件
                    for file_hash, storage_path in file_hashes_to_check:
                        cursor.execute("""
                                       SELECT reference_count
                                       FROM file_hashes
                                       WHERE hash = %s
                                       """, (file_hash,))
                        result = cursor.fetchone()

                        if result and result[0] == 0:
                            cursor.execute("""
                                           DELETE
                                           FROM file_hashes
                                           WHERE hash = %s
                                           """, (file_hash,))
                            pending_file_deletions.append(storage_path)

                    conn.commit()

                    # 物理删除文件
                    for file_path in pending_file_deletions:
                        try:
                            if os.path.exists(file_path):
                                os.remove(file_path)
                        except Exception as e:
                            print(f"后台文件删除失败: {file_path} - {str(e)}")

        except Exception as e:
            print(f"后台清理任务失败: {str(e)}")

    @media_bp.route('/api/media/<int:id>', methods=['DELETE'])
    @jwt_required
    def mei_delete_api(user_id, id):
        id_list = str(id)
        print(f"mei_delete_api - user_id: {user_id}, id_list: {id_list}")  # 添加调试信息
        return media_delete(user_id, id_list)

    return media_bp
