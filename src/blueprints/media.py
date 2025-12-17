import os
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from threading import Thread

import humanize
from flask import Blueprint, request, render_template, abort, jsonify, send_file, current_app
from sqlalchemy import func

from src.auth_utils import jwt_required
# from src.database import get_db
from src.extensions import cache
from src.models import Media, FileHash, db
from src.models.user import User
from src.setting import AppConfig, BaseConfig
from src.utils.image.processing import generate_video_thumbnail, generate_thumbnail
from src.utils.security.safe import is_valid_hash

media_bp = Blueprint('media', __name__, template_folder='templates')

base_dir = AppConfig.base_dir


@cache.memoize(60)
def get_user_storage_used(user_id):
    used_storage = db.session.query(func.sum(FileHash.file_size)) \
                       .join(Media, Media.hash == FileHash.hash) \
                       .filter(Media.user_id == user_id) \
                       .scalar() or 0
    return used_storage

@cache.memoize(60)
def get_user_storage_limit(user_id):
    """
    根据用户VIP等级获取存储限制
    普通用户: 512MB
    VIP 1级: 1GB
    VIP 2级: 5GB
    VIP 3级: 20GB
    """
    user = User.query.get(user_id)
    if not user:
        return BaseConfig.USER_FREE_STORAGE_LIMIT
        
    # 基础免费空间
    base_limit = BaseConfig.USER_FREE_STORAGE_LIMIT  # 512MB
    
    # 根据VIP等级增加存储空间
    if user.vip_level == 1:
        return base_limit * 2  # 1GB
    elif user.vip_level == 2:
        return base_limit * 10  # 5GB
    elif user.vip_level >= 3:
        return base_limit * 40  # 20GB
    else:
        return base_limit  # 512MB for non-VIP users


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
            file_hash = FileHash.query.filter_by(hash=f_hash).first()
            if not file_hash:
                print("No result found for the given f_hash")
                return "File not found", 404
            file_path = Path(base_dir) / file_hash.storage_path
            thumb_path = Path(base_dir) / f"thumbnails/{f_hash}.jpg"
            if not os.path.exists(thumb_path):
                if f_type == "video":
                    generate_video_thumbnail(file_path, thumb_path)
                else:
                    generate_thumbnail(file_path, thumb_path)
        except Exception as e:
            # 处理异常但不阻止发送文件
            print(f"Error generating thumbnail: {e}")
    
    # 总是尝试发送缩略图文件
    if thumb_path.exists():
        return send_file(thumb_path, as_attachment=False, mimetype='image/jpeg', max_age=2592000)
    else:
        return "Thumbnail not found", 404


@media_bp.route('/shared', methods=['GET'])
def media_shared():
    f_hash = request.args.get('data')
    if not is_valid_hash(64, f_hash):
        return "Invalid file hash", 400
    try:
        file_hash = FileHash.query.filter_by(hash=f_hash).first()
        if not file_hash:
            print("No result found for the given f_hash")
            return "File not found", 404
        file_path = Path(base_dir) / file_hash.storage_path
        return send_file(file_path, as_attachment=False, mimetype=file_hash.mime_type, max_age=2592000)
    except FileNotFoundError:
        abort(404)


@media_bp.route('/media', methods=['GET'])
@jwt_required
def media_v2(user_id):
    try:
        user_id = int(user_id)
        base_query = Media.query.filter(Media.user_id == user_id)
        query = base_query.join(FileHash, Media.hash == FileHash.hash)

        media_type = request.args.get('type') or 'all'
        if media_type == 'image':
            query = query.filter(FileHash.mime_type.startswith('image'))
        elif media_type == 'video':
            query = query.filter(FileHash.mime_type.startswith('video'))
        # print(f"[DEBUG5] Type filter applied: {media_type}")

        page = request.args.get('page', 1, type=int)
        per_page = 20
        pagination = query.order_by(Media.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        media_files = pagination.items

        storage_used_query = get_user_storage_used(user_id)
        storage_total_bytes = Decimal(str(get_user_storage_limit(user_id)))
        
        # 修复：允许显示超过100%的存储使用百分比
        storage_percentage = int(storage_used_query / storage_total_bytes * 100)
        can_be_uploaded = bool(storage_total_bytes - storage_used_query > 1024)
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
            'storage_total': convert_storage_size(storage_total_bytes),
            'storage_percentage': storage_percentage,
            'canBeUploaded': can_be_uploaded,
            'totalUsed': storage_used_query  # 添加这一行以修复模板中的引用
        }

        return render_template('media.html',
                               title='媒体库',
                               media_files=media_files,
                               pagination=pagination,
                               media_type=media_type,
                               stats=stats,
                               current_year=datetime.now().year)

    except Exception as e:
        import traceback
        return f"Server Error: {str(e)}", 500


def convert_storage_size(total_bytes):
    """
    将字节数转换为GB、MB或KB的字符串表示。

    :param total_bytes: 存储大小的字节数
    :return: 存储大小的字符串表示，单位为GB、MB或KB
    """
    gb_factor = Decimal('1073741824')  # 1024 * 1024 * 1024
    mb_factor = Decimal('1048576')  # 1024 * 1024
    kb_factor = Decimal('1024')  # 1024

    # 统一转换为 Decimal
    total_bytes = Decimal(str(total_bytes))

    if total_bytes >= gb_factor:
        size_in_gb = total_bytes / gb_factor
        return f"{int(size_in_gb)} GB"
    elif total_bytes >= mb_factor:
        size_in_mb = total_bytes / mb_factor
        return f"{int(size_in_mb)} MB"
    else:
        size_in_kb = total_bytes / kb_factor
        return f"{int(size_in_kb)} KB"


@media_bp.route('/media', methods=['DELETE'])
@jwt_required
def media_delete(user_id):
    try:
        file_ids = request.args.get('file-id-list', '')
        if not file_ids:
            return jsonify({"message": "缺少文件ID列表"}), 400

        try:
            id_list = [int(media_id) for media_id in file_ids.split(',')]
        except ValueError:
            return jsonify({"message": "文件ID包含非法字符"}), 400

        try:
            # 使用 with_for_update 锁定记录，避免并发问题
            target_files = db.session.query(Media).filter(
                Media.id.in_(id_list),
                Media.user_id == user_id
            ).with_for_update().all()

            if len(target_files) != len(id_list):
                return jsonify({
                    "message": f"找到{len(target_files)}个文件，请求{len(id_list)}个",
                    "hint": "可能文件不存在或无权访问"
                }), 403

            # 收集需要清理的信息
            cleanup_data = []
            media_hashes = []  # 收集所有涉及的hash
            valid_target_files = []  # 只处理hash不为null的记录

            # 第一步：先检查所有记录的hash是否有效，过滤掉hash为null的记录
            for media_file in target_files:
                if media_file.hash is not None:
                    media_hashes.append(media_file.hash)
                    valid_target_files.append(media_file)
                else:
                    current_app.logger.warning(f"跳过hash为null的媒体记录: ID={media_file.id}")

            # 如果没有有效的记录，直接返回
            if not valid_target_files:
                return jsonify({"message": "没有有效的媒体记录可删除"}), 400

            # 第二步：批量查询FileHash对象，确保它们属于当前会话
            file_hashes = db.session.query(FileHash).filter(
                FileHash.hash.in_(media_hashes)
            ).with_for_update().all()

            # 创建hash到对象的映射
            file_hash_map = {fh.hash: fh for fh in file_hashes}

            # 第三步：执行删除和更新操作
            for media_file in valid_target_files:
                db.session.delete(media_file)

                file_hash_obj = file_hash_map.get(media_file.hash)
                if file_hash_obj:
                    file_hash_obj.reference_count -= 1
                    if file_hash_obj.reference_count == 0:
                        cleanup_data.append({
                            'hash': file_hash_obj.hash,
                            'storage_path': file_hash_obj.storage_path
                        })
                        db.session.delete(file_hash_obj)

            # 提交所有更改
            db.session.commit()

            # 启动后台清理
            if cleanup_data:
                Thread(target=async_file_cleanup,
                       args=(current_app._get_current_object(), cleanup_data)).start()

            return jsonify({
                "deleted_count": len(valid_target_files),
                "message": "删除成功，后台清理中"
            }), 200

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"删除失败: {str(e)}")
            return jsonify({"message": "数据库操作失败"}), 500

    except Exception as e:
        current_app.logger.error(f"请求处理异常: {str(e)}")
        return jsonify({"message": "服务器内部错误"}), 500


def async_file_cleanup(app, cleanup_data):
    """后台线程执行的清理任务"""
    try:
        for file_info in cleanup_data:
            storage_path = file_info['storage_path']
            # 只进行文件清理，不在后台进行数据库操作
            try:
                if os.path.exists(storage_path):
                    os.remove(storage_path)
                    app.logger.info(f"成功删除文件: {storage_path}")
                else:
                    app.logger.warning(f"文件不存在: {storage_path}")
            except Exception as e:
                app.logger.error(f"文件删除失败: {storage_path} - {str(e)}")

    except Exception as e:
        app.logger.error(f"后台清理任务失败: {str(e)}")