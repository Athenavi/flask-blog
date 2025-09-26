import hashlib
import os
import shutil
import uuid

import magic
from flask import jsonify, request
from werkzeug.utils import secure_filename

from src.database import get_db
from src.models import Media, FileHash
from src.utils.shortener.links import create_special_url


def handle_user_upload(user_id, allowed_size, allowed_mimes, check_existing=False):
    if not request.files.getlist('file'):
        return jsonify({'message': 'no files uploaded'}), 400
    try:
        return file_handler(user_id=user_id, allowed_size=allowed_size, allowed_mimes=allowed_mimes,
                            check_existing=check_existing)
    except Exception as e:
        print(f"Upload Error: {str(e)}")
        return jsonify({'message': 'failed', 'error': str(e)}), 500


def upload_cover_back(user_id, base_path, domain):
    if 'cover_image' not in request.files:
        return jsonify({"code": 400, "msg": "未上传文件"}), 400

    file = request.files['cover_image']

    if file.filename == '':
        return jsonify({"code": 400, "msg": "文件名为空"}), 400

    if file:
        allowed_mimes = {'image/jpeg', 'image/png'}
        if file.mimetype not in allowed_mimes:
            return jsonify({"error": f"Unsupported file type: {file.mimetype}"}), 415

        # 1. 先上传到临时的cover目录
        temp_filename = str(uuid.uuid4()) + '.png'
        temp_file_path = os.path.join(base_path, temp_filename)
        os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
        file.save(temp_file_path)

        try:
            # 2. 复用file_handler将其上传到用户媒体库并记录
            result = process_file_with_handler(user_id, temp_file_path, file.filename, allowed_size=1024 * 1024 * 8,
                                               allowed_mimes=allowed_mimes)

            if result.get('success'):
                s_url = create_special_url(
                    long_url=(domain + "thumbnail?data=" + result.get('hash')),
                    user_id=user_id)
                cover_url = ("/s/" + s_url)
                return jsonify({"code": 200, "msg": "上传成功", "data": cover_url}), 200
            else:
                # 如果文件处理失败，删除临时文件
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
                return jsonify({"code": 500, "msg": "文件处理失败", "error": result.get('error')}), 500

        except Exception as e:
            # 发生异常时清理临时文件
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            print(f"Cover upload error: {str(e)}")
            return jsonify({"code": 500, "msg": "上传失败", "error": str(e)}), 500

    else:
        return jsonify({"code": 400, "msg": "文件类型不支持"}), 400


def process_file_with_handler(user_id, file_path, original_filename, allowed_size, allowed_mimes):
    """
    复用file_handler逻辑处理单个文件
    """
    with get_db() as db:
        try:
            # 读取文件内容
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # 计算文件哈希
            file_hash = hashlib.sha256(file_data).hexdigest()

            # 校验MIME类型
            mime_type = magic.from_buffer(file_data, mime=True)
            if mime_type not in allowed_mimes:
                return {'success': False, 'error': f'Invalid MIME type: {mime_type}'}

            # 检查文件大小
            file_size = len(file_data)
            if file_size > allowed_size:
                return {'success': False, 'error': f'File size exceeds limit: {allowed_size}'}

            # 检查文件哈希是否已存在
            existing_file_hash = FileHash.query.filter_by(
                hash=file_hash,
                mime_type=mime_type
            ).first()

            if existing_file_hash:
                return {'success': True, 'hash': file_hash}
            else:
                # 生成存储路径（哈希分片目录）
                hash_prefix = file_hash[:2]
                hash_subdir = os.path.join('hashed_files', hash_prefix)
                os.makedirs(hash_subdir, exist_ok=True)

                # 保存文件到最终位置
                storage_path = os.path.join(hash_subdir, file_hash)
                shutil.copy2(file_path, storage_path)  # 复制文件，保留元数据

                # 创建新的 FileHash 记录
                new_file_hash = FileHash(
                    hash=file_hash,
                    filename=original_filename,
                    file_size=file_size,
                    mime_type=mime_type,
                    storage_path=storage_path,
                    reference_count=1
                )
                db.add(new_file_hash)

            # 创建媒体记录
            try:
                # 检查是否已存在相同的用户媒体记录
                existing_media = Media.query.filter_by(
                    user_id=user_id,
                    hash=file_hash
                ).first()

                if not existing_media:
                    new_media = Media(
                        user_id=user_id,
                        hash=file_hash,
                        original_filename=secure_filename(original_filename)
                    )
                    db.add(new_media)
                return {'success': True, 'hash': file_hash}

            except Exception as e:
                db.rollback()
                return {'success': False, 'error': f'Database error: {str(e)}'}

        except Exception as e:
            db.rollback()
            return {'success': False, 'error': str(e)}


def file_handler(user_id, check_existing=False, allowed_size=1024 * 1024 * 10,
                 allowed_mimes={'image/jpeg', 'image/png'}):
    with get_db() as db:
        uploaded_files = []
        reused_count = 0

        for f in request.files.getlist('file'):
            # 校验基础属性
            if f.content_length > allowed_size:
                return jsonify({'message': f'File size exceeds limit: {allowed_size / 1024 / 1024}MB'}), 413

            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
            f.seek(0)  # 重置文件指针

            if check_existing:
                # 检查用户是否已上传过相同文件
                existing_media = Media.query.filter_by(
                    user_id=user_id,
                    hash=file_hash
                ).first()

                if existing_media:
                    # 根据需求决定是否跳过已存在文件
                    pass

            # 校验MIME类型
            mime_type = magic.from_buffer(file_data, mime=True)
            if mime_type not in allowed_mimes:
                print(f'Rejected: User {user_id}, Invalid MIME {mime_type}')
                continue

            # 检查文件哈希是否已存在
            existing_file_hash = FileHash.query.filter_by(
                hash=file_hash,
                mime_type=mime_type
            ).first()

            if existing_file_hash:
                # 复用已有文件
                storage_path = existing_file_hash.storage_path
                print(f'Reuse existing file: {storage_path}')
                # 增加引用计数
                existing_file_hash.reference_count += 1
                db.add(existing_file_hash)
                reused_count += 1
            else:
                # 生成存储路径（哈希分片目录）
                hash_prefix = file_hash[:2]
                hash_subdir = os.path.join('hashed_files', hash_prefix)
                os.makedirs(hash_subdir, exist_ok=True)

                # 保存文件
                filename = f.filename
                storage_path = os.path.join(hash_subdir, file_hash)
                with open(storage_path, 'wb') as dest:
                    dest.write(file_data)

                # 创建新的 FileHash 记录
                new_file_hash = FileHash(
                    hash=file_hash,
                    filename=filename,
                    file_size=len(file_data),
                    mime_type=mime_type,
                    storage_path=storage_path,
                    reference_count=1
                )
                db.add(new_file_hash)

            # 创建媒体记录
            try:
                new_media = Media(
                    user_id=user_id,
                    hash=file_hash,
                    original_filename=secure_filename(f.filename)
                )
                db.add(new_media)
                uploaded_files.append(f.filename)
            except Exception as e:
                print(f'Error inserting media record: {e}')
                db.rollback()
                continue

        db.commit()
        return jsonify({
            'message': 'success',
            'uploaded': uploaded_files,
            'reused': reused_count
        }), 200
