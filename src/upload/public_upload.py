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


def handle_user_upload(user_id, allowed_size, allowed_mimes, check_existing=False):
    if not request.files.getlist('file'):
        return jsonify({'message': 'no files uploaded'}), 400
    try:
        return file_handler(user_id=user_id, allowed_size=allowed_size,
                            allowed_mimes=allowed_mimes, check_existing=check_existing)
    except Exception as e:
        print(f"Upload Error: {str(e)}")
        return jsonify({'message': 'failed', 'error': str(e)}), 500


def file_handler(user_id, check_existing=False, allowed_size=1024 * 1024 * 10,
                 allowed_mimes={'image/jpeg', 'image/png'}):
    uploaded_files = []
    reused_count = 0
    errors = []

    # 先处理所有文件，收集信息
    file_info_list = []

    for f in request.files.getlist('file'):
        try:
            # 校验基础属性
            if f.content_length > allowed_size:
                errors.append(f'File {f.filename} size exceeds limit: {allowed_size / 1024 / 1024}MB')
                continue

            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
            f.seek(0)  # 重置文件指针

            # 校验MIME类型
            mime_type = magic.from_buffer(file_data, mime=True)
            if mime_type not in allowed_mimes:
                errors.append(f'File {f.filename} has invalid MIME type: {mime_type}')
                continue

            file_info_list.append({
                'file_obj': f,
                'filename': f.filename,
                'file_data': file_data,
                'file_hash': file_hash,
                'mime_type': mime_type,
                'file_size': len(file_data)
            })

        except Exception as e:
            errors.append(f'Error processing file {f.filename}: {str(e)}')
            continue

    # 按哈希分组，处理重复文件
    hash_groups = {}
    for file_info in file_info_list:
        hash_key = file_info['file_hash']
        if hash_key not in hash_groups:
            hash_groups[hash_key] = []
        hash_groups[hash_key].append(file_info)

    # 处理每个哈希组
    with get_db() as db:
        for file_hash, file_group in hash_groups.items():
            try:
                # 检查文件哈希是否已存在
                existing_file_hash = db.query(FileHash).filter_by(
                    hash=file_hash,
                    mime_type=file_group[0]['mime_type']
                ).first()

                if existing_file_hash:
                    # 复用已有文件 - 使用新的数据库查询获取对象
                    file_hash_obj = db.query(FileHash).filter_by(
                        hash=file_hash,
                        mime_type=file_group[0]['mime_type']
                    ).with_for_update().first()  # 加锁防止并发问题

                    if file_hash_obj:
                        storage_path = file_hash_obj.storage_path
                        print(f'Reuse existing file: {storage_path}')
                        # 增加引用计数
                        file_hash_obj.reference_count += len(file_group)
                        reused_count += len(file_group)
                    else:
                        # 如果记录被删除，重新创建
                        existing_file_hash = None

                if not existing_file_hash:
                    # 生成存储路径（哈希分片目录）
                    hash_prefix = file_hash[:2]
                    hash_subdir = os.path.join('hashed_files', hash_prefix)
                    os.makedirs(hash_subdir, exist_ok=True)

                    # 保存文件（只需要保存一次）
                    storage_path = os.path.join(hash_subdir, file_hash)
                    with open(storage_path, 'wb') as dest:
                        dest.write(file_group[0]['file_data'])

                    # 创建新的 FileHash 记录
                    file_hash_obj = FileHash(
                        hash=file_hash,
                        filename=file_group[0]['filename'],
                        file_size=file_group[0]['file_size'],
                        mime_type=file_group[0]['mime_type'],
                        storage_path=storage_path,
                        reference_count=len(file_group)
                    )
                    db.add(file_hash_obj)

                # 为组内的每个文件创建媒体记录
                for file_info in file_group:
                    if check_existing:
                        # 检查用户是否已上传过相同文件
                        existing_media = db.query(Media).filter_by(
                            user_id=user_id,
                            hash=file_hash
                        ).first()

                        if existing_media:
                            # 如果要求跳过已存在文件，则跳过
                            continue

                    # 创建媒体记录
                    new_media = Media(
                        user_id=user_id,
                        hash=file_hash,
                        original_filename=secure_filename(file_info['filename'])
                    )
                    db.add(new_media)
                    uploaded_files.append(file_info['filename'])

                db.commit()

            except Exception as e:
                db.rollback()
                errors.append(f'Error processing files with hash {file_hash}: {str(e)}')
                continue

    # 构建响应
    response_data = {
        'message': 'success' if not errors else 'partial success',
        'uploaded': uploaded_files,
        'reused': reused_count
    }

    if errors:
        response_data['errors'] = errors

    status_code = 200 if not errors else 207  # 207 Multi-Status

    return jsonify(response_data), status_code


# 可选：专门处理重复上传的函数
def handle_duplicate_upload(user_id, file_hash, filename, db_session):
    """处理重复文件上传，避免会话冲突"""
    try:
        # 使用新的查询确保对象在当前会话中
        file_hash_obj = db_session.query(FileHash).filter_by(hash=file_hash).first()

        if file_hash_obj:
            # 增加引用计数
            file_hash_obj.reference_count += 1
            db_session.add(file_hash_obj)

        # 创建媒体记录
        new_media = Media(
            user_id=user_id,
            hash=file_hash,
            original_filename=secure_filename(filename)
        )
        db_session.add(new_media)

        return True
    except Exception as e:
        print(f"Error handling duplicate upload: {e}")
        return False
