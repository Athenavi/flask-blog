import hashlib
import os
import shutil
import uuid

import magic
from flask import jsonify, request
from werkzeug.utils import secure_filename

from src.auth import jwt_required
from src.database import get_db
from src.models import Media, FileHash, UploadChunk, UploadTask
from src.utils.shortener.links import create_special_url


class FileProcessor:
    """文件处理器，统一处理文件上传逻辑"""

    def __init__(self, user_id, allowed_mimes=None, allowed_size=10 * 1024 * 1024):
        self.user_id = user_id
        self.allowed_mimes = allowed_mimes or {'image/jpeg', 'image/png'}
        self.allowed_size = allowed_size

    def validate_file(self, file_data, filename):
        """验证文件基本属性"""
        if not filename:
            return False, "文件名为空"

        mime_type = magic.from_buffer(file_data, mime=True)
        if mime_type not in self.allowed_mimes:
            return False, f"不支持的文件类型: {mime_type}"

        file_size = len(file_data)
        if file_size > self.allowed_size:
            return False, f"文件大小超过限制: {self.allowed_size / 1024 / 1024}MB"

        return True, {"mime_type": mime_type, "file_size": file_size}

    def calculate_hash(self, file_data):
        """计算文件哈希"""
        return hashlib.sha256(file_data).hexdigest()

    def save_file(self, file_hash, file_data, original_filename):
        """保存文件到存储系统"""
        print(f"save file: {original_filename}")
        hash_prefix = file_hash[:2]
        hash_subdir = os.path.join('hashed_files', hash_prefix)
        os.makedirs(hash_subdir, exist_ok=True)

        storage_path = os.path.join(hash_subdir, file_hash)
        with open(storage_path, 'wb') as f:
            f.write(file_data)

        return storage_path

    def create_file_hash_record(self, db, file_hash, filename, file_size, mime_type, storage_path, reference_count=1):
        """创建文件哈希记录"""
        # 使用当前会话查询，避免会话冲突
        existing = db.query(FileHash).filter_by(hash=file_hash, mime_type=mime_type).first()
        if existing:
            existing.reference_count += reference_count
            return existing

        new_file_hash = FileHash(
            hash=file_hash,
            filename=filename,
            file_size=file_size,
            mime_type=mime_type,
            storage_path=storage_path,
            reference_count=reference_count
        )
        db.add(new_file_hash)
        return new_file_hash

    def create_media_record(self, db, file_hash, filename, check_existing=False):
        """创建媒体记录"""
        if check_existing:
            existing = db.query(Media).filter_by(user_id=self.user_id, hash=file_hash).first()
            if existing:
                return existing

        new_media = Media(
            user_id=self.user_id,
            hash=file_hash,
            original_filename=secure_filename(filename)
        )
        db.add(new_media)
        return new_media


class ChunkedUploadProcessor:
    """分块上传处理器"""

    def __init__(self, user_id, chunk_size=5 * 1024 * 1024):  # 默认5MB每块
        self.user_id = user_id
        self.chunk_size = chunk_size
        self.temp_dir = "upload_chunks"
        os.makedirs(self.temp_dir, exist_ok=True)

    def init_upload(self, filename, total_size, total_chunks, file_hash=None, existing_upload_id=None):
        """初始化上传任务，支持断点续传"""
        with get_db() as db:
            try:
                # 如果提供了现有的upload_id，检查是否可以进行断点续传
                if existing_upload_id:
                    # 使用当前会话查询现有任务
                    existing_task = db.query(UploadTask).filter_by(
                        id=existing_upload_id,
                        user_id=self.user_id,
                        filename=filename,
                        total_size=total_size,
                        total_chunks=total_chunks
                    ).first()

                    if existing_task:
                        # 获取已上传的分块信息
                        uploaded_chunks = db.query(UploadChunk.chunk_index).filter_by(
                            upload_id=existing_upload_id
                        ).all()
                        uploaded_chunk_indices = [chunk.chunk_index for chunk in uploaded_chunks]

                        return {
                            'success': True,
                            'upload_id': existing_upload_id,
                            'file_exists': False,
                            'resume_upload': True,
                            'uploaded_chunks': uploaded_chunk_indices,
                            'uploaded_count': len(uploaded_chunk_indices),
                            'total_chunks': total_chunks
                        }

                upload_id = str(uuid.uuid4())

                # 如果提供了文件哈希，检查是否已存在
                if file_hash:
                    # 使用当前会话查询
                    existing_file = db.query(FileHash).filter_by(hash=file_hash).first()
                    if existing_file:
                        # 为用户创建媒体记录
                        file_processor = FileProcessor(self.user_id)
                        media_record = file_processor.create_media_record(db, file_hash, filename, check_existing=True)

                        # 增加文件哈希的引用计数
                        existing_file.reference_count += 1

                        db.commit()
                        
                        return {
                            'success': True,
                            'upload_id': upload_id,
                            'file_exists': True,
                            'file_hash': file_hash,
                            'media_id': media_record.id,
                            'instant': True
                        }

                # 检查是否有相同文件名和用户正在进行中的上传任务
                existing_task = db.query(UploadTask).filter_by(
                    user_id=self.user_id,
                    filename=filename,
                    status='initialized'
                ).first() or db.query(UploadTask).filter_by(
                    user_id=self.user_id,
                    filename=filename,
                    status='uploading'
                ).first()
                
                if existing_task:
                    # 获取已上传的分块信息
                    uploaded_chunks = db.query(UploadChunk.chunk_index).filter_by(
                        upload_id=existing_task.id
                    ).all()
                    uploaded_chunk_indices = [chunk.chunk_index for chunk in uploaded_chunks]
                    
                    # 更新任务状态为上传中
                    existing_task.status = 'uploading'
                    db.commit()
                    
                    return {
                        'success': True,
                        'upload_id': existing_task.id,
                        'file_exists': False,
                        'resume_upload': True,
                        'uploaded_chunks': uploaded_chunk_indices,
                        'uploaded_count': len(uploaded_chunk_indices),
                        'total_chunks': existing_task.total_chunks
                    }

                task = UploadTask(
                    id=upload_id,
                    user_id=self.user_id,
                    filename=filename,
                    total_size=total_size,
                    total_chunks=total_chunks,
                    uploaded_chunks=0,
                    file_hash=file_hash,
                    status='initialized'
                )
                db.add(task)
                db.commit()

                return {
                    'success': True,
                    'upload_id': upload_id,
                    'file_exists': False,
                    'resume_upload': False
                }
            except Exception as e:
                db.rollback()
                return {'success': False, 'error': str(e)}

    def upload_chunk(self, upload_id, chunk_index, chunk_data, chunk_hash):
        """上传单个分块"""
        with get_db() as db:
            try:
                # 获取上传任务 - 使用当前会话查询
                task = db.query(UploadTask).filter_by(id=upload_id, user_id=self.user_id).first()
                if not task:
                    return {'success': False, 'error': '上传任务不存在'}

                # 检查分块是否已上传 - 使用当前会话查询
                existing_chunk = db.query(UploadChunk).filter_by(
                    upload_id=upload_id,
                    chunk_index=chunk_index
                ).first()

                if existing_chunk:
                    # 验证分块哈希是否匹配
                    if existing_chunk.chunk_hash != chunk_hash:
                        return {'success': False, 'error': '分块哈希不匹配'}
                    return {'success': True, 'message': '分块已存在'}

                # 保存分块文件
                chunk_filename = f"{upload_id}_{chunk_index}.chunk"
                chunk_path = os.path.join(self.temp_dir, chunk_filename)
                
                # 确保目录存在
                os.makedirs(os.path.dirname(chunk_path), exist_ok=True)

                with open(chunk_path, 'wb') as f:
                    f.write(chunk_data)

                # 记录分块信息
                chunk_record = UploadChunk(
                    upload_id=upload_id,
                    chunk_index=chunk_index,
                    chunk_hash=chunk_hash,
                    chunk_size=len(chunk_data),
                    chunk_path=chunk_path
                )
                db.add(chunk_record)

                # 更新任务进度
                task.uploaded_chunks += 1
                task.status = 'uploading'
                db.commit()

                return {'success': True, 'message': '分块上传成功'}

            except Exception as e:
                db.rollback()
                # 记录详细的错误信息
                import traceback
                error_details = f"分块 {chunk_index} 上传失败: {str(e)}\n{traceback.format_exc()}"
                print(error_details)  # 输出到日志
                return {'success': False, 'error': error_details}

    def get_upload_progress(self, upload_id):
        """获取上传进度"""
        with get_db() as db:
            # 使用当前会话查询
            task = db.query(UploadTask).filter_by(id=upload_id, user_id=self.user_id).first()
            if not task:
                return {'success': False, 'error': '上传任务不存在'}

            uploaded_chunks = db.query(UploadChunk).filter_by(upload_id=upload_id).count()

            return {
                'success': True,
                'upload_id': upload_id,
                'total_chunks': task.total_chunks,
                'uploaded_chunks': uploaded_chunks,
                'progress': round((uploaded_chunks / task.total_chunks) * 100, 2) if task.total_chunks > 0 else 0,
                'status': task.status
            }

    def complete_upload(self, upload_id, file_hash, mime_type):
        """完成上传，合并所有分块"""
        with get_db() as db:
            try:
                # 使用当前会话查询
                task = db.query(UploadTask).filter_by(id=upload_id, user_id=self.user_id).first()
                if not task:
                    return {'success': False, 'error': '上传任务不存在'}

                # 检查是否所有分块都已上传
                uploaded_count = db.query(UploadChunk).filter_by(upload_id=upload_id).count()
                if uploaded_count != task.total_chunks:
                    return {
                        'success': False,
                        'error': f'分块不完整: {uploaded_count}/{task.total_chunks}'
                    }

                # 获取所有分块并按索引排序 - 使用当前会话查询
                chunks = db.query(UploadChunk).filter_by(upload_id=upload_id).order_by(UploadChunk.chunk_index).all()

                # 合并分块
                merged_file_path = os.path.join(self.temp_dir, f"{upload_id}_merged")
                
                # 确保目录存在
                os.makedirs(os.path.dirname(merged_file_path), exist_ok=True)
                
                with open(merged_file_path, 'wb') as merged_file:
                    for chunk in chunks:
                        # 检查分块文件是否存在
                        if not os.path.exists(chunk.chunk_path):
                            return {'success': False, 'error': f'分块文件不存在: {chunk.chunk_path}'}
                            
                        with open(chunk.chunk_path, 'rb') as chunk_file:
                            shutil.copyfileobj(chunk_file, merged_file)

                # 验证最终文件哈希
                with open(merged_file_path, 'rb') as f:
                    final_hash = hashlib.sha256(f.read()).hexdigest()

                if final_hash != file_hash:
                    # 清理临时文件
                    if os.path.exists(merged_file_path):
                        os.remove(merged_file_path)
                    return {'success': False, 'error': '文件哈希验证失败'}

                # 读取合并后的文件数据
                with open(merged_file_path, 'rb') as f:
                    file_data = f.read()

                # 保存到最终位置
                processor = FileProcessor(self.user_id)
                storage_path = processor.save_file(file_hash, file_data, task.filename)

                # 创建文件记录
                file_hash_record = processor.create_file_hash_record(
                    db, file_hash, task.filename, task.total_size, mime_type, storage_path
                )

                # 创建媒体记录
                processor.create_media_record(db, file_hash, task.filename)

                # 更新任务状态
                task.status = 'completed'
                task.file_hash = file_hash

                # 清理分块文件
                for chunk in chunks:
                    if os.path.exists(chunk.chunk_path):
                        os.remove(chunk.chunk_path)
                    db.delete(chunk)

                # 清理合并的临时文件
                if os.path.exists(merged_file_path):
                    os.remove(merged_file_path)

                db.commit()

                return {
                    'success': True,
                    'file_hash': file_hash,
                    'message': '文件上传完成'
                }

            except Exception as e:
                db.rollback()
                # 清理临时文件
                if 'merged_file_path' in locals() and os.path.exists(merged_file_path):
                    os.remove(merged_file_path)
                # 记录详细错误信息
                import traceback
                error_details = f"完成上传失败: {str(e)}\n{traceback.format_exc()}"
                print(error_details)
                return {'success': False, 'error': error_details}

    def get_uploaded_chunks(self, upload_id):
        """获取已上传的分块列表"""
        with get_db() as db:
            try:
                # 检查上传任务是否存在
                task = db.query(UploadTask).filter_by(id=upload_id, user_id=self.user_id).first()
                if not task:
                    return {'success': False, 'error': '上传任务不存在'}

                # 获取已上传的分块信息
                uploaded_chunks = db.query(UploadChunk.chunk_index, UploadChunk.chunk_hash,
                                           UploadChunk.chunk_size).filter_by(
                    upload_id=upload_id
                ).order_by(UploadChunk.chunk_index).all()

                uploaded_chunk_list = [
                    {
                        'chunk_index': chunk.chunk_index,
                        'chunk_hash': chunk.chunk_hash,
                        'chunk_size': chunk.chunk_size
                    }
                    for chunk in uploaded_chunks
                ]

                return {
                    'success': True,
                    'upload_id': upload_id,
                    'uploaded_chunks': uploaded_chunk_list,
                    'uploaded_count': len(uploaded_chunk_list),
                    'total_chunks': task.total_chunks,
                    'progress': round((len(uploaded_chunk_list) / task.total_chunks) * 100,
                                      2) if task.total_chunks > 0 else 0
                }

            except Exception as e:
                return {'success': False, 'error': str(e)}

    def cancel_upload(self, upload_id):
        """取消上传任务"""
        with get_db() as db:
            try:
                # 使用当前会话查询
                task = db.query(UploadTask).filter_by(id=upload_id, user_id=self.user_id).first()
                if not task:
                    return {'success': False, 'error': '上传任务不存在'}

                # 删除所有分块文件 - 使用当前会话查询
                chunks = db.query(UploadChunk).filter_by(upload_id=upload_id).all()
                for chunk in chunks:
                    if os.path.exists(chunk.chunk_path):
                        os.remove(chunk.chunk_path)
                    db.delete(chunk)

                # 删除任务记录
                db.delete(task)
                db.commit()

                return {'success': True, 'message': '上传任务已取消'}

            except Exception as e:
                db.rollback()
                return {'success': False, 'error': str(e)}


# 原有的小文件上传函数保持不变
def upload_cover_back(user_id, base_path, domain):
    """上传封面图片（小文件）"""
    if 'cover_image' not in request.files:
        return jsonify({"code": 400, "msg": "未上传文件"}), 400

    file = request.files['cover_image']
    if not file or file.filename == '':
        return jsonify({"code": 400, "msg": "文件名为空"}), 400

    # 保存临时文件
    temp_filename = str(uuid.uuid4()) + '.png'
    temp_file_path = os.path.join(base_path, temp_filename)
    os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
    file.save(temp_file_path)

    try:
        # 处理文件
        with open(temp_file_path, 'rb') as f:
            file_data = f.read()

        processor = FileProcessor(user_id, allowed_size=8 * 1024 * 1024)
        result = _process_single_file(processor, file_data, file.filename)

        if result['success']:
            s_url = create_special_url(
                domain + "thumbnail?data=" + result['hash'],
                user_id=user_id
            )
            cover_url = "/s/" + s_url
            return jsonify({"code": 200, "msg": "上传成功", "data": cover_url}), 200
        else:
            return jsonify({"code": 500, "msg": "文件处理失败", "error": result['error']}), 500

    except Exception as e:
        return jsonify({"code": 500, "msg": "上传失败", "error": str(e)}), 500
    finally:
        # 清理临时文件
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


def handle_user_upload(user_id, allowed_size=10 * 1024 * 1024, allowed_mimes=None, check_existing=False):
    """处理用户文件上传（小文件）"""
    if not request.files.getlist('file'):
        return jsonify({'message': 'no files uploaded'}), 400

    try:
        return _process_multiple_files(user_id, allowed_size, allowed_mimes, check_existing)
    except Exception as e:
        print(f"Upload Error: {str(e)}")
        return jsonify({'message': 'failed', 'error': str(e)}), 500


@jwt_required
# 大文件分块上传接口
def handle_chunked_upload_init(user_id):
    """初始化分块上传，支持断点续传"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        total_size = data.get('total_size')
        total_chunks = data.get('total_chunks')
        file_hash = data.get('file_hash')  # 可选，用于秒传
        existing_upload_id = data.get('existing_upload_id')  # 可选，用于断点续传

        if not all([filename, total_size, total_chunks]):
            return jsonify({'success': False, 'error': '缺少必要参数'}), 400

        processor = ChunkedUploadProcessor(user_id)
        result = processor.init_upload(filename, total_size, total_chunks, file_hash, existing_upload_id)

        return jsonify(result), 200 if result['success'] else 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@jwt_required
def handle_chunked_upload_chunk(user_id):
    """上传文件分块"""
    try:
        upload_id = request.form.get('upload_id')
        chunk_index = int(request.form.get('chunk_index'))
        chunk_hash = request.form.get('chunk_hash')

        if 'chunk' not in request.files:
            return jsonify({'success': False, 'error': '未找到分块文件'}), 400

        chunk_file = request.files['chunk']
        chunk_data = chunk_file.read()

        # 验证分块哈希
        actual_chunk_hash = hashlib.sha256(chunk_data).hexdigest()
        if actual_chunk_hash != chunk_hash:
            return jsonify({'success': False, 'error': '分块哈希验证失败'}), 400

        processor = ChunkedUploadProcessor(user_id)
        result = processor.upload_chunk(upload_id, chunk_index, chunk_data, chunk_hash)

        return jsonify(result), 200 if result['success'] else 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@jwt_required
def handle_chunked_upload_complete(user_id):
    """完成分块上传"""
    try:
        data = request.get_json()
        upload_id = data.get('upload_id')
        file_hash = data.get('file_hash')
        mime_type = data.get('mime_type')

        if not all([upload_id, file_hash, mime_type]):
            return jsonify({'success': False, 'error': '缺少必要参数'}), 400

        processor = ChunkedUploadProcessor(user_id)
        result = processor.complete_upload(upload_id, file_hash, mime_type)

        if result['success']:
            # 创建短链接（如果需要）
            domain = request.host_url
            s_url = create_special_url(
                domain + "file?hash=" + result['file_hash'],
                user_id=user_id
            )
            result['short_url'] = "/s/" + s_url

        return jsonify(result), 200 if result['success'] else 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@jwt_required
def handle_chunked_upload_progress(user_id):
    """获取上传进度"""
    try:
        upload_id = request.args.get('upload_id')
        if not upload_id:
            return jsonify({'success': False, 'error': '缺少upload_id'}), 400

        processor = ChunkedUploadProcessor(user_id)
        result = processor.get_upload_progress(upload_id)

        return jsonify(result), 200 if result['success'] else 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@jwt_required
def handle_chunked_upload_cancel(user_id):
    """取消上传"""
    try:
        data = request.get_json()
        upload_id = data.get('upload_id')

        if not upload_id:
            return jsonify({'success': False, 'error': '缺少upload_id'}), 400

        processor = ChunkedUploadProcessor(user_id)
        result = processor.cancel_upload(upload_id)

        return jsonify(result), 200 if result['success'] else 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# 原有的辅助函数保持不变
def _process_single_file(processor, file_data, filename):
    """处理单个文件的核心逻辑"""
    with get_db() as db:
        try:
            # 验证文件
            is_valid, validation_result = processor.validate_file(file_data, filename)
            if not is_valid:
                return {'success': False, 'error': validation_result}

            # 计算哈希
            file_hash = processor.calculate_hash(file_data)
            mime_type = validation_result['mime_type']
            file_size = validation_result['file_size']

            # 检查文件是否已存在 - 使用当前会话查询
            existing_file_hash = db.query(FileHash).filter_by(
                hash=file_hash, mime_type=mime_type
            ).first()

            if not existing_file_hash:
                # 保存新文件
                storage_path = processor.save_file(file_hash, file_data, filename)
                processor.create_file_hash_record(db, file_hash, filename, file_size, mime_type, storage_path)

            # 创建媒体记录
            processor.create_media_record(db, file_hash, filename)
            db.commit()

            return {'success': True, 'hash': file_hash}

        except Exception as e:
            db.rollback()
            return {'success': False, 'error': str(e)}


def _process_multiple_files(user_id, allowed_size, allowed_mimes, check_existing):
    """处理多个文件上传"""
    processor = FileProcessor(user_id, allowed_mimes, allowed_size)
    uploaded_files = []
    reused_count = 0
    errors = []

    # 收集文件信息
    file_info_list = []
    for f in request.files.getlist('file'):
        try:
            file_data = f.read()
            file_info = {
                'file_obj': f,
                'filename': f.filename,
                'file_data': file_data,
                'file_hash': processor.calculate_hash(file_data)
            }

            # 验证文件
            is_valid, validation_result = processor.validate_file(file_data, f.filename)
            if not is_valid:
                errors.append(f'File {f.filename}: {validation_result}')
                continue

            file_info.update(validation_result)
            file_info_list.append(file_info)

        except Exception as e:
            errors.append(f'Error processing file {f.filename}: {str(e)}')

    # 按哈希分组处理
    hash_groups = {}
    for file_info in file_info_list:
        hash_groups.setdefault(file_info['file_hash'], []).append(file_info)

    # 处理每个哈希组
    with get_db() as db:
        for file_hash, file_group in hash_groups.items():
            try:
                first_file = file_group[0]

                # 检查文件是否已存在 - 使用当前会话查询
                existing_file_hash = db.query(FileHash).filter_by(
                    hash=file_hash, mime_type=first_file['mime_type']
                ).first()

                if existing_file_hash:
                    # 更新引用计数
                    existing_file_hash.reference_count += len(file_group)
                    reused_count += len(file_group)
                    # storage_path = existing_file_hash.storage_path
                else:
                    # 保存新文件
                    storage_path = processor.save_file(file_hash, first_file['file_data'], first_file['filename'])
                    processor.create_file_hash_record(
                        db, file_hash, first_file['filename'],
                        first_file['file_size'], first_file['mime_type'],
                        storage_path, len(file_group)
                    )

                # 为每个文件创建媒体记录
                for file_info in file_group:
                    media_record = processor.create_media_record(
                        db, file_hash, file_info['filename'], check_existing
                    )
                    if media_record:
                        uploaded_files.append(file_info['filename'])

                db.commit()

            except Exception as e:
                db.rollback()
                errors.append(f'Error processing files with hash {file_hash}: {str(e)}')

    # 构建响应
    response_data = {
        'message': 'success' if not errors else 'partial success',
        'uploaded': uploaded_files,
        'reused': reused_count
    }

    if errors:
        response_data['errors'] = errors

    status_code = 200 if not errors else 207
    return jsonify(response_data), status_code


@jwt_required
def handle_chunked_upload_chunks(user_id):
    """获取已上传的分块列表"""
    try:
        upload_id = request.args.get('upload_id')
        if not upload_id:
            return jsonify({'success': False, 'error': '缺少upload_id'}), 400

        processor = ChunkedUploadProcessor(user_id)
        result = processor.get_uploaded_chunks(upload_id)

        return jsonify(result), 200 if result['success'] else 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500