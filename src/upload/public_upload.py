import hashlib
import os
from datetime import datetime
from pathlib import Path

import magic
from flask import jsonify, request
from werkzeug.utils import secure_filename

from src.database import get_db_connection


def upload_article(file, upload_folder, allowed_size):
    # 验证文件格式和大小
    if not file.filename.endswith('.md') or file.content_length > allowed_size:
        return 'Invalid file format or file too large.', 400

    # 使用 pathlib 创建上传文件夹
    upload_path = Path(upload_folder)
    upload_path.mkdir(parents=True, exist_ok=True)

    # 构建文件路径
    file_path = upload_path / file.filename

    # 避免文件名冲突
    if file_path.is_file():
        return 'Upload failed, the file already exists.', 400

    # 保存文件
    file.save(str(file_path))  # 确保转换为字符串
    # shutil.copy(str(file_path), str(Path('articles') / file.filename))
    return None


def handle_user_upload(user_id, allowed_size, allowed_mimes, check_existing=False):
    if not request.files.getlist('file'):
        return jsonify({'message': 'no files uploaded'}), 400

    try:
        uploaded_files = []
        with get_db_connection() as db:
            cursor = db.cursor()

            for f in request.files.getlist('file'):
                # 校验基础属性
                if f.content_length > allowed_size:
                    return jsonify({'message': f'File size exceeds limit: {allowed_size / 1024 / 1024}MB'}), 413

                # 读取文件内容并计算哈希
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()
                f.seek(0)  # 重置文件指针

                if check_existing:
                    try:
                        with cursor.execute(
                            """SELECT hash
                               FROM media
                               WHERE hash = %s and user_id = %s""",
                            (file_hash,user_id)
                        ) as cursor:
                            existing_file = cursor.fetchone()
                            if existing_file:
                                pass
                    except Exception as e:
                        return jsonify({'message': 'failed', 'error': str(e)}), 500

                # 校验MIME类型
                mime_type = magic.from_buffer(file_data, mime=True)
                if mime_type not in allowed_mimes:
                    print(f'Rejected: User {user_id}, Invalid MIME {mime_type}')
                    continue

                # 检查哈希是否已存在
                cursor.execute(
                    """SELECT hash, storage_path
                       FROM file_hashes
                       WHERE hash = %s
                         AND mime_type = %s""",
                    (file_hash, mime_type)
                )
                existing_file = cursor.fetchone()

                storage_path = None
                if existing_file:
                    # 复用已有文件
                    storage_path = existing_file[1]
                    print(f'Reuse existing file: {storage_path}')
                    # 增加引用计数
                    cursor.execute(
                        """UPDATE file_hashes
                           SET reference_count = reference_count + 1
                           WHERE hash = %s
                             AND mime_type = %s""",
                        (file_hash, mime_type)
                    )
                else:
                    # 生成存储路径（哈希分片目录）
                    hash_prefix = file_hash[:2]
                    hash_subdir = os.path.join('hashed_files', hash_prefix)
                    os.makedirs(hash_subdir, exist_ok=True)

                    # 保存文件（示例路径格式：hashed_files/ab/abcdef12345...）
                    filename = f.filename
                    storage_path = os.path.join(hash_subdir, file_hash)
                    with open(storage_path, 'wb') as dest:
                        dest.write(file_data)

                    # 插入文件哈希记录
                    cursor.execute(
                        """INSERT INTO file_hashes
                               (hash, filename, file_size, mime_type, storage_path, reference_count)
                           VALUES (%s, %s, %s, %s, %s, 1)
                           ON DUPLICATE KEY UPDATE reference_count = reference_count + 1""",
                        (file_hash, filename, len(file_data), mime_type, storage_path)
                    )

                # 插入媒体记录（即使文件已存在也需要记录用户关联）
                try:
                    cursor.execute(
                        """INSERT INTO media
                               (user_id, hash, original_filename)
                           VALUES (%s, %s, %s)""",
                        (user_id, file_hash, secure_filename(f.filename))
                    )
                    uploaded_files.append(f.filename)
                except Exception as e:
                    # 处理同一用户重复上传相同文件
                    print(f'Error inserting media record: {e}')
                    db.rollback()
                    continue

            db.commit()
            return jsonify({
                'message': 'success',
                'uploaded': uploaded_files,
                'reused': len(request.files) - len(uploaded_files)
            }), 200

    except Exception as e:
        print(f"Upload Error: {str(e)}")
        db.rollback()
        return jsonify({'message': 'failed', 'error': str(e)}), 500


def bulk_save_articles(filename, user_id):
    title = filename.split('.')[0]
    tags = datetime.now().year
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute("INSERT INTO articles (Title, user_id, Status, tags,slug) VALUES (%s, %s, %s, %s, %s)",
                               (title, user_id, 'Draft', tags, title.lower().replace(' ', '-')))
            db.commit()
            return True
    except Exception as e:
        print(f"Error in saving to database: {e}")
        return False


def process_single_upload(f, user_id, allowed_size, allowed_mimes, db):
    """
    处理单个上传文件，返回 (storage_path, file_hash)
    若出现异常，则抛出错误，让上层捕获记录错误信息。
    """
    # 检查文件大小（注意：有时 f.content_length 可能为空，因此以读取后的字节长度为准）
    if f.content_length and f.content_length > allowed_size:
        raise Exception(f"文件大小超过限制: {allowed_size / 1024 / 1024:.2f}MB")

    file_data = f.read()
    if len(file_data) > allowed_size:
        raise Exception(f"文件大小超过限制: {allowed_size / 1024 / 1024:.2f}MB")

    # 计算文件 SHA256 哈希
    file_hash = hashlib.sha256(file_data).hexdigest()
    f.seek(0)  # 重置文件指针（如后续需要重新读取）

    # 校验 MIME 类型
    mime_type = magic.from_buffer(file_data, mime=True)
    if mime_type not in allowed_mimes:
        raise Exception(f"无效的 MIME 类型: {mime_type}")

    cursor = db.cursor()
    # 检查该文件是否已存在
    cursor.execute(
        """SELECT hash, storage_path
           FROM file_hashes
           WHERE hash = %s
             AND mime_type = %s""",
        (file_hash, mime_type)
    )
    existing_file = cursor.fetchone()

    if existing_file:
        storage_path = existing_file[1]
        # 已存在则增加引用计数
        cursor.execute(
            """UPDATE file_hashes
               SET reference_count = reference_count + 1
               WHERE hash = %s
                 AND mime_type = %s""",
            (file_hash, mime_type)
        )
    else:
        # 生成存储路径：利用哈希前两位作为目录分片
        hash_prefix = file_hash[:2]
        hash_subdir = os.path.join('hashed_files', hash_prefix)
        os.makedirs(hash_subdir, exist_ok=True)
        storage_path = os.path.join(hash_subdir, file_hash)
        with open(storage_path, 'wb') as dest:
            dest.write(file_data)
        cursor.execute(
            """INSERT INTO file_hashes
                   (hash, filename, file_size, mime_type, storage_path, reference_count)
               VALUES (%s, %s, %s, %s, %s, 1)
               ON DUPLICATE KEY UPDATE reference_count = reference_count + 1""",
            (file_hash, f.filename, len(file_data), mime_type, storage_path)
        )

    # 插入媒体记录（即使文件复用也要记录用户关联）
    try:
        cursor.execute(
            """INSERT INTO media
                   (user_id, hash, original_filename)
               VALUES (%s, %s, %s)""",
            (user_id, file_hash, secure_filename(f.filename))
        )
    except Exception as e:
        db.rollback()
        raise Exception("插入媒体记录失败: " + str(e))

    return storage_path, file_hash


def save_bulk_content(success_path_list, success_file_list):
    if not success_file_list:  # 处理空列表情况
        return True

    try:
        with get_db_connection() as db:
            cursor = db.cursor()

            # 获取文章ID映射 (使用title)
            titles = [title for title in success_file_list]
            placeholders = ', '.join(['%s'] * len(titles))
            query = f"SELECT article_id, title FROM articles WHERE title IN ({placeholders})"
            cursor.execute(query, titles)
            id_map = {row[1]: row[0] for row in cursor.fetchall()}

            # 批量保存内容
            for path, title in zip(success_path_list, success_file_list):
                if title not in id_map:
                    print(f"Warning: No article found for title '{title}'. Skipping.")
                    continue

                with open(path, 'rb') as f:
                    content = f.read()

                cursor.execute(
                    "INSERT INTO article_content (aid, content) VALUES (%s, %s)",
                    (id_map[title], content)
                )

            db.commit()
            return True

    except Exception as e:
        print(f"Database error in bulk_content_save: {e}")
        if db:
            db.rollback()
        return False


def handle_editor_upload(domain, user_id, allowed_size, allowed_mimes):
    """处理文件上传（严格匹配 Vditor 格式）"""
    if 'file' not in request.files:
        return jsonify({
            "code": 400,
            "msg": "未上传文件",
            "data": {"errFiles": [], "succMap": {}}
        }), 400
    succ_map = {}
    err_files = []
    try:
        with get_db_connection() as db:
            # 遍历所有上传的文件
            for f in request.files.getlist('file'):
                try:
                    _, file_hash = process_single_upload(f, user_id, allowed_size, allowed_mimes, db)
                    # 生成供外部访问的 URL
                    file_url = domain + 'shared?data=' + file_hash
                    succ_map[f.filename] = file_url
                except Exception as e:
                    err_files.append({
                        "name": f.filename,
                        "error": str(e)
                    })
            db.commit()
    except Exception as e:
        return jsonify({
            "code": 500,
            "msg": "服务器处理错误: " + str(e),
            "data": {"errFiles": err_files, "succMap": succ_map}
        }), 500

    response_code = 0 if succ_map else 500
    if succ_map and err_files:
        response_msg = "部分成功"
    elif succ_map:
        response_msg = "成功"
    else:
        response_msg = "失败"

    return jsonify({
        "code": response_code,
        "msg": response_msg,
        "data": {
            "errFiles": err_files,
            "succMap": succ_map
        }
    })


def handle_file_upload_v2(user_id, domain, storage_path):
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    # 文件类型验证 :cite[4]
    allowed_mimes = {'image/jpeg', 'image/png', 'image/gif', 'video/mp4', 'video/webm'}
    if file.mimetype not in allowed_mimes:
        return jsonify({"error": f"Unsupported file type: {file.mimetype}"}), 415

    # 文件大小验证 :cite[8]
    max_size = 10 * 1024 * 1024  # 10MB
    if len(file.read()) > max_size:
        return jsonify({"error": "File exceeds 10MB limit"}), 413
    file.seek(0)  # 重置文件指针

    filename = f"{file.filename}"
    upload_dir = os.path.join(storage_path, 'uploads')  # 确保这里有一个目录名
    os.makedirs(upload_dir, exist_ok=True)
    file.save(os.path.join(upload_dir, filename))

    return jsonify({
        "url": f"{domain}uploads/{filename}",
        "mime": file.mimetype
    }), 200

