"""
Dashboard 媒体管理模块
包含媒体文件的上传、管理、删除等功能
"""
import inspect
import os
from datetime import datetime, timedelta
from pathlib import Path

from flask import request, render_template, jsonify
from sqlalchemy import or_

from src.auth_utils import admin_required
from src.models import User, db, Media, FileHash
from update import base_dir
from . import admin_bp


@admin_bp.route('/media', methods=['GET', 'DELETE'])
@admin_required
def admin_media(user_id):
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        # 处理删除请求
        if request.method == 'DELETE':
            media_hash = request.args.get('media_hash')
            if file_record := db.session.query(FileHash).filter_by(hash=media_hash).first():
                try:
                    # 检查文件是否存在
                    file_dir = Path(base_dir) / file_record.storage_path
                    if not os.path.exists(file_dir):
                        pass
                    else:
                        os.remove(file_dir)
                except Exception as e:
                    print(f"删除文件失败: {str(e)}")
                db.session.delete(file_record)
            db.session.commit()
            return jsonify({'success': True, 'message': '附件已删除'})

        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        mime_type = request.args.get('mime_type', '')
        user_id_filter = request.args.get('user_id', '')
        search = request.args.get('search', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')

        # 构建查询
        query = db.session.query(Media).join(FileHash, Media.hash == FileHash.hash).join(User, Media.user_id == User.id)

        # 应用筛选条件
        if mime_type:
            if mime_type == 'image':
                query = query.filter(FileHash.mime_type.like('image/%'))
            elif mime_type == 'video':
                query = query.filter(FileHash.mime_type.like('video/%'))
            elif mime_type == 'audio':
                query = query.filter(FileHash.mime_type.like('audio/%'))
            elif mime_type == 'document':
                query = query.filter(or_(
                    FileHash.mime_type.like('application/pdf'),
                    FileHash.mime_type.like('application/msword'),
                    FileHash.mime_type.like('application/vnd.openxmlformats-officedocument.%')
                ))
            else:
                query = query.filter(FileHash.mime_type == mime_type)

        if user_id_filter:
            query = query.filter(Media.user_id == user_id_filter)

        if search:
            query = query.filter(or_(
                FileHash.filename.ilike(f'%{search}%'),
                Media.original_filename.ilike(f'%{search}%'),
                User.username.ilike(f'%{search}%')
            ))

        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Media.created_at >= date_from_obj)
            except ValueError:
                pass

        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(Media.created_at < date_to_obj)
            except ValueError:
                pass

        # 获取用户列表用于筛选
        users = db.session.query(User).all()

        # 执行分页查询
        media_items = query.order_by(Media.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return render_template('dashboard/media.html',
                               media_items=media_items,
                               users=users,
                               current_user=current_user,
                               mime_type=mime_type,
                               user_id_filter=user_id_filter,
                               search=search,
                               date_from=date_from,
                               date_to=date_to)

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/media/preview/<int:media_id>')
@admin_required
def media_preview(user_id, media_id):
    try:
        media = db.session.query(Media).filter_by(id=media_id).first()
        if not media:
            return jsonify({'error': '文件不存在'}), 404

        file_record = db.session.query(FileHash).filter_by(hash=media.hash).first()
        if not file_record:
            return jsonify({'error': '文件哈希记录不存在'}), 404
        # 根据MIME类型决定返回方式
        file_type = 'unknown'
        if file_record.mime_type.startswith('image/'):
            file_type = 'image'
        elif file_record.mime_type.startswith('video/'):
            file_type = 'video'
        elif file_record.mime_type.startswith('text/'):
            return jsonify({
                'type': file_type,
                'filename': file_record.filename,
                'mime_type': file_record.mime_type,
                'size': file_record.file_size,
                'error': '文件已丢失',
                'view_url': None,
                'url': None
            })
        return jsonify({
            'type': file_type,
            'filename': file_record.filename,
            'mime_type': file_record.mime_type,
            'size': file_record.file_size,
            'view_url': f'/shared?data={file_record.hash}',
            'url': f'/admin/media/download/{media_id}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")
