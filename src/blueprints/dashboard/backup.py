"""
Dashboard 备份管理模块
包含数据库备份、恢复等功能
"""
import inspect
from pathlib import Path

from flask import request, render_template, jsonify, send_file

from src.auth_utils import admin_required
from src.extensions import limiter
from src.models import User, db
from src.utils.database.backup import create_backup_tool
from update import base_dir
from . import admin_bp


@admin_bp.route('/backup', methods=['GET', 'POST'])
@admin_required
@limiter.limit("5 per minute")
def backup(user_id):
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        # 初始化备份工具
        backup_dir = Path(base_dir) / 'backup'
        backup_tool = create_backup_tool(db, str(backup_dir))

        # 处理备份请求
        if request.method == 'POST':
            backup_type = request.form.get('backup_type')

            if backup_type == 'schema':
                # 使用工具类备份表结构
                result = backup_tool.backup_schema()

                if result:
                    filename = Path(result).name
                    return jsonify({
                        'success': True,
                        'message': f'数据库结构备份成功: {filename}',
                        'filename': filename
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': '数据库结构备份失败'
                    })

            elif backup_type == 'data':
                # 使用工具类备份表数据
                result = backup_tool.backup_data()

                if result:
                    filename = Path(result).name
                    return jsonify({
                        'success': True,
                        'message': f'数据库数据备份成功: {filename}',
                        'filename': filename
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': '数据库数据备份失败'
                    })

            elif backup_type == 'all':
                # 使用工具类完整备份数据库
                result = backup_tool.backup_all()

                if result and 'full' in result:
                    filename = Path(result['full']).name
                    return jsonify({
                        'success': True,
                        'message': f'完整数据库备份成功: {filename}',
                        'filename': filename
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': '完整数据库备份失败'
                    })

            elif backup_type == 'delete':
                # 删除备份文件
                filename = request.form.get('filename')
                if filename and filename.endswith(('.sql', '.sql.gz', '.zip')):
                    filepath = backup_dir / filename
                    if filepath.exists() and filepath.parent == backup_dir:
                        filepath.unlink()
                        return jsonify({
                            'success': True,
                            'message': f'备份文件已删除: {filename}'
                        })

                return jsonify({
                    'success': False,
                    'message': '文件删除失败'
                })

        # GET请求 - 显示备份页面
        backup_list = []
        if backup_dir.exists():
            # 使用工具类列出备份文件
            backups = backup_tool.list_backups()

            for backup_info in backups:
                filename = backup_info['name']
                file_size = backup_info['size']
                created_at = backup_info['modified']

                # 确定备份类型
                if filename.startswith('schema_backup_'):
                    backup_type = 'schema'
                elif filename.startswith('data_backup_'):
                    backup_type = 'data'
                elif filename.startswith('full_backup_'):
                    backup_type = 'all'
                else:
                    backup_type = 'unknown'

                backup_list.append({
                    'name': filename,
                    'size': file_size,
                    'created_at': created_at,
                    'type': backup_type
                })

        # 按创建时间倒序排列
        backup_list.sort(key=lambda x: x['created_at'], reverse=True)

        return render_template('dashboard/backup.html',
                               backup_list=backup_list,
                               current_user=current_user)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/backup/download/<filename>')
@admin_required
def download_backup(user_id, filename):
    try:
        backup_dir = Path(base_dir) / 'backup'
        filepath = backup_dir / filename

        # 安全检查：确保文件在备份目录内
        if not filepath.exists() or filepath.parent != backup_dir:
            return jsonify({'error': '文件不存在'}), 404
        # 处理压缩文件的下载名称
        download_name = filename
        return send_file(
            filepath,
            as_attachment=True,
            download_name=download_name
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")
