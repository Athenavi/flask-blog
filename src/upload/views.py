import os

from flask import jsonify, request, render_template

from src.upload.public_upload import bulk_save_articles, save_bulk_content


def upload_bulk_back(user_id, cache_instance, upload_limit):
    upload_locked = cache_instance.get(f"upload_locked_{user_id}") or False
    if request.method == 'POST':
        success_path_list = []
        success_file_list = []  # 存储文件名（不含扩展名）
        success_titles = []  # 存储用于查询的标题

        if upload_locked:
            return jsonify([{"filename": "无法上传", "status": "failed", "message": "上传已被锁定，请稍后再试"}]), 209

        try:
            files = request.files.getlist('files')

            # 检查文件数量限制
            if len(files) > 50:
                return jsonify([{"filename": "无法上传", "status": "failed", "message": "最多只能上传50个文件"}]), 400

            upload_result = []
            cache_instance.set(f"upload_locked_{user_id}", True, timeout=30)

            for file in files:
                current_file_result = {
                    "filename": file.filename,
                    "status": "",
                    "message": ""
                }

                # 原始文件名处理
                original_name = file.filename
                base_name = os.path.splitext(original_name)[0]  # 不含扩展名

                # 验证文件
                if not original_name.endswith('.md'):
                    current_file_result["status"] = "failed"
                    current_file_result["message"] = "仅支持.md文件"
                    upload_result.append(current_file_result)
                    continue

                if original_name.startswith('_'):
                    current_file_result["status"] = "failed"
                    current_file_result["message"] = "文件名不能以下划线开头"
                    upload_result.append(current_file_result)
                    continue

                if file.content_length > upload_limit:
                    current_file_result["status"] = "failed"
                    current_file_result[
                        "message"] = f"文件大小超过限制 ({upload_limit // (1024 * 1024)}MB)"
                    upload_result.append(current_file_result)
                    continue

                # 创建上传目录
                upload_dir = "temp/upload"
                os.makedirs(upload_dir, exist_ok=True)
                file_path = os.path.join(upload_dir, original_name)

                # 检查文件是否已存在
                if os.path.exists(file_path):
                    current_file_result["status"] = "failed"
                    current_file_result["message"] = "存在同名文件"
                    upload_result.append(current_file_result)
                    continue

                # 保存文件
                file.save(file_path)

                # 保存到数据库 (articles表)
                if bulk_save_articles(base_name, user_id):  # 使用不含扩展名的名称
                    current_file_result["status"] = "success"
                    current_file_result["message"] = "上传成功"

                    # 添加到成功列表
                    success_path_list.append(file_path)
                    success_file_list.append(base_name)  # 存储不含扩展名的名称
                    success_titles.append(base_name)  # 用于后续查询
                else:
                    current_file_result["status"] = "failed"
                    current_file_result["message"] = "数据库保存失败"

                upload_result.append(current_file_result)

            # 批量保存内容 (所有文件处理完成后)
            if success_path_list:
                if not save_bulk_content(success_path_list, success_titles):
                    print("部分文件内容保存失败")
                    # app.logger.error("部分文件内容保存失败")
                    # 可选：标记失败的文件

            return jsonify({'upload_result': upload_result})

        except Exception as e:
            # app.logger.error(f"批量上传错误: {str(e)}", exc_info=True)
            return jsonify({'message': '上传失败', 'error': str(e)}), 500

    tip_message = f"请不要上传超过 {upload_limit / (1024 * 1024)}MB 的文件"
    return render_template('upload.html', upload_locked=upload_locked, message=tip_message)