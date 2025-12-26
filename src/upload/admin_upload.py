import os

import magic  # 用于检测文件真实类型
from flask import request
from werkzeug.utils import secure_filename

from src.error import error
from src.utils.config.theme import validate_and_extract_theme


def admin_upload_file(size_limit):
    # 检查是否有文件被上传
    if 'file' not in request.files:
        return error('No file uploaded', 400)

    file = request.files['file']

    # 检查用户是否选择了文件
    if file.filename == '':
        return error('No file selected', 400)

    # 检查文件大小是否在允许范围内
    if file.content_length > size_limit:
        return error('Invalid file', 400)

    # 验证文件的真实类型（而不仅仅是扩展名）
    file_content = file.read()
    file.seek(0)  # 重置文件指针以便后续保存

    # 使用 python-magic 检测文件真实 MIME 类型
    try:
        mime = magic.Magic(mime=True)
        file_mime_type = mime.from_buffer(file_content)
    except Exception as e:
        return error('Unable to detect file type', 400)
    
    file_type = request.form.get('type')

    # 根据类型和真实的 MIME 类型选择保存目录和验证
    if file_type == 'theme':
        save_directory = 'templates/theme/'
        # 主题文件必须是 ZIP 格式
        if file_mime_type != 'application/zip':
            return error('Theme files must be valid ZIP archives', 400)
    else:
        return error('Invalid type', 400)

    # 检查保存目录是否存在，不存在则创建它
    if not os.path.exists(save_directory):
        os.makedirs(save_directory)

    # 保存文件到服务器上的指定目录，覆盖同名文件
    file_path = os.path.join(save_directory, secure_filename(file.filename))
    file.save(file_path)

    # 判断文件是否为 .zip 文件
    if file.filename[-4:] == '.zip' and file_type == 'theme':
        # 获取主题ID（去除.zip扩展名）
        theme_id = file.filename[:-4]
        # 验证并解压主题文件
        is_valid, message = validate_and_extract_theme(file_path, theme_id)
        if not is_valid:
            # 删除无效的主题文件
            os.remove(file_path)
            return error(message, 400)
        else:
            # 删除原始ZIP文件
            os.remove(file_path)
    else:
        # 跳过非 .zip 文件的处理
        pass

    return 'File uploaded successfully'