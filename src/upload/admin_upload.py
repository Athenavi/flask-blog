import os
import zipfile

from werkzeug.utils import secure_filename
from flask import request

from src.error import error


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

    file_type = request.form.get('type')

    # 根据类型选择保存目录
    if file_type == 'articles':
        save_directory = 'articles/'
    elif file_type == 'theme':
        save_directory = 'templates/theme/'
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
        # 预览 .zip 文件的内容
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # 获取压缩包中的文件列表
            zip_ref.extractall(save_directory)
    else:
        # 跳过非 .zip 文件的处理
        pass

    return 'File uploaded successfully'
