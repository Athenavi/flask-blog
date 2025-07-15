def is_allowed_file(filename, allowed_types):
    # 检查文件是否是允许的类型
    return any(filename.lower().endswith(ext) for ext in allowed_types)