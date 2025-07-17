# logger_config.py
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime


def init_logger(
        log_dir="temp",
        log_base_name="app",
        max_bytes=10 * 1024 * 1024,  # 10MB
        backup_count=5,
        log_level=logging.INFO
):
    """
    初始化日志配置，日志文件将带上启动时间戳，
    同时采用 RotatingFileHandler 防止日志文件过大影响性能。

    参数:
      log_dir: 日志文件存放目录。
      log_base_name: 日志文件基础名称，最终文件名会包含时间戳。
      max_bytes: 单个日志文件的最大字节数。
      backup_count: 保留备份文件的数量。
      log_level: 日志级别。
    """
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # 使用当前时间戳创建新的日志文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{log_base_name}_{timestamp}.log"
    log_path = os.path.join(log_dir, log_filename)

    # 获取根日志记录器，设置全局级别
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # 设置文件处理器，支持文件滚动
    file_handler = RotatingFileHandler(
        log_path,
        mode='w',  # 每次启动创建新文件，或可配合 mode='a' 来累积，并依 max_bytes 触发滚动
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # 同时添加一个控制台处理器，如果需要在控制台查看日志
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logger.info("Logger initialized, log file created: %s", log_path)
    return logger
