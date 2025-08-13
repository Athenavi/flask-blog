# logger_config.py
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from prometheus_client import start_http_server, Counter, Gauge

# 初始化全局指标
REQUEST_COUNT = Counter('app_requests_total', 'Total application requests')
ERROR_COUNT = Counter('app_errors_total', 'Total application errors')
LATENCY_GAUGE = Gauge('app_request_latency_seconds', 'Application request latency')
MEMORY_USAGE = Gauge('app_memory_usage_mb', 'Application memory usage in MB')
CPU_USAGE = Gauge('app_cpu_usage_percent', 'Application CPU usage percent')


class StructuredFormatter(logging.Formatter):
    """结构化日志格式化器 (JSON格式)"""

    MAX_MSG_SIZE = 32 * 1024  # 32KB最大消息长度

    def format(self, record):
        # 截断超大消息
        msg = record.getMessage()
        if len(msg) > self.MAX_MSG_SIZE:
            record.msg = msg[:self.MAX_MSG_SIZE] + "...[TRUNCATED]"

        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': record.threadName,
            'process': record.processName
        }

        # 添加业务指标
        if hasattr(record, 'metrics'):
            log_data.update(record.metrics)

        return json.dumps(log_data)


class AlertHandler(logging.Handler):
    """自定义告警处理器"""

    def __init__(self, alert_threshold=logging.ERROR, alert_callback=None):
        super().__init__()
        self.alert_threshold = alert_threshold
        self.alert_callback = alert_callback or self.default_alert_callback

    def emit(self, record):
        if record.levelno >= self.alert_threshold:
            alert_data = {
                'level': record.levelname,
                'message': record.getMessage(),
                'time': datetime.now(timezone.utc).isoformat(),
                'location': f"{record.module}.{record.funcName}:{record.lineno}"
            }
            self.alert_callback(alert_data)

    @staticmethod
    def default_alert_callback(alert_data):
        """默认告警处理（打印到控制台）"""
        print(f"🚨 ALERT TRIGGERED: {alert_data}")


def check_disk_space(log_dir, threshold_mb=100):
    """检查磁盘空间是否充足"""
    try:
        total, used, free = shutil.disk_usage(log_dir)
        free_space_mb = free / (1024 * 1024)  # 转换为MB
        if free_space_mb < threshold_mb:
            return False, free_space_mb
        return True, free_space_mb
    except Exception as e:
        logging.error(f"磁盘空间检查失败: {str(e)}")
        return False, 0


def init_logger(
        log_dir="logs",
        log_base_name="app",
        max_bytes=10 * 1024 * 1024,  # 10MB
        backup_count=5,
        log_level=logging.INFO,
        metrics_port=9090,
        enable_metrics=True
):
    """初始化日志系统

    参数:
      log_dir: 日志文件存放目录
      log_base_name: 日志文件基础名称
      max_bytes: 单个日志文件的最大字节数
      backup_count: 保留备份文件的数量
      log_level: 日志级别
      metrics_port: Prometheus指标暴露端口
      enable_metrics: 是否启用指标监控
    """
    # 创建日志目录
    os.makedirs(log_dir, exist_ok=True)

    # 检查磁盘空间
    has_space, free_space = check_disk_space(log_dir)
    if not has_space:
        raise RuntimeError(f"Insufficient disk space: {free_space:.2f}MB left in {log_dir}")

    # 启动Prometheus指标服务器
    if enable_metrics:
        start_http_server(metrics_port)
        print(f"📊 Metrics server started on port {metrics_port}")

    # 获取根日志记录器
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # 创建结构化日志格式器
    structured_formatter = StructuredFormatter()

    # 使用固定文件名保证轮转生效
    log_path = os.path.join(log_dir, f"{log_base_name}.log")

    # 文件处理器
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setFormatter(structured_formatter)
    logger.addHandler(file_handler)

    # 设置文件权限 (644)
    try:
        os.chmod(log_path, 0o644)
    except Exception as e:
        logger.warning(f"Failed to set log file permissions: {str(e)}")

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(module)s:%(funcName)s:%(lineno)d - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # 告警处理器
    alert_handler = AlertHandler(
        alert_threshold=logging.ERROR,
        alert_callback=lambda alert: logger.critical(f"ALERT: {alert}")
    )
    logger.addHandler(alert_handler)

    logger.info("✅ Logger initialized", extra={
        'metrics': {
            'log_file': log_path,
            'log_level': logging.getLevelName(log_level),
            'max_size_mb': max_bytes // (1024 * 1024),
            'backup_count': backup_count,
            'free_space_mb': free_space
        }
    })

    return logger


# 使用示例
if __name__ == "__main__":
    logger = init_logger()

    # 测试日志
    logger.debug("Debug message")
    logger.info("Info message")
    logger.warning("Warning message")
    try:
        1 / 0
    except Exception as e:
        logger.error("Error occurred", exc_info=True)

    # 测试大日志消息
    large_msg = "A" * 50 * 1024  # 50KB
    logger.info(f"Large message test: {large_msg}")
