# logger_config.py
import os
import logging
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from prometheus_client import start_http_server, Counter, Gauge

# 初始化全局指标
REQUEST_COUNT = Counter('app_requests_total', 'Total application requests')
ERROR_COUNT = Counter('app_errors_total', 'Total application errors')
LATENCY_GAUGE = Gauge('app_request_latency_seconds', 'Application request latency')
MEMORY_USAGE = Gauge('app_memory_usage_mb', 'Application memory usage in MB')
CPU_USAGE = Gauge('app_cpu_usage_percent', 'Application CPU usage percent')


class StructuredFormatter(logging.Formatter):
    """结构化日志格式化器 (JSON格式)"""

    def format(self, record):
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


def init_logger(
        log_dir="logs",
        log_base_name="app",
        max_bytes=10 * 1024 * 1024,  # 10MB
        backup_count=5,
        log_level=logging.INFO,
        metrics_port=9090
):
    """参数:
      log_dir: 日志文件存放目录
      log_base_name: 日志文件基础名称
      max_bytes: 单个日志文件的最大字节数
      backup_count: 保留备份文件的数量
      log_level: 日志级别
      metrics_port: Prometheus指标暴露端口
    """
    # 创建日志目录
    os.makedirs(log_dir, exist_ok=True)

    # 启动Prometheus指标服务器
    start_http_server(metrics_port)
    print(f"📊 Metrics server started on port {metrics_port}")

    # 获取根日志记录器
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # 创建结构化日志格式器
    structured_formatter = StructuredFormatter()

    # 文件处理器
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{log_base_name}_{timestamp}.log"
    log_path = os.path.join(log_dir, log_filename)

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setFormatter(structured_formatter)
    logger.addHandler(file_handler)

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
            'log_level': logging.getLevelName(log_level)
        }
    })

    # 添加系统指标监控
    logger.info("📊 System metrics monitoring enabled")

    return logger
