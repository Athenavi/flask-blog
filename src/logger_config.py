import gzip
import json
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import request, g


class CompressedRotatingFileHandler(RotatingFileHandler):
    """支持压缩的轮转文件处理器"""

    def doRollover(self):
        """执行日志轮转并压缩旧文件"""
        if self.stream:
            self.stream.close()
            self.stream = None  # type: ignore

        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = self.rotation_filename("%s.%d.gz" % (self.baseFilename, i))
                dfn = self.rotation_filename("%s.%d.gz" % (self.baseFilename, i + 1))
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)

            # 压缩当前日志文件
            dfn = self.rotation_filename(self.baseFilename + ".1.gz")
            if os.path.exists(dfn):
                os.remove(dfn)

            # 压缩原文件
            with open(self.baseFilename, 'rb') as f_in:
                with gzip.open(dfn, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)  # type: ignore

            # 删除原文件
            os.remove(self.baseFilename)

        if not self.delay:
            self.stream = self._open()


class OptimizedStructuredFormatter(logging.Formatter):
    """优化的结构化日志格式化器"""

    MAX_MSG_SIZE = 1024  # 减少到1KB

    def format(self, record):
        # 截断超大消息
        msg = record.getMessage()
        if len(msg) > self.MAX_MSG_SIZE:
            record.msg = msg[:self.MAX_MSG_SIZE] + "...[TRUNCATED]"

        # 简化的日志结构
        log_data = {
            'ts': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            'level': record.levelname[0],  # 只保留首字母
            'msg': record.getMessage(),
            'loc': f"{record.module}:{record.lineno}"
        }

        # 只在错误时添加详细信息
        if record.levelno >= logging.ERROR:
            log_data.update({
                'func': record.funcName,
                'thread': record.threadName
            })

        return json.dumps(log_data, ensure_ascii=False, separators=(',', ':'))


def cleanup_old_logs(log_dir, pattern="app_*.log*", max_age_days=7):
    """清理旧的日志文件"""
    log_path = Path(log_dir)
    if not log_path.exists():
        return

    current_time = datetime.now()
    cleaned_files = []
    total_size_freed = 0

    for log_file in log_path.glob(pattern):
        try:
            file_age = current_time - datetime.fromtimestamp(log_file.stat().st_mtime)
            if file_age.days > max_age_days:
                file_size = log_file.stat().st_size
                log_file.unlink()
                cleaned_files.append(str(log_file))
                total_size_freed += file_size
        except Exception as e:
            logging.warning(f"清理文件 {log_file} 时出错: {e}")

    if cleaned_files:
        logging.info(f"🧹 清理了 {len(cleaned_files)} 个旧日志文件，释放空间: {total_size_freed / (1024 * 1024):.2f} MB")
        for file in cleaned_files:
            logging.info(f"  - {file}")


def init_optimized_logger(
        log_dir="logs",
        log_name="app.log",  # 固定文件名
        max_bytes=5 * 1024 * 1024,  # 减少到5MB
        backup_count=3,  # 减少备份数量
        log_level=logging.INFO,
        enable_compression=True,
        cleanup_old=True
):
    """初始化优化的日志系统"""

    # 创建日志目录
    os.makedirs(log_dir, exist_ok=True)

    # 清理旧日志文件
    if cleanup_old:
        cleanup_old_logs(log_dir)

    # 检查磁盘空间
    try:
        total, used, free = shutil.disk_usage(log_dir)
        free_mb = free / (1024 * 1024)
        if free_mb < 50:  # 至少需要50MB空间
            raise RuntimeError(f"磁盘空间不足: 仅剩 {free_mb:.2f}MB")
    except Exception as e:
        logging.warning(f"⚠️  磁盘空间检查失败: {e}")

    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.handlers.clear()  # 清除现有处理器
    root_logger.setLevel(log_level)

    # 创建优化的格式化器
    formatter = OptimizedStructuredFormatter()

    # 文件处理器 - 使用固定文件名
    log_path = os.path.join(log_dir, log_name)

    if enable_compression:
        file_handler = CompressedRotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
    else:
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )

    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # 简化的控制台处理器
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # 设置文件权限
    try:
        os.chmod(log_path, 0o644)
    except (OSError, PermissionError) as e:
        root_logger.warning(f"无法设置文件权限: {e}")
        pass

    root_logger.info(f"✅ 优化日志系统已启动 - 文件: {log_path}, 大小限制: {max_bytes / (1024 * 1024):.1f}MB")

    return root_logger


def init_pythonanywhere_logger():
    """初始化优化日志配置，避免递归问题"""

    # 获取根日志记录器
    no_record_logger = logging.getLogger()

    # 清除现有的处理器，避免重复
    for handler in no_record_logger.handlers[:]:
        no_record_logger.removeHandler(handler)

    # 设置日志级别
    no_record_logger.setLevel(logging.INFO)

    # 创建格式化器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 创建控制台处理器（避免文件写入权限问题）
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # 添加处理器到日志记录器
    no_record_logger.addHandler(console_handler)

    # 禁用过于冗长的日志记录器
    logging.getLogger('waitress').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    logging.info("Logger initialized successfully without recursion issues")

    # 关键修复：返回 logger 对象
    return no_record_logger


# 新增Prometheus指标监控
try:
    from prometheus_client import Counter, Histogram, Gauge, Summary
    import time

    # 定义监控指标
    REQUEST_COUNT = Counter('app_requests_total', 'Total requests', ['method', 'endpoint', 'status'])
    REQUEST_DURATION = Histogram('app_request_duration_seconds', 'Request duration')
    ACTIVE_CONNECTIONS = Gauge('app_active_connections', 'Active connections')
    LOG_ENTRIES = Counter('app_log_entries_total', 'Total log entries', ['level'])
    REQUEST_SIZE = Summary('app_request_size_bytes', 'Request size')
    RESPONSE_SIZE = Summary('app_response_size_bytes', 'Response size')

    # 重写日志处理类以添加监控
    class MonitoredRotatingFileHandler(RotatingFileHandler):
        def emit(self, record):
            super().emit(record)
            LOG_ENTRIES.labels(level=record.levelname.lower()).inc()

    # 为Flask应用添加监控中间件
    class MonitoringMiddleware:
        def __init__(self, app):
            self.app = app
            self.app.before_request(self.before_request)
            self.app.after_request(self.after_request)
            ACTIVE_CONNECTIONS.inc()

        @staticmethod
        def before_request():
            g.start_time = time.time()
            # 记录请求大小
            if request.content_length:
                REQUEST_SIZE.observe(request.content_length)

        @staticmethod
        def after_request(response):
            duration = time.time() - g.start_time
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown',
                status=response.status_code
            ).inc()
            REQUEST_DURATION.observe(duration)
            
            # 记录响应大小
            if hasattr(response, 'content_length') and response.content_length:
                RESPONSE_SIZE.observe(response.content_length)
                
            return response

    # 健康检查端点
    def setup_health_check(app):
        @app.route('/health')
        def health_check():
            return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}, 200

        @app.route('/metrics')
        def metrics():
            from prometheus_client import generate_latest
            return generate_latest(), 200, {'Content-Type': 'text/plain; charset=utf-8'}

except ImportError:
    Counter, Histogram, Gauge, Summary, generate_latest = None, None, None, None, None
    time = None
    # Prometheus客户端不可用时不启用监控
    class MonitoringMiddleware:
        def __init__(self, app):
            pass
    
    def setup_health_check(app):
        def health_check():
            return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}, 200

        def metrics():
            # prometheus_client不可用，返回空响应
            return 'Metrics not available', 501, {'Content-Type': 'text/plain; charset=utf-8'}

        # 将路由函数注册到app
        app.add_url_rule('/health', 'health_check', health_check)
        app.add_url_rule('/metrics', 'metrics', metrics, methods=['GET'])

# 使用示例
if __name__ == "__main__":
    # 初始化优化的日志系统
    logger = init_optimized_logger()
    # 测试日志
    logger.info("应用启动")
    logger.warning("这是一个警告")
    logger.error("这是一个错误")

    logger.info("✅ 日志系统测试完成")