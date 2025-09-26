import gzip
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path


class CompressedRotatingFileHandler(RotatingFileHandler):
    """支持压缩的轮转文件处理器"""

    def doRollover(self):
        """执行日志轮转并压缩旧文件"""
        if self.stream:
            self.stream.close()
            self.stream = None

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
                    shutil.copyfileobj(f_in, f_out)

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
            print(f"清理文件 {log_file} 时出错: {e}")

    if cleaned_files:
        print(f"🧹 清理了 {len(cleaned_files)} 个旧日志文件，释放空间: {total_size_freed / (1024 * 1024):.2f} MB")
        for file in cleaned_files:
            print(f"  - {file}")


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
        print(f"⚠️  磁盘空间检查失败: {e}")

    # 配置根日志记录器
    logger = logging.getLogger()
    logger.handlers.clear()  # 清除现有处理器
    logger.setLevel(log_level)

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
    logger.addHandler(file_handler)

    # 简化的控制台处理器
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # 设置文件权限
    try:
        os.chmod(log_path, 0o644)
    except Exception:
        pass

    logger.info(f"✅ 优化日志系统已启动 - 文件: {log_path}, 大小限制: {max_bytes / (1024 * 1024):.1f}MB")

    return logger


# 使用示例
if __name__ == "__main__":
    # 初始化优化的日志系统
    logger = init_optimized_logger(
        log_dir="logs",
        log_name="app.log",
        max_bytes=2 * 1024 * 1024,  # 2MB
        backup_count=3,
        enable_compression=True
    )

    # 测试日志
    logger.info("应用启动")
    logger.warning("这是一个警告")
    logger.error("这是一个错误")

    print("✅ 日志系统测试完成")
