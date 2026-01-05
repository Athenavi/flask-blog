"""Gunicorn配置文件"""

import multiprocessing

# 服务器套接字绑定
bind = "0.0.0.0:9421"

# 工人进程数
# 根据CPU核心数计算，但不超过4个worker以节省资源
workers = min(multiprocessing.cpu_count() * 2 + 1, 4)

# 工人类
worker_class = "gevent"

# 每个工人进程的最大请求数，达到后重启进程，有助于防止内存泄漏
max_requests = 1000
max_requests_jitter = 100

# 超时时间
timeout = 30

# 保持连接时间
keepalive = 2

# 日志级别
loglevel = "info"

# 访问日志和错误日志
accesslog = "logs/gunicorn_access.log"
errorlog = "logs/gunicorn_error.log"

# 日志格式
access_log_format = '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# 是否启用前台运行（用于调试）
# daemon = True

# 工人进程名称
proc_name = "zb_app"

# worker连接数
worker_connections = 1000

# 优雅地重启worker
preload_app = True

# 限制请求行大小
limit_request_line = 4094

# 限制请求字段大小
limit_request_field_size = 8190