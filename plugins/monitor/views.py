import datetime as dt
import os
import threading
from collections import deque

import psutil
from flask import Blueprint, render_template_string
from flask import jsonify

monitor_bp = Blueprint('monitor', __name__)


@monitor_bp.route('/status')
def index():
    template_path = os.path.join('plugins', 'monitor', 'index.html')
    with open(template_path, 'r', encoding='utf-8') as file:
        template_string = file.read()
    return render_template_string(template_string)


# 配置参数
MAX_DATA_POINTS = 60  # 1分钟数据
COLLECTION_INTERVAL = 1  # 收集间隔(秒)


# 线程安全的环形缓冲区
class CircularBuffer:
    def __init__(self, max_size):
        self.buffer = deque(maxlen=max_size)
        self.lock = threading.Lock()

    def add(self, item):
        with self.lock:
            self.buffer.append(item)

    def get_all(self):
        with self.lock:
            return list(self.buffer)


# 系统数据存储
system_data = {
    "cpu_total": CircularBuffer(MAX_DATA_POINTS),
    "cpu_cores": CircularBuffer(MAX_DATA_POINTS),
    "memory": CircularBuffer(MAX_DATA_POINTS),
    "disk": CircularBuffer(MAX_DATA_POINTS),
    "network_sent": CircularBuffer(MAX_DATA_POINTS),
    "network_recv": CircularBuffer(MAX_DATA_POINTS),
    "process_count": CircularBuffer(MAX_DATA_POINTS),
    "boot_time": dt.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
}


@monitor_bp.route('/data')
def get_data():
    # 直接返回当前数据
    return jsonify({
        "cpu_total": system_data["cpu_total"].get_all(),
        "cpu_cores": system_data["cpu_cores"].get_all(),
        "memory": system_data["memory"].get_all(),
        "disk": system_data["disk"].get_all(),
        "network_sent": system_data["network_sent"].get_all(),
        "network_recv": system_data["network_recv"].get_all(),
        "process_count": system_data["process_count"].get_all(),
        "boot_time": system_data["boot_time"]
    })


@monitor_bp.route('/system_info')
def get_system_info():
    # 获取CPU核心数量
    core_count = psutil.cpu_count(logical=False)  # 物理核心

    # 获取内存信息
    mem = psutil.virtual_memory()
    memory_total = mem.total
    memory_used = mem.used
    memory_available = mem.available

    # 获取磁盘信息
    disk = psutil.disk_usage('/')
    disk_total = disk.total
    disk_used = disk.used
    disk_available = disk.free

    return jsonify({
        "core_count": core_count,
        "memory_total": memory_total,
        "memory_used": memory_used,
        "memory_available": memory_available,
        "disk_total": disk_total,
        "disk_used": disk_used,
        "disk_available": disk_available
    })
