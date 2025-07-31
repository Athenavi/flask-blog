import threading
import time

import psutil
from flask import Blueprint

from .views import monitor_bp, COLLECTION_INTERVAL, system_data


def register_plugin(app):
    # 创建蓝图
    bp = Blueprint('monitor_plugin', __name__)

    # 注册路由
    bp.register_blueprint(monitor_bp)

    # 创建插件对象（包含元数据）
    plugin = type('Plugin', (), {
        'name': 'monitor Plugin',
        'version': '0.0.1',
        'description': 'A simple plugin demonstrating plugin system capabilities',
        'author': '--author--',
        'blueprint': bp,
        'enabled': True,
        'config': app.config.get('HELLO_PLUGIN_CONFIG', {})
    })()

    # 添加自定义方法
    plugin.greet = lambda: f"Hello from {plugin.name}!"
    # 按需启动收集器
    if not data_collector.running:
        data_collector.start()

    return plugin


# 网络流量计算器（线程安全）
class NetworkTrafficCalculator:
    def __init__(self):
        self.last_net_io = psutil.net_io_counters()
        self.last_time = time.time()
        self.lock = threading.Lock()

    def get_traffic(self):
        with self.lock:
            current_time = time.time()
            current_net_io = psutil.net_io_counters()

            time_diff = current_time - self.last_time
            sent = (current_net_io.bytes_sent - self.last_net_io.bytes_sent) / time_diff / 1024
            recv = (current_net_io.bytes_recv - self.last_net_io.bytes_recv) / time_diff / 1024

            self.last_net_io = current_net_io
            self.last_time = current_time

            return round(sent, 2), round(recv, 2)


# 创建流量计算器
traffic_calculator = NetworkTrafficCalculator()


# 数据收集控制
class DataCollector:
    def __init__(self):
        self.running = False
        self.thread = None
        self.stop_event = threading.Event()

    def start(self):
        if self.running:
            return

        self.running = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.thread.start()

    def stop(self):
        if not self.running:
            return

        self.stop_event.set()
        self.thread.join(timeout=2.0)
        self.running = False

    def _collect_loop(self):
        while not self.stop_event.is_set():
            start_time = time.time()

            # 收集系统数据
            cpu_total = psutil.cpu_percent(interval=0.1)
            cpu_cores = psutil.cpu_percent(interval=0.1, percpu=True)
            memory = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            sent, recv = traffic_calculator.get_traffic()
            process_count = len(psutil.pids())

            # 存储数据
            system_data["cpu_total"].add(cpu_total)
            system_data["cpu_cores"].add(cpu_cores)
            system_data["memory"].add(memory)
            system_data["disk"].add(disk)
            system_data["network_sent"].add(sent)
            system_data["network_recv"].add(recv)
            system_data["process_count"].add(process_count)

            # 精确控制采集间隔
            elapsed = time.time() - start_time
            sleep_time = max(0, COLLECTION_INTERVAL - elapsed)
            time.sleep(sleep_time)


# 创建数据收集器
data_collector = DataCollector()
