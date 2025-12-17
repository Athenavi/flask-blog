"""
应用监控系统
提供健康检查、性能指标和系统状态监控功能
"""

import time
from datetime import datetime

import psutil
from flask import jsonify, request, g

from src.logger_config import REQUEST_COUNT, REQUEST_DURATION


class SystemMonitor:
    """系统监控类"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """初始化监控"""
        # 注册监控中间件
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # 注册监控端点
        self.register_monitoring_endpoints(app)
        
    def before_request(self):
        """请求前处理"""
        g.start_time = time.time()
        
    def after_request(self, response):
        """请求后处理"""
        # 记录请求指标
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown',
                status=response.status_code
            ).inc()
            REQUEST_DURATION.observe(duration)
            
        return response
        
    def register_monitoring_endpoints(self, app):
        """注册监控相关端点"""
        
        @app.route('/system-status')
        def system_status():
            """系统状态端点"""
            # 获取系统资源使用情况
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return jsonify({
                'timestamp': datetime.utcnow().isoformat(),
                'cpu': {
                    'percent': cpu_percent
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'used': memory.used,
                    'percent': memory.percent
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': (disk.used / disk.total) * 100
                },
                'network': self.get_network_stats()
            }), 200
            
    def get_network_stats(self):
        """获取网络统计信息"""
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }


# 全局监控实例
monitor = SystemMonitor()