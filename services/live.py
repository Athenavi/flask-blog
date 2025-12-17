import hashlib
import json
import secrets
from datetime import datetime, timedelta
import os


class LiveStreamService:
    """直播服务类"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
            
    def init_app(self, app):
        """初始化应用"""
        self.app = app
        
        # 从配置获取直播服务器设置
        self.rtmp_server = app.config.get('RTMP_SERVER', 'rtmp://localhost/live')
        self.http_server = app.config.get('HTTP_LIVE_SERVER', 'http://localhost:8080/hls')
        self.secret_key = app.config.get('LIVE_SECRET_KEY', 'default_secret')
        self.local_mode = app.config.get('LIVE_LOCAL_MODE', False)  # 本地模式
        
    def generate_stream_key(self, user_id):
        """
        为用户生成唯一的推流密钥
        """
        # 生成随机字符串和时间戳组合
        random_str = secrets.token_hex(16)
        timestamp = str(int(datetime.now().timestamp()))
        raw_key = f"{user_id}_{random_str}_{timestamp}_{self.secret_key}"
        
        # 使用SHA256生成最终的流密钥
        stream_key = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
        return stream_key[:32]  # 返回32位长度的密钥
        
    def generate_push_url(self, stream_key):
        """
        生成推流地址
        """
        if self.local_mode:
            # 本地模式下，我们不需要真实的RTMP服务器
            # 可以返回一个模拟的地址或者特殊标识
            return f"local://{stream_key}"
        return f"{self.rtmp_server}/{stream_key}"
        
    def generate_play_url(self, stream_key):
        """
        生成播放地址（支持多种格式）
        """
        if self.local_mode:
            # 本地模式下，我们可以返回一些本地资源用于演示
            return {
                'rtmp': f"rtmp://localhost/live/{stream_key}",
                'demo': f"/static/demo/live/{stream_key}.html",
                'local_player': f"/live/player/{stream_key}",
                'test_video': '/static/demo/test_video.mp4'
            }
        return {
            'rtmp': f"{self.rtmp_server}/{stream_key}",
            'http_flv': f"{self.http_server}/{stream_key}.flv",
            'hls': f"{self.http_server}/{stream_key}.m3u8",
            'websocket': f"ws://localhost:8080/ws/{stream_key}"
        }
        
    def verify_stream_key(self, stream_key, expected_key):
        """
        验证流密钥是否正确
        """
        return stream_key == expected_key


# 创建本地演示页面的函数
def create_local_demo_page(stream_key, template_path='templates/live/local_demo.html'):
    """
    创建本地演示页面
    """
    demo_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>本地直播间演示 - {stream_key}</title>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f0f0f0;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .video-placeholder {{
            width: 100%;
            height: 450px;
            background: linear-gradient(45deg, #333, #666);
            border-radius: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .controls {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }}
        button {{
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            background: #007bff;
            color: white;
        }}
        button:hover {{
            background: #0056b3;
        }}
        .chat {{
            border: 1px solid #ddd;
            border-radius: 5px;
            height: 200px;
            overflow-y: auto;
            padding: 10px;
            background: #f8f9fa;
        }}
        .chat-message {{
            margin-bottom: 10px;
            padding: 5px;
            border-bottom: 1px solid #eee;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>本地直播间演示</h1>
        <p>直播间密钥: {stream_key}</p>
        
        <div class="video-placeholder">
            本地直播演示区域<br>
            <small>实际部署时将显示真实视频流</small>
        </div>
        
        <div class="controls">
            <button onclick="startStream()">开始直播</button>
            <button onclick="stopStream()">结束直播</button>
            <button onclick="sendMessage()">发送消息</button>
        </div>
        
        <h3>聊天室</h3>
        <div class="chat" id="chatBox">
            <div class="chat-message"><strong>系统:</strong> 欢迎来到直播间！</div>
            <div class="chat-message"><strong>主播:</strong> 大家好，欢迎来到我的直播间！</div>
        </div>
    </div>

    <script>
        function startStream() {{
            alert('直播已开始（本地演示）');
            // 在实际应用中，这里会与后端通信更新直播间状态
        }}
        
        function stopStream() {{
            if (confirm('确定要结束直播吗？')) {{
                alert('直播已结束（本地演示）');
                // 在实际应用中，这里会与后端通信更新直播间状态
            }}
        }}
        
        function sendMessage() {{
            const chatBox = document.getElementById('chatBox');
            const msg = prompt('请输入消息:');
            if (msg) {{
                const messageDiv = document.createElement('div');
                messageDiv.className = 'chat-message';
                messageDiv.innerHTML = `<strong>观众:</strong> ${{msg}}`;
                chatBox.appendChild(messageDiv);
                chatBox.scrollTop = chatBox.scrollHeight;
            }}
        }}
    </script>
</body>
</html>
"""
    return demo_content
