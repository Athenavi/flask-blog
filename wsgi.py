# wsgi.py
import os
from src.logger_config import init_logger


def main():
    # 初始化日志，调用后会创建新的带时间戳的日志文件
    init_logger()

    if not os.path.isfile(".env"):
        print('配置文件不存在！详情请阅读 README.md')
        return

    from src.app import app
    from src.database import test_database_connection, check_db
    test_database_connection()
    check_db()

    # 启动服务
    from waitress import serve
    serve(app, host='0.0.0.0', port=9421, threads=8, channel_timeout=60)


if __name__ == '__main__':
    main()
