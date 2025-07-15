# wsgi.py
import os
from src.logger_config import init_logger


def main():
    # 初始化日志，调用后会创建新的带时间戳的日志文件
    init_logger()

    if not os.path.isfile(".env"):
        print('配置文件不存在！详情请阅读 README.md')
        return

    from src.app import app, domain, run_security_checks
    # 以下安全检查示例代码可根据需要开启
    # if not run_security_checks(domain):
    #     print('请修改默认安全密钥！.env[security] 项, 并正确修改域名信息 然后重启程序！')
    #     return
    from src.database import test_database_connection, check_db
    test_database_connection()
    check_db()

    # 启动服务
    from waitress import serve
    serve(app, host='0.0.0.0', port=9421, threads=8, channel_timeout=60)


if __name__ == '__main__':
    main()
