import os


def main():
    if not os.path.isfile(".env"):
        print('配置文件不存在！详情请阅读 README.md')
        return
    if not os.path.exists('./temp/app.log'):
        print('日志文件未创建！')
        log_path = "temp"
        try:
            os.makedirs(log_path)
        except FileExistsError:
            print(f'目录 {log_path} 已存在，跳过创建。')
        finally:
            with open(log_path + "/app.log", "w", encoding='utf-8') as file:
                file.write("------zyBlog_V2.0------")
        print('success------日志文件已自动创建！！(提示:若创建失败，你可以自行创建 temp 目录并在其中创建 app.log 文件)')
        print('现在你可以重新启动程序！')
        return
    else:
        from src.app import app, domain, run_security_checks
        #if not run_security_checks(domain):
        #    print('请修改默认安全密钥！.env[security] 项, 并正确修改域名信息 然后重启程序！')
        #    return
        from src.database import test_database_connection, check_db
        test_database_connection()
        check_db()
        print("从浏览器打开: http://127.0.0.1:9421")
        from waitress import serve
        # 运行 Waitress
        serve(app, host='0.0.0.0', port=9421, threads=8, channel_timeout=60)


if __name__ == '__main__':
    main()
