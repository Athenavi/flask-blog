# wsgi.py
import argparse
import os
import socket
import sys

from src.logger_config import init_optimized_logger


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='启动应用程序')
    parser.add_argument('--port', type=int, default=9421,
                        help='应用程序运行的端口号 (默认: 9421)')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='绑定主机地址 (默认: 0.0.0.0)')
    parser.add_argument('--update', action='store_true',
                        help='启动前执行更新检查')
    parser.add_argument('--update-only', action='store_true',
                        help='仅执行更新而不启动服务器')
    return parser.parse_args()


def is_port_available(port, host='0.0.0.0'):
    """检查端口是否可用"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def find_available_port(start_port, end_port, host='0.0.0.0'):
    """在指定范围内查找可用端口"""
    for port in range(start_port, end_port + 1):
        if is_port_available(port, host):
            return port
    return None


def get_user_port_input():
    """获取用户输入的端口号"""
    while True:
        try:
            user_port = int(input("请提供一个可用的端口号: "))
            if 1 <= user_port <= 65535:
                if is_port_available(user_port):
                    return user_port
                else:
                    print(f"端口 {user_port} 已被占用，请尝试其他端口。")
            else:
                print("端口号必须在 1-65535 范围内。")
        except ValueError:
            print("请输入有效的数字端口号。")


def run_update():
    """执行更新程序"""
    print("正在检查更新...")
    try:
        # 导入并运行更新程序
        from update import main as update_main
        update_main()
        print("更新完成")
        return True
    except Exception as e:
        print(f"更新过程中出错: {str(e)}")
        return False


def main():
    # 解析命令行参数
    args = parse_arguments()

    # 初始化日志系统
    init_optimized_logger()

    # 检查配置文件
    if not os.path.isfile(".env"):
        print('配置文件不存在！详情请阅读 README.md')
        return

    # 处理更新选项
    if args.update_only:
        if not run_update():
            print("更新失败，程序将退出")
            sys.exit(1)
        return

    if args.update:
        if not run_update():
            print("更新失败，继续使用当前版本启动")

    # 测试数据库连接
    from src.database import test_database_connection, check_db
    try:
        test_database_connection()
        check_db()
    except Exception as e:
        print(f"数据库连接测试失败: {str(e)}")
        sys.exit(1)

    # 检查端口可用性
    final_port = args.port

    # 如果默认端口被占用，尝试9421-9430范围内的端口
    if not is_port_available(final_port, args.host):
        print(f"端口 {final_port} 已被占用，正在尝试9421-9430范围内的其他端口...")
        available_port = find_available_port(9421, 9430, args.host)

        if available_port:
            final_port = available_port
            print(f"找到可用端口: {final_port}")
        else:
            print("9421-9430范围内的所有端口均被占用。")
            final_port = get_user_port_input()

    # 导入应用
    from src.app import create_app

    # 显示端口信息
    print("=" * 50)
    print(f"应用程序正在启动...")
    print(f"服务地址: http://{args.host}:{final_port}")
    print(f"内部地址: http://127.0.0.1:{final_port}")
    print("=" * 50)
    print("您可以使用以下方式访问应用:")
    print(f"1. 直接访问: http://您的域名:{final_port}")
    print(
        f"2. 使用域名: 在您的云服务器供应商的域名控制台将域名解析到服务器IP，并通过反向代理将流量转发到端口 {final_port}")
    print("=" * 50)

    # 启动服务
    try:
        from waitress import serve
        serve(create_app(), host=args.host, port=final_port, threads=8, channel_timeout=60)
    except KeyboardInterrupt:
        print("\n服务器正在关闭...")
    except Exception as e:
        print(f"服务器启动失败: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
