import argparse
import os
import socket
import sys

from src.logger_config import init_pythonanywhere_logger, init_optimized_logger


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
    parser.add_argument('--pythonanywhere', action='store_true', default=False,
                        help='在 PythonAnywhere 上运行,将禁用日志文件')
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

    # 检查配置文件是否存在
    if not os.path.isfile(".env"):
        print("=" * 60)
        print("检测到系统未初始化，正在启动引导程序...")
        print("=" * 60)

        # 导入并运行引导程序
        try:
            # 运行引导应用
            from guide import run_guide_app
            success = run_guide_app(args.host, args.port)
            if success:
                print("引导程序已结束，请重新启动应用以使用主程序")
            else:
                print("引导程序运行失败")

        except ImportError as e:
            print(f"导入引导程序失败: {str(e)}")
            print("请确保 standalone_guide.py 文件存在")
        except Exception as e:
            print(f"启动引导程序时发生错误: {str(e)}")

        return

    # 初始化日志系统
    if args.pythonanywhere:
        logger = init_pythonanywhere_logger()
        if logger is None:
            print("PythonAnywhere 环境下日志系统初始化失败")
            sys.exit(1)
        logger.info("PythonAnywhere 环境下日志系统已启动")
    else:
        logger = init_optimized_logger()
        if logger is None:
            print("日志系统初始化失败")
            sys.exit(1)
        logger.info("日志系统已启动")

    # 处理更新选项
    if args.update_only:
        if not run_update():
            print("更新失败，程序将退出")
            sys.exit(1)
        return

    if args.update:
        if not run_update():
            print("更新失败，继续使用当前版本启动")

    # 测试数据库连接（仅在配置文件存在时）
    try:
        from src.database import test_database_connection, check_db
        test_database_connection()
        check_db()
    except ImportError:
        print("警告: 无法导入数据库模块，跳过数据库检查")
    except Exception as e:
        print(f"数据库连接测试失败: {str(e)}")
        if not args.skip_guide:
            print("建议运行引导程序重新配置数据库")
            response = input("是否立即启动引导程序? (y/N): ")
            if response.lower() in ['y', 'yes']:
                from guide import run_guide_app
                run_guide_app(args.host, args.port)
                return
        sys.exit(1)

    # 检查端口可用性
    final_port = args.port
    if not is_port_available(final_port, args.host):
        print(f"端口 {final_port} 已被占用，正在尝试9421-9430范围内的其他端口...")
        available_port = find_available_port(9421, 9430, args.host)

        if available_port:
            final_port = available_port
            print(f"找到可用端口: {final_port}")
        else:
            print("9421-9430范围内的所有端口已被占用。")
            final_port = get_user_port_input()

    # 导入应用
    try:
        from src.app import create_app
    except ImportError as e:
        print(f"导入应用失败: {str(e)}")
        print("请检查应用模块是否正确安装")
        sys.exit(1)

    # 显示启动信息
    print("=" * 50)
    print("应用程序正在启动...")
    print(f"服务地址: http://{args.host}:{final_port}")
    print(f"内部地址: http://127.0.0.1:{final_port}")
    print("=" * 50)

    # 启动服务
    try:
        from waitress import serve
        app = create_app()
        serve(app, host=args.host, port=final_port, threads=8, channel_timeout=60)
    except KeyboardInterrupt:
        print("\n服务器正在关闭...")
    except Exception as e:
        print(f"服务器启动失败: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
