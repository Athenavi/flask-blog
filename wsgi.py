import sys
import warnings

from gevent import monkey

monkey.patch_all()

import argparse
import os
import socket
import logging
import glob

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
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
    parser.add_argument('--nolog', action='store_true', default=False,
                        help='禁用日志文件')
    parser.add_argument('--env', type=str, choices=['prod', 'dev', 'test', 'production', 'development', 'testing'],
                        default='prod', help='指定运行环境: prod/dev/test (默认: prod)')
    parser.add_argument('--run-debug-scripts', action='store_true',
                        help='执行 debug 目录下的脚本 (默认操作: 执行')
    parser.add_argument('--guide', action='store_true', default=False,
                        help='强制启动系统初始化引导 (默认: False)')
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
    logging.info("正在检查更新...")
    try:
        # 导入并运行更新程序
        from update import main as update_main, start_auto_update_thread
        # 启动自动更新检查线程（如果尚未启动）
        start_auto_update_thread()
        update_main()
        logging.info("更新完成")
        return True
    except Exception as e:
        logging.error(f"更新过程中出错: {str(e)}")
        return False


# 创建 Flask 应用实例，供 Flask 命令行工具使用
from src.app import create_app
from src.setting import ProductionConfig, DevelopmentConfig, TestingConfig


# 根据环境参数选择配置类
def get_config_by_env(env):
    # 支持简写和完整形式
    if env in ['prod', 'production']:
        return ProductionConfig()
    elif env in ['dev', 'development']:
        return DevelopmentConfig()
    elif env in ['test', 'testing']:
        return TestingConfig()
    else:
        return ProductionConfig()  # 默认使用生产环境配置


def execute_debug_scripts():
    """执行 debug 目录下的所有 Python 脚本"""
    debug_dir = os.path.join(os.path.dirname(__file__), 'debug')

    # 获取 debug 目录下所有 .py 文件
    debug_scripts = glob.glob(os.path.join(debug_dir, '*.py'))

    # 按文件名排序，确保按顺序执行
    debug_scripts.sort()

    logging.info("开始执行 debug 目录下的脚本...")
    for script_path in debug_scripts:
        try:
            script_name = os.path.basename(script_path)
            logging.info(f"正在执行: {script_name}")

            # 执行脚本并捕获输出，添加项目根目录到PYTHONPATH
            import subprocess
            import sys
            # 注意：这里不需要再次导入 os，因为它已经在文件顶部导入了

            # 复制当前环境变量并添加项目根目录到PYTHONPATH
            env = os.environ.copy()
            project_root = os.path.dirname(__file__)
            if 'PYTHONPATH' in env:
                env['PYTHONPATH'] = f"{project_root};{env['PYTHONPATH']}"
            else:
                env['PYTHONPATH'] = project_root

            result = subprocess.run([sys.executable, script_path],
                                    capture_output=True, text=True, cwd=os.path.dirname(__file__), env=env)

            if result.stdout:
                logging.info(f"{script_name} 输出:\n{result.stdout}")
            if result.stderr:
                logging.error(f"{script_name} 错误:\n{result.stderr}")

            logging.info(f"完成执行: {script_name} (返回码: {result.returncode})")
        except Exception as e:
            logging.error(f"执行 {script_name} 时出错: {str(e)}")

    logging.info("debug 目录下的脚本执行完成")


# 为 Flask CLI 创建应用实例
application = create_app()


def main():
    # 解析命令行参数
    args = parse_arguments()

    # 检查配置文件是否存在或强制启动引导程序
    if not os.path.isfile(".env") or args.guide:
        logging.info("=" * 60)
        if not os.path.isfile(".env"):
            logging.info("检测到系统未初始化，正在启动引导程序...")
        else:
            logging.info("强制启动系统初始化引导...")
        logging.info("=" * 60)

        # 导入并运行引导程序
        try:
            # 运行引导应用
            from guide import run_guide_app
            success = run_guide_app(args.host, args.port)
            if success:
                logging.info("引导程序已结束，请重新启动应用以使用主程序")
            else:
                logging.error("引导程序运行失败")

        except ImportError as e:
            logging.error(f"导入引导程序失败: {str(e)}")
            logging.error("请确保 guide.py 文件存在")
        except Exception as e:
            logging.error(f"启动引导程序时发生错误: {str(e)}")

        return

    # 初始化日志系统
    if args.nolog:
        logger = init_pythonanywhere_logger()
        if logger is None:
            logger.error("PythonAnywhere 环境下日志系统初始化失败")
            sys.exit(1)
        logger.info("PythonAnywhere 环境下日志系统已启动")
    else:
        logger = init_optimized_logger()
        if logger is None:
            logger.error("日志系统初始化失败")
            sys.exit(1)
        logger.info("日志系统已启动")

    # 处理更新选项
    if args.update_only:
        if not run_update():
            logger.error("更新失败，程序将退出")
            sys.exit(1)
        return

    if args.update:
        if not run_update():
            logger.warning("更新失败，继续使用当前版本启动")

    # 在数据库连接前执行debug脚本
    config = get_config_by_env(args.env)

    # 默认执行 debug 脚本，无论环境如何（除非明确禁用）
    should_run_debug_scripts = args.run_debug_scripts or True  # 默认为True
    if should_run_debug_scripts and not args.env in ['dev', 'development']:
        execute_debug_scripts()

    # 数据库一致性检查（现在是必需步骤）
    logger.info("开始检查数据库模型一致性...")
    try:
        from src.database_checker import handle_database_consistency_check
        # 创建应用实例用于检查
        app = create_app(config)
        handle_database_consistency_check(app)
    except ImportError as e:
        logger.error(f"导入数据库检查模块失败: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"数据库一致性检查过程中出错: {str(e)}")
        sys.exit(1)

    # 测试数据库连接（仅在配置文件存在时）
    try:
        from src.database import test_database_connection, check_db
        test_database_connection()
        check_db()
    except ImportError:
        logger.warning("警告: 无法导入数据库模块，跳过数据库检查")
    except Exception as e:
        logger.error(f"数据库连接测试失败: {str(e)}")
        logger.info("建议运行引导程序重新配置数据库")
        response = input("是否立即启动引导程序? (y/N): ")
        if response.lower() in ['y', 'yes']:
            from guide import run_guide_app
            run_guide_app(args.host, args.port)
            return
        sys.exit(1)

    # 检查端口可用性
    final_port = args.port
    if not is_port_available(final_port, args.host):
        logger.warning(f"端口 {final_port} 已被占用，正在尝试9421-9430范围内的其他端口...")
        available_port = find_available_port(9421, 9430, args.host)

        if available_port:
            final_port = available_port
            logger.info(f"找到可用端口: {final_port}")
        else:
            logger.error("9421-9430范围内的所有端口已被占用。")
            final_port = get_user_port_input()

    # 显示启动信息
    logger.info("=" * 50)
    logger.info("应用程序正在启动...")
    logger.info(f"服务地址: http://{args.host}:{final_port}")
    logger.info(f"内部地址: http://127.0.0.1:{final_port}")
    logger.info(f"运行环境: {args.env}")
    logger.info("=" * 50)

    # 在启动服务前执行debug脚本
    try:
        # 根据环境参数选择相应的配置类
        config = get_config_by_env(args.env)

        # 默认执行 debug 脚本，无论环境如何
        should_run_debug_scripts = args.run_debug_scripts or True  # 默认为True
        if should_run_debug_scripts:
            execute_debug_scripts()

        app = create_app(config)

        # 使用 gevent websocket 服务器启动应用
        from gevent.pywsgi import WSGIServer
        from geventwebsocket.handler import WebSocketHandler
        http_server = WSGIServer((args.host, final_port), app, handler_class=WebSocketHandler)
        logger.info("使用 gevent websocket 服务器启动应用")
        logger.info(f"运行环境配置: {args.env}")
        http_server.serve_forever()

    except KeyboardInterrupt:
        logger.info("\n服务器正在关闭...")
    except Exception as e:
        logger.error(f"服务器启动失败: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
