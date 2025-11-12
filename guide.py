import os
import secrets
import socket
import string
from sqlite3 import connect as sqlite_connect

import psycopg2
from flask import Flask, render_template, request, jsonify
from mysql.connector import connect as mysql_connect


class GuideConfig:
    """引导配置类"""

    def __init__(self):
        self.steps = [
            {'id': 'welcome', 'title': '欢迎', 'description': '系统初始化引导'},
            {'id': 'database', 'title': '数据库', 'description': '数据库连接配置'},
            {'id': 'app', 'title': '应用配置', 'description': '基础应用设置'},
            {'id': 'admin', 'title': '管理员', 'description': '创建管理员账户'},
            {'id': 'optional', 'title': '可选配置', 'description': '其他功能配置'},
            {'id': 'complete', 'title': '完成', 'description': '系统初始化完成'}
        ]

    @staticmethod
    def generate_secret_key(length=32):
        """生成安全的 SECRET_KEY"""
        alphabet = string.ascii_letters + string.digits + '!@#$%^&*()_+-='
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def test_database_connection(db_config):
        """测试数据库连接"""
        db_engine = db_config.get('db_engine', '').lower()

        try:
            # 处理端口号，确保不为None且有默认值
            port = db_config.get('port')
            if port is None or port == '':
                # 根据数据库类型设置默认端口
                if db_engine == 'postgresql':
                    port = 5432
                elif db_engine == 'mysql':
                    port = 3306
                else:
                    port = None
            else:
                # 确保端口号是整数
                port = int(port)

            if db_engine == 'postgresql':
                conn = psycopg2.connect(
                    host=db_config.get('host'),
                    port=port,
                    user=db_config.get('user'),
                    password=db_config.get('password'),
                    database=db_config.get('database')
                )
            elif db_engine == 'mysql':
                conn = mysql_connect(
                    host=db_config.get('host'),
                    port=port,
                    user=db_config.get('user'),
                    password=db_config.get('password'),
                    database=db_config.get('database')
                )
            elif db_engine == 'sqlite':
                db_path = db_config.get('database', '')
                if not db_path:
                    return False, "SQLite数据库路径不能为空"
                # 对于SQLite，确保路径存在
                db_dir = os.path.dirname(db_path)
                if db_dir and not os.path.exists(db_dir):
                    os.makedirs(db_dir, exist_ok=True)
                conn = sqlite_connect(db_path)
            else:
                return False, "不支持的数据库类型"

            conn.close()
            return True, "数据库连接成功"
        except ValueError as ve:
            return False, f"参数错误: {str(ve)}"
        except Exception as e:
            return False, f"数据库连接失败: {str(e)}"

    @staticmethod
    def generate_env_file(config_data):
        """生成 .env 配置文件"""
        env_content = f"""# 数据库配置
DB_ENGINE={config_data.get('db_engine', 'postgresql')}
DB_HOST={config_data.get('db_host')}
DB_PORT={config_data.get('db_port')}
DB_NAME={config_data.get('db_name')}
DB_USER={config_data.get('db_user')}
DB_PASSWORD={config_data.get('db_password')}
DB_POOL_SIZE={config_data.get('db_pool_size', 16)}

# 通用配置
DOMAIN={config_data.get('domain')}
TITLE={config_data.get('title')}
BEIAN={config_data.get('beian', '')}

# 安全配置
SECRET_KEY={config_data.get('secret_key')}
JWT_EXPIRATION_DELTA={config_data.get('jwt_expiration', 604800)}
REFRESH_TOKEN_EXPIRATION_DELTA={config_data.get('refresh_expiration', 604800)}

# 邮件配置
MAIL_HOST={config_data.get('mail_host', '')}
MAIL_PORT={config_data.get('mail_port', 465)}
MAIL_USER={config_data.get('mail_user', '')}
MAIL_PASSWORD={config_data.get('mail_password', '')}

# Redis配置
REDIS_HOST={config_data.get('redis_host', 'localhost')}
REDIS_PORT={config_data.get('redis_port', 6379)}
REDIS_PASSWORD={config_data.get('redis_password', '')}
REDIS_DB={config_data.get('redis_db', 0)}
"""
        return env_content


def create_guide_app():
    """创建引导应用"""
    app = Flask(__name__,
                template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
                static_folder=os.path.join(os.path.dirname(__file__), 'static'))
    app.config['SECRET_KEY'] = secrets.token_hex(16)

    guide_config = GuideConfig()

    @app.route('/guide')
    @app.route('/')
    def guide_index():
        """引导首页"""
        try:
            return render_template('guide/guide.html', steps=guide_config.steps, current_step=0)
        except Exception as e:
            return jsonify({'success': False, 'message': f'加载引导页面失败: {str(e)}'})

    @app.route('/guide/test-db', methods=['POST'])
    def test_database():
        """测试数据库连接"""
        data = request.get_json()
        print("测试数据库连接数据:", data)

        # 统一的字段名映射处理
        def get_field(*possible_names):
            for name in possible_names:
                value = data.get(name)
                if value is not None and value != '':
                    return value
            return None

        db_config = {
            'db_engine': get_field('db_engine', 'engine'),
            'host': get_field('db_host', 'host'),
            'port': get_field('db_port', 'port'),
            'user': get_field('db_user', 'user'),
            'password': get_field('db_password', 'password'),
            'database': get_field('db_name', 'database', 'db_database')
        }

        print("处理后的数据库配置:", db_config)

        # 验证必需字段
        if not db_config['db_engine']:
            return jsonify({'success': False, 'message': '请选择数据库类型'})

        if db_config['db_engine'] != 'sqlite':
            required_fields = ['host', 'user', 'database']
            missing_fields = [field for field in required_fields if not db_config[field]]
            if missing_fields:
                return jsonify({'success': False, 'message': f'缺少必需字段: {", ".join(missing_fields)}'})

        success, message = guide_config.test_database_connection(db_config)
        return jsonify({'success': success, 'message': message})

    @app.route('/guide/generate-secret', methods=['POST'])
    def generate_secret():
        """生成 SECRET_KEY"""
        secret_key = guide_config.generate_secret_key()
        return jsonify({'secret_key': secret_key})

    @app.route('/guide/save-config', methods=['POST'])
    def save_config():
        """保存配置文件"""
        try:
            data = request.get_json()
            print("保存配置数据:", data)

            # 生成环境文件内容
            env_content = guide_config.generate_env_file(data)

            # 确定 .env 文件路径（项目根目录）
            base_dir = os.path.dirname(os.path.abspath(__file__))
            env_path = os.path.join(base_dir, '.env')

            # 备份现有配置文件（如果存在）
            if os.path.exists(env_path):
                backup_path = env_path + '.backup'
                os.rename(env_path, backup_path)

            # 写入新的配置文件
            with open(env_path, 'w', encoding='utf-8') as f:
                f.write(env_content)

            print(f"配置文件已保存到: {env_path}")

            return jsonify({
                'success': True,
                'message': '配置保存成功',
                'env_path': env_path
            })

        except Exception as e:
            print(f"保存配置失败: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'保存配置失败: {str(e)}'
            })

    @app.route('/guide/restart-info')
    def restart_info():
        """获取重启信息"""
        return jsonify({
            'manual_restart': True,
            'message': '配置已保存，请重启应用程序以应用新配置',
            'commands': [
                '手动重启命令:',
                '1. 如果使用开发服务器: Ctrl+C 然后重新启动',
                '2. 如果使用生产服务器: 重启对应的服务进程',
                '3. 如果使用 Docker: docker restart <container_name>',
                '4. 如果使用 systemd: systemctl restart your-service'
            ]
        })

    return app


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


def run_guide_app(host='0.0.0.0', port=9421):
    """运行引导应用"""
    app = create_guide_app()

    # 检查端口可用性
    final_port = port
    if not is_port_available(final_port, host):
        print(f"端口 {final_port} 已被占用，正在尝试9421-9430范围内的其他端口...")
        available_port = find_available_port(9421, 9430, host)

        if available_port:
            final_port = available_port
            print(f"找到可用端口: {final_port}")
        else:
            print("9421-9430范围内的所有端口均被占用。")
            final_port = get_user_port_input()

    print("=" * 50)
    print("系统引导程序启动")
    print(f"服务地址: http://{host}:{final_port}")
    print(f"内部地址: http://127.0.0.1:{final_port}")
    print("=" * 50)
    print("请通过浏览器访问上述地址完成系统初始化配置")
    print("=" * 50)

    try:
        from waitress import serve
        serve(app, host=host, port=final_port, threads=4)
    except KeyboardInterrupt:
        print("\n引导程序正在关闭...")
    except Exception as e:
        print(f"引导程序启动失败: {str(e)}")
        return False

    return True


if __name__ == '__main__':
    run_guide_app()
