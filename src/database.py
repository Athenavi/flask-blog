import os
import mysql.connector
from dotenv import load_dotenv
from mysql.connector import pooling


def get_db_connection():
    global db_pool  # 确保可以在函数内使用全局变量db_pool

    # 如果连接池尚未初始化，则初始化之
    if db_pool is None:
        # 加载 .env 文件
        load_dotenv()

        db_host = os.environ.get('DB_HOST') or os.getenv('DATABASE_HOST')
        db_port = os.environ.get('DB_PORT') or os.getenv('DATABASE_PORT')
        db_name = os.environ.get('DB_NAME') or os.getenv('DATABASE_NAME')
        db_user = os.environ.get('DB_USER') or os.getenv('DATABASE_USER')
        db_password = os.environ.get('DB_PASSWORD') or os.getenv('DATABASE_PASSWORD')

        pool_size = int(os.environ.get('DB_POOL_SIZE', 16)) or int(os.getenv('DATABASE_POOL_SIZE', 16))

        if not all([db_host, db_port, db_name, db_user, db_password]):
            print('数据库连接配置不完整，请检查 .env 文件或环境变量。')
            return None

        print('正在初始化数据库连接池...')
        try:
            db_pool = pooling.MySQLConnectionPool(
                pool_name="zb_pool",
                pool_size=pool_size,
                host=db_host,
                port=db_port,
                user=db_user,
                password=db_password,
                database=db_name,
                pool_reset_session=True
            )
        except mysql.connector.Error as err:
            print(f"数据库连接池初始化失败: {err}")
            return None

    # 从连接池获取连接
    return db_pool.get_connection()


def get_sqlalchemy_uri():
    # 加载 .env 文件
    load_dotenv()

    db_host = os.environ.get('DB_HOST') or os.getenv('DATABASE_HOST')
    db_port = os.environ.get('DB_PORT') or os.getenv('DATABASE_PORT')
    db_name = os.environ.get('DB_NAME') or os.getenv('DATABASE_NAME')
    db_user = os.environ.get('DB_USER') or os.getenv('DATABASE_USER')
    db_password = os.environ.get('DB_PASSWORD') or os.getenv('DATABASE_PASSWORD')

    if not all([db_host, db_port, db_name, db_user, db_password]):
        print('数据库连接配置不完整，请检查 .env 文件或环境变量。')
        return None

    # 构建SQLAlchemy数据库URI
    sqlalchemy_uri = f"mysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
    return sqlalchemy_uri


def test_database_connection():
    try:
        test_db = get_db_connection()
        if test_db is None:
            print("无法获取数据库连接。")
            return
        test_db.close()
        print("数据库连接成功。")
    except mysql.connector.Error as err:
        print(f"连接数据库失败: {err}")


def check_db():
    db = None
    try:
        db = get_db_connection()
        if db is None:
            print("无法获取数据库连接。")
            return None
        with db.cursor() as cursor:
            # 执行查询
            sql = "SHOW TABLES"  # 查询所有表的SQL语句
            cursor.execute(sql)
            result = cursor.fetchall()

            # 检查查询结果
            if result:
                table_names = [row[0] for row in result]
                if len(table_names) <= 6:
                    print("/".join(table_names))
                else:
                    print("/".join(table_names[:3] + ["..."] + table_names[-3:]))
                print(f"总表数: {len(result)}")
                print(f"----------------数据库表 预检测---------成功")
                return len(result)
            else:
                print("数据库中没有找到表。")
                print(f"----------------数据库表丢失")
                return 0

    except mysql.connector.Error as err:
        print(f"数据库错误: {err}")
        return None

    finally:
        # 关闭数据库连接
        if db:
            db.close()


db_pool = None
