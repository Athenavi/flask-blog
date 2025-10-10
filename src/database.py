import logging
import os
from contextlib import contextmanager

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from src.setting import AppConfig

app_config = AppConfig()

# 根据数据库引擎动态引入相关依赖
DB_ENGINE = os.getenv('DB_ENGINE', 'postgresql').lower()

# 数据库驱动映射
DB_DRIVERS = {
    'postgresql': 'psycopg2',
    'mysql': 'pymysql',
    'sqlite': 'sqlite3',
    'oracle': 'cx_oracle',
    'mssql': 'pyodbc'
}


def get_database_driver():
    """获取数据库驱动名称"""
    return DB_DRIVERS.get(DB_ENGINE, 'psycopg2')


def import_database_dependencies():
    """动态导入数据库相关依赖"""
    global DatabaseError

    try:
        if DB_ENGINE == 'postgresql':
            import psycopg2
            from psycopg2 import Error as DatabaseError
            logger.info("使用 PostgreSQL 数据库 (psycopg2)")
            return psycopg2, DatabaseError

        elif DB_ENGINE == 'mysql':
            import pymysql
            from pymysql import Error as DatabaseError
            pymysql.install_as_MySQLdb()  # 兼容MySQLdb
            logger.info("使用 MySQL 数据库 (pymysql)")
            return pymysql, DatabaseError

        elif DB_ENGINE == 'sqlite':
            import sqlite3
            from sqlite3 import Error as DatabaseError
            logger.info("使用 SQLite 数据库")
            return sqlite3, DatabaseError

        elif DB_ENGINE == 'oracle':
            import cx_Oracle
            from cx_Oracle import Error as DatabaseError
            logger.info("使用 Oracle 数据库 (cx_Oracle)")
            return cx_Oracle, DatabaseError

        elif DB_ENGINE == 'mssql':
            import pyodbc
            from pyodbc import Error as DatabaseError
            logger.info("使用 SQL Server 数据库 (pyodbc)")
            return pyodbc, DatabaseError

        else:
            # 默认使用 PostgreSQL
            import psycopg2
            from psycopg2 import Error as DatabaseError
            logger.warning(f"不支持的数据库引擎: {DB_ENGINE}，默认使用 PostgreSQL")
            return psycopg2, DatabaseError

    except ImportError as e:
        logger.error(f"无法导入 {DB_ENGINE} 数据库驱动: {e}")
        logger.info(f"请安装: pip install {DB_DRIVERS.get(DB_ENGINE, 'psycopg2')}")
        raise


# 动态导入数据库驱动
db_driver, DatabaseError = import_database_dependencies()

# 创建带有连接池的引擎
engine = create_engine(
    app_config.SQLALCHEMY_DATABASE_URI,
    poolclass=QueuePool,  # 使用队列连接池
    **app_config.pool_config
)

# 创建会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@contextmanager
def get_db():
    """
    提供数据库session的上下文管理器，确保session正确关闭
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"数据库操作失败: {e}")
        raise
    finally:
        db.close()


def get_database_version_query():
    """根据数据库类型返回版本查询语句"""
    version_queries = {
        'postgresql': "SELECT version()",
        'mysql': "SELECT version()",
        'sqlite': "SELECT sqlite_version()",
        'oracle': "SELECT * FROM v$version WHERE banner LIKE 'Oracle%'",
        'mssql': "SELECT @@version"
    }
    return version_queries.get(DB_ENGINE, "SELECT version()")


def test_database_connection():
    """测试数据库连接"""
    with get_db() as session:
        try:
            version_query = get_database_version_query()
            result = session.execute(text(version_query)).scalar()
            logger.info(f"{DB_ENGINE.upper()} 版本: {result}")
            logger.info("数据库连接测试成功。")
            return True
        except DatabaseError as err:
            logger.error(f"连接数据库失败: {err}")
            return False
        except Exception as e:
            logger.error(f"测试数据库连接时发生错误: {e}")
            return False


def get_table_names_by_engine(inspector, schema):
    """根据数据库引擎获取表名列表"""
    try:
        if DB_ENGINE in ['oracle']:
            return inspector.get_table_names(schema=schema.upper() if schema else None)
        elif DB_ENGINE in ['mssql']:
            return inspector.get_table_names(schema=schema)
        else:
            return inspector.get_table_names(schema=schema or 'public')
    except Exception as e:
        logger.warning(f"获取表名时出错: {e}，尝试使用默认方式")
        return inspector.get_table_names()


def check_db():
    """检查数据库表结构"""
    inspector = inspect(engine)

    # 根据数据库类型确定schema
    schema = None
    if DB_ENGINE in ['oracle']:
        schema = app_config.get('DB_SCHEMA', 'SYSTEM')  # Oracle 默认schema
    elif DB_ENGINE in ['mssql']:
        schema = app_config.get('DB_SCHEMA', 'dbo')  # SQL Server 默认schema

    table_names = get_table_names_by_engine(inspector, schema)

    # 检查查询结果
    if table_names:
        if len(table_names) <= 6:
            tables_str = "/".join(table_names)
        else:
            tables_str = "/".join(table_names[:3] + ["..."] + table_names[-3:])

        logger.info(f"检测到表: {tables_str}")
        logger.info(f"总表数: {len(table_names)}")
        print(f"----------------数据库表预检测成功---------")
        return len(table_names)
    else:
        logger.warning("数据库中没有找到表。")
        print(f"----------------数据库表丢失")
        return 0


def get_database_info():
    """获取数据库信息"""
    return {
        'engine': DB_ENGINE,
        'driver': get_database_driver(),
        'version_query': get_database_version_query(),
        'supported': DB_ENGINE in DB_DRIVERS
    }


# Redis连接配置
redis_client = None
try:
    import redis

    redis_client = redis.Redis(
        **app_config.RedisConfig
    )
    redis_client.ping()
    print("Redis连接成功")
except ImportError:
    print("Redis Python客户端未安装，将使用内存缓存")
    redis_client = None
except Exception as e:
    print(f"Redis连接失败，将使用内存缓存: {e}")
    redis_client = None


# 辅助函数：检查当前使用的缓存类型
def get_cache_status():
    """获取当前缓存状态"""
    if redis_client is not None:
        try:
            redis_client.ping()
            return "redis"
        except:
            return "memory"
    return "memory"


# 辅助函数：手动切换缓存类型（用于测试或特殊场景）
def switch_cache_type(cache_type):
    """手动切换缓存类型（主要用于测试）"""
    global redis_client
    if cache_type == "redis":
        try:
            import redis
            redis_client = redis.Redis(**app_config.RedisConfig)
            redis_client.ping()
            print("已切换到Redis缓存")
        except Exception as e:
            print(f"无法切换到Redis: {e}")
            redis_client = None
    elif cache_type == "memory":
        redis_client = None
        print("已切换到内存缓存")
    else:
        print("不支持或不可用的缓存类型")


if __name__ == "__main__":
    # 测试代码
    db_info = get_database_info()
    print(f"数据库引擎: {db_info['engine']}")
    print(f"数据库驱动: {db_info['driver']}")
    print(f"支持状态: {'是' if db_info['supported'] else '否'}")

    print("开始测试数据库连接...")
    if test_database_connection():
        print("✓ 数据库连接测试成功")
        table_count = check_db()
        print(f"✓ 数据库表检查完成，找到 {table_count} 张表")
    else:
        print("✗ 数据库连接测试失败")
