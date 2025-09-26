import logging
from contextlib import contextmanager

import psycopg2
import redis
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from src.setting import AppConfig

app_config = AppConfig()

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


def test_database_connection():
    """测试数据库连接"""
    with get_db() as session:
        try:
            result = session.execute(text("SELECT version()")).scalar()
            logger.info(f"PostgreSQL版本: {result}")
            logger.info("数据库连接测试成功。")
            return True
        except psycopg2.Error as err:
            logger.error(f"连接数据库失败: {err}")
            return False
        except Exception as e:
            logger.error(f"测试数据库连接时发生错误: {e}")
            return False


def check_db():
    """检查数据库表结构"""
    inspector = inspect(engine)
    table_names = inspector.get_table_names(schema='public')

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


# Redis连接配置
redis_client = None
try:
    redis_client = redis.Redis(
        **app_config.RedisConfig
    )
    redis_client.ping()
    print("Redis连接成功")
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
    if cache_type == "redis" and redis_client is not None:
        try:
            redis_client.ping()
            print("已切换到Redis缓存")
        except Exception as e:
            print(f"无法切换到Redis: {e}")
    elif cache_type == "memory":
        print("已切换到内存缓存")
    else:
        print("不支持或不可用的缓存类型")


if __name__ == "__main__":
    # 测试代码
    print("开始测试数据库连接...")
    if test_database_connection():
        print("✓ 数据库连接测试成功")
        table_count = check_db()
        print(f"✓ 数据库表检查完成，找到 {table_count} 张表")
    else:
        print("✗ 数据库连接测试失败")
