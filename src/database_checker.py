import importlib
import logging
import os
import sys

from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError

from src.models import *

logger = logging.getLogger(__name__)


def check_model_consistency(app):
    """
    检查数据库模型与实际数据库表结构的一致性
    
    :param app: Flask应用实例
    :return: 不一致的表列表
    """
    with app.app_context():
        try:
            # 获取数据库元数据
            inspector = inspect(db.engine)
            
            # 获取所有模型类 - 兼容不同版本的SQLAlchemy
            model_classes = []
            processed_models = set()  # 用于跟踪已处理的模型，避免重复
            
            # 方法1: 从已导入的模型中获取（通过 from src.models import *）
            import src.models
            for attr_name in dir(src.models):
                attr = getattr(src.models, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, db.Model) and 
                    attr != db.Model and 
                    hasattr(attr, '__tablename__') and
                    attr.__name__ not in processed_models):  # 避免重复添加
                    model_classes.append(attr)
                    processed_models.add(attr.__name__)
            
            # 方法2: 如果上面没有找到模型，则尝试通过模块遍历查找
            if not model_classes:
                import pkgutil
                
                # 获取src.models包中的所有模块
                for importer, modname, ispkg in pkgutil.walk_packages(
                    path=src.models.__path__, 
                    prefix=src.models.__name__ + ".",
                    onerror=lambda x: None):
                    try:
                        module = importlib.import_module(modname)
                        # 查找模块中的所有模型类
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (isinstance(attr, type) and 
                                issubclass(attr, db.Model) and 
                                attr != db.Model and 
                                hasattr(attr, '__tablename__') and
                                attr.__name__ not in processed_models):  # 避免重复添加
                                model_classes.append(attr)
                                processed_models.add(attr.__name__)
                    except Exception:
                        pass
            
            # 方法3: 查找插件中的模型
            plugins_path = os.path.join(os.path.dirname(app.root_path), 'plugins')
            if os.path.exists(plugins_path):
                for plugin_name in os.listdir(plugins_path):
                    plugin_dir = os.path.join(plugins_path, plugin_name)
                    # 检查是否为有效的插件目录
                    if (os.path.isdir(plugin_dir) and 
                        plugin_name != "__pycache__" and
                        os.path.exists(os.path.join(plugin_dir, 'models.py'))):
                        
                        try:
                            # 对于特殊的插件（如live），需要调用初始化函数
                            if plugin_name == 'live':
                                # 动态导入插件模型模块
                                plugin_module_name = f"plugins.{plugin_name}.models"
                                plugin_module = importlib.import_module(plugin_module_name)
                                
                                # 初始化模型
                                if hasattr(plugin_module, 'init_models'):
                                    plugin_module.init_models(db)
                                    
                                # 查找模型类
                                for attr_name in dir(plugin_module):
                                    attr = getattr(plugin_module, attr_name)
                                    if (isinstance(attr, type) and 
                                        issubclass(attr, db.Model) and 
                                        attr != db.Model and 
                                        hasattr(attr, '__tablename__') and
                                        attr.__name__ not in processed_models):  # 避免重复添加
                                        model_classes.append(attr)
                                        processed_models.add(attr.__name__)
                            else:
                                # 动态导入插件模型模块
                                plugin_module_name = f"plugins.{plugin_name}.models"
                                plugin_module = importlib.import_module(plugin_module_name)
                                
                                # 查找模型类
                                for attr_name in dir(plugin_module):
                                    attr = getattr(plugin_module, attr_name)
                                    if (isinstance(attr, type) and 
                                        issubclass(attr, db.Model) and 
                                        attr != db.Model and 
                                        hasattr(attr, '__tablename__') and
                                        attr.__name__ not in processed_models):  # 避免重复添加
                                        model_classes.append(attr)
                                        processed_models.add(attr.__name__)
                                    
                        except Exception as e:
                            logger.warning(f"无法导入插件 {plugin_name} 的模型: {e}")
                            continue
            
            inconsistent_tables = []
            
            # 检查每个模型对应的表是否存在以及字段是否匹配
            for model_class in model_classes:
                table_name = model_class.__tablename__
                
                # 获取数据库中的表名列表
                existing_tables = inspector.get_table_names()
                
                # 检查表是否存在
                if table_name not in existing_tables:
                    inconsistent_tables.append({
                        'model': model_class.__name__,
                        'table': table_name,
                        'issue': 'missing_table',
                        'details': 'Table does not exist in database'
                    })
                    continue
                    
                # 表存在，检查字段是否匹配
                model_columns = {column.name: column for column in model_class.__table__.columns}
                db_columns = {column['name']: column for column in inspector.get_columns(table_name)}
                
                logger.debug(f"检查表 {table_name}:")
                logger.debug(f"  模型字段: {list(model_columns.keys())}")
                logger.debug(f"  数据库字段: {list(db_columns.keys())}")
                
                # 检查是否有缺失的字段（模型中有但数据库中没有）
                missing_columns = set(model_columns.keys()) - set(db_columns.keys())
                if missing_columns:
                    inconsistent_tables.append({
                        'model': model_class.__name__,
                        'table': table_name,
                        'issue': 'missing_columns',
                        'details': f'Missing columns: {", ".join(missing_columns)}'
                    })
                    continue
                    
                # 检查是否有额外的字段（数据库中有但模型中没有）
                extra_columns = set(db_columns.keys()) - set(model_columns.keys())
                if extra_columns:
                    inconsistent_tables.append({
                        'model': model_class.__name__,
                        'table': table_name,
                        'issue': 'extra_columns',
                        'details': f'Extra columns: {", ".join(extra_columns)}'
                    })
                    continue
                    
                # 检查字段类型是否匹配（简化比较）
                mismatched_columns = []
                for col_name, model_col in model_columns.items():
                    if col_name in db_columns:
                        db_col = db_columns[col_name]
                        # 简单比较类型（实际项目中可能需要更复杂的比较逻辑）
                        # 注意：这里只是粗略比较，因为不同数据库的类型表示可能不同
                        model_type_str = str(model_col.type).lower()
                        db_type_str = str(db_col['type']).lower()
                        
                        # 只有明显不匹配时才报告
                        if (model_type_str not in db_type_str and 
                            db_type_str not in model_type_str and
                            not (model_type_str.startswith('varchar') and db_type_str.startswith('character varying')) and
                            not (model_type_str.startswith('timestamp') and db_type_str.startswith('datetime')) and
                            not (model_type_str.startswith('integer') and db_type_str.startswith('int'))):
                            mismatched_columns.append({
                                'column': col_name,
                                'model_type': str(model_col.type),
                                'db_type': str(db_col['type'])
                            })
                
                if mismatched_columns:
                    inconsistent_tables.append({
                        'model': model_class.__name__,
                        'table': table_name,
                        'issue': 'column_type_mismatch',
                        'details': f'Column type mismatches: {mismatched_columns}'
                    })
            
            # 检查数据库中是否存在模型中未定义的多余表
            model_table_names = {model_class.__tablename__ for model_class in model_classes}
            existing_tables = inspector.get_table_names()
            extra_tables = set(existing_tables) - model_table_names
            
            if extra_tables:
                logger.warning(f"发现数据库中存在但模型中未定义的多余表: {', '.join(sorted(extra_tables))}")
            
            return inconsistent_tables, extra_tables
            
        except SQLAlchemyError as e:
            logger.error(f"检查数据库模型一致性时出错: {e}")
            return [{'error': 'sqlalchemy_error', 'message': str(e)}], set()
        except Exception as e:
            logger.error(f"检查数据库模型一致性时出现未知错误: {e}")
            return [{'error': 'unknown_error', 'message': str(e)}], set()


def prompt_user_for_action(inconsistent_tables):
    """
    提示用户选择如何处理不一致的表
    
    :param inconsistent_tables: 不一致的表列表
    :return: 用户选择的操作
    """
    if not inconsistent_tables:
        return 'continue'
        
    print("\n" + "="*60)
    print("数据库模型一致性检查发现问题:")
    print("="*60)
    
    for issue in inconsistent_tables:
        print(f"  表 '{issue['table']}' ({issue['model']} 模型) 存在问题:")
        print(f"    问题类型: {issue['issue']}")
        print(f"    详细信息: {issue['details']}")
    
    print("\n可选操作:")
    print("  1. 使用Flask-Migrate自动迁移数据库 (推荐)")
    print("  2. 忽略警告并继续启动")
    print("  3. 手动处理并退出")
    print("  4. 跳过自动迁移，继续启动（适用于复杂迁移场景）")
    
    while True:
        choice = input("\n请选择操作 (1/2/3/4): ").strip()
        if choice in ['1', '2', '3', '4']:
            return {
                '1': 'auto_migrate',
                '2': 'continue',
                '3': 'exit',
                '4': 'skip_migration'
            }[choice]
        else:
            print("无效的选择，请输入 1、2、3 或 4")


def auto_migrate_database(app):
    """
    使用Flask-Migrate自动迁移数据库
    
    :param app: Flask应用实例
    """
    print("\n正在使用Flask-Migrate自动迁移数据库...")
    
    try:
        with app.app_context():
            from flask_migrate import upgrade, stamp, init, migrate as flask_migrate
            
            # 检查迁移仓库状态
            env_py_exists = os.path.exists('alembic_migrations/env.py')
            versions_dir_exists = os.path.exists('alembic_migrations/versions')
            
            if not env_py_exists:
                print("初始化迁移仓库...")
                try:
                    # 如果目录存在但缺少必要文件，则重新初始化
                    if os.path.exists('alembic_migrations'):
                        # 删除旧的不完整目录
                        import shutil
                        shutil.rmtree('alembic_migrations')
                    
                    init(directory='alembic_migrations')
                    print("迁移仓库初始化完成")
                except Exception as e:
                    print(f"初始化迁移仓库失败: {e}")
                    print("请手动运行 'flask db init --directory alembic_migrations' 命令初始化迁移仓库")
                    return False
            else:
                print("迁移仓库已存在")
            
            # 生成迁移脚本
            print("生成迁移脚本...")
            try:
                flask_migrate(directory='alembic_migrations', message="Auto migration for missing tables/columns")
                print("迁移脚本生成完成")
            except Exception as e:
                print(f"生成迁移脚本时出错: {e}")
                print("可能需要手动检查模型定义")
                return False
            
            # 应用迁移
            print("应用数据库迁移...")
            try:
                upgrade(directory='alembic_migrations')
                print("数据库迁移应用完成")
            except Exception as e:
                print(f"应用数据库迁移时出错: {e}")
                return False
            
            print("数据库迁移完成!")
            return True
            
    except Exception as e:
        logger.error(f"自动迁移数据库时出错: {e}")
        print(f"自动迁移失败: {e}")
        return False


def handle_database_consistency_check(app):
    """
    处理数据库一致性检查的主要函数
    
    :param app: Flask应用实例
    """
    # 检查模型一致性
    inconsistent_tables, extra_tables = check_model_consistency(app)
    
    if not inconsistent_tables and not extra_tables:
        logger.info("数据库模型一致性检查通过")
        return
    
    # 如果有多余的表，显示警告但不处理
    if extra_tables:
        print("\n" + "="*60)
        print("警告：发现数据库中存在但模型中未定义的多余表:")
        print("="*60)
        print(f"  多余表: {', '.join(sorted(extra_tables))}")
        print("  这些表不会被自动删除，如有需要可手动处理。")
        print("="*60)
    
    if not inconsistent_tables:
        logger.info("数据库中有多余的表，但模型一致性检查通过")
        return
    
    # 提示用户选择操作
    action = prompt_user_for_action(inconsistent_tables)
    
    if action == 'auto_migrate':
        # 使用Flask-Migrate自动迁移数据库
        if auto_migrate_database(app):
            print("自动迁移完成，应用将继续启动...")
        else:
            print("自动迁移失败，应用将退出")
            sys.exit(1)
            
    elif action == 'exit':
        # 用户选择手动处理
        print("\n请手动处理上述数据库表问题后再启动应用")
        print("您可以通过以下方式解决:")
        print("1. 执行 'flask db init --directory alembic_migrations' (如果迁移仓库未初始化)")
        print("2. 执行 'flask db migrate --directory alembic_migrations' 和 'flask db upgrade --directory alembic_migrations' 命令")
        print("3. 检查模型定义是否正确")
        sys.exit(0)
        
    elif action == 'skip_migration':
        # 跳过自动迁移，继续启动
        print("用户选择跳过自动迁移，继续启动应用...")
        logger.warning("用户跳过了数据库自动迁移")
        return
        
    elif action == 'continue':
        # 用户选择忽略警告继续
        print("用户选择忽略警告，继续启动应用...")
        logger.warning("用户忽略了数据库模型不一致警告")
