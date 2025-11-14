"""
数据库备份工具库
基于 Flask-SQLAlchemy 的数据库结构和数据备份工具
"""

import gzip
import os
import zipfile
from datetime import datetime, date

from sqlalchemy import text


def _get_timestamp():
    """获取当前时间戳字符串"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


class DatabaseBackup:
    """数据库备份工具类"""

    def __init__(self, db, backup_dir="backups"):
        """
        初始化备份工具

        Args:
            db: Flask-SQLAlchemy 数据库实例
            backup_dir: 备份文件存储目录
        """
        self.db = db
        self.backup_dir = backup_dir
        self._ensure_backup_dir()

        # 获取数据库方言
        if hasattr(db, 'engine') and db.engine:
            self.dialect_name = db.engine.dialect.name
        elif db.session.bind:
            self.dialect_name = db.session.bind.dialect.name
        else:
            raise ValueError("无法确定数据库方言 - 没有可用的数据库引擎或会话绑定")

    def _ensure_backup_dir(self):
        """确保备份目录存在"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)

    def _get_tables(self):
        """获取需要备份的表列表"""
        metadata = self.db.metadata
        all_tables = list(metadata.tables.keys())

        # 过滤掉系统表
        exclude_tables = ['alembic_version']
        tables_to_backup = [table for table in all_tables if table not in exclude_tables]

        return tables_to_backup

    def _get_connection(self):
        """获取数据库连接"""
        if self.db.session.bind:
            return self.db.session.connection()
        elif hasattr(self.db, 'engine'):
            return self.db.engine.connect()
        else:
            raise ConnectionError("没有可用的数据库连接")

    def _format_value(self, value, column_type=None):
        """格式化数据库值用于SQL语句"""
        if value is None:
            return "NULL"
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, bool):
            if self.dialect_name == 'sqlite':
                return "1" if value else "0"
            else:
                return "TRUE" if value else "FALSE"
        elif isinstance(value, (datetime, date)):
            return f"'{value.isoformat()}'"
        else:
            escaped = str(value).replace("'", "''")
            return f"'{escaped}'"

    def backup_schema(self, filepath=None, compress=False):
        """
        备份数据库结构

        Args:
            filepath: 备份文件路径，如果为None则自动生成
            compress: 是否压缩备份文件

        Returns:
            str: 备份文件路径
        """
        if filepath is None:
            timestamp = _get_timestamp()
            filename = f"schema_backup_{timestamp}.sql"
            filepath = os.path.join(self.backup_dir, filename)

        if compress and not filepath.endswith('.gz'):
            filepath += '.gz'

        try:
            print(f"开始备份数据库结构: {self.dialect_name}")

            tables = self._get_tables()
            print(f"找到 {len(tables)} 个表需要备份")

            schema_sql = ["-- Database Schema Backup",
                          f"-- Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                          f"-- Database dialect: {self.dialect_name}", ""]

            connection = self._get_connection()

            for table in tables:
                print(f"处理表结构: {table}")

                if self.dialect_name == 'sqlite':
                    # SQLite 获取表结构
                    try:
                        create_table_result = connection.execute(text(
                            f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table}'"
                        ))
                        create_row = create_table_result.fetchone()
                        if create_row and create_row[0]:
                            create_sql = create_row[0]
                            schema_sql.append(create_sql + ";")
                        else:
                            schema_sql.append(f"-- Table {table} not found in sqlite_master")

                        # 获取索引
                        indexes_result = connection.execute(text(
                            f"SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='{table}' AND sql IS NOT NULL"
                        ))
                        for row in indexes_result:
                            if row[0]:
                                schema_sql.append(row[0] + ";")

                    except Exception as e:
                        schema_sql.append(f"-- Error processing table {table}: {str(e)}")
                        print(f"处理SQLite表 {table} 时出错: {str(e)}")

                elif self.dialect_name == 'postgresql':
                    # PostgreSQL 获取表结构
                    try:
                        create_table_result = connection.execute(text(
                            f"SELECT column_name, data_type, is_nullable, column_default "
                            f"FROM information_schema.columns WHERE table_name = '{table}' "
                            f"ORDER BY ordinal_position"
                        ))

                        columns = []
                        for row in create_table_result:
                            col_def = f"{row[0]} {row[1]}"
                            if row[2] == 'NO':
                                col_def += " NOT NULL"
                            if row[3]:
                                col_def += f" DEFAULT {row[3]}"
                            columns.append(col_def)

                        if columns:
                            schema_sql.append(f"CREATE TABLE {table} (")
                            schema_sql.append(",\n".join(columns))
                            schema_sql.append(");")

                    except Exception as e:
                        schema_sql.append(f"-- Error processing table {table}: {str(e)}")
                        print(f"处理PostgreSQL表 {table} 时出错: {str(e)}")

                schema_sql.append("")

            # 写入文件
            content = '\n'.join(schema_sql)
            if compress:
                with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                    f.write(content)
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)

            file_size = os.path.getsize(filepath)
            print(f"数据库结构备份完成: {filepath} ({file_size} 字节)")
            return filepath

        except Exception as e:
            print(f"数据库结构备份错误: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def backup_data(self, filepath=None, compress=False, batch_size=1000):
        """
        备份数据库数据

        Args:
            filepath: 备份文件路径，如果为None则自动生成
            compress: 是否压缩备份文件
            batch_size: 每批处理的记录数（用于大表）

        Returns:
            str: 备份文件路径
        """
        if filepath is None:
            timestamp = _get_timestamp()
            filename = f"data_backup_{timestamp}.sql"
            filepath = os.path.join(self.backup_dir, filename)

        if compress and not filepath.endswith('.gz'):
            filepath += '.gz'

        try:
            print(f"开始备份数据库数据: {self.dialect_name}")

            tables = self._get_tables()
            print(f"找到 {len(tables)} 个表需要备份")

            data_sql = [
                "-- Database Data Backup",
                f"-- Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"-- Database dialect: {self.dialect_name}",
                ""
            ]

            total_records = 0
            connection = self._get_connection()

            for table_name in tables:
                print(f"备份表数据: {table_name}")

                # 获取表的列信息
                columns_info = []
                if self.dialect_name == 'sqlite':
                    result = connection.execute(text(f"PRAGMA table_info({table_name})"))
                    columns_info = [{'name': row[1], 'type': row[2]} for row in result]
                elif self.dialect_name == 'postgresql':
                    result = connection.execute(text(
                        f"SELECT column_name, data_type FROM information_schema.columns "
                        f"WHERE table_name = '{table_name}' ORDER BY ordinal_position"
                    ))
                    columns_info = [{'name': row[0], 'type': row[1]} for row in result]

                # 执行查询获取数据
                try:
                    result = connection.execute(text(f"SELECT * FROM {table_name}"))
                    rows = result.fetchall()
                except Exception as e:
                    print(f"查询表 {table_name} 时出错: {str(e)}")
                    data_sql.append(f"-- Error querying table {table_name}: {str(e)}")
                    data_sql.append("")
                    continue

                if not rows:
                    data_sql.append(f"-- Table {table_name} is empty")
                    data_sql.append("")
                    continue

                # 生成INSERT语句
                table_records = 0
                columns = [col['name'] for col in columns_info] if columns_info else list(rows[0]._mapping.keys())

                for row in rows:
                    values = [self._format_value(value) for value in row]
                    insert_sql = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({', '.join(values)});"
                    data_sql.append(insert_sql)
                    total_records += 1
                    table_records += 1

                data_sql.append(f"-- {table_records} records from {table_name}")
                data_sql.append("")
                print(f"已备份 {table_records} 条记录从 {table_name}")

            # 添加摘要信息
            data_sql.append(f"-- Backup completed: {total_records} total records")

            # 写入文件
            content = '\n'.join(data_sql)
            if compress:
                with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                    f.write(content)
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)

            file_size = os.path.getsize(filepath)
            print(f"数据库数据备份完成: {filepath} ({file_size} 字节, {total_records} 条记录)")
            return filepath

        except Exception as e:
            print(f"数据库数据备份错误: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def backup_all(self, filepath=None, clean_temp_files=True):
        """
        备份整个数据库（结构和数据），并合并到单个文件后压缩为zip

        Args:
            filepath: 备份文件路径，如果为None则自动生成
            clean_temp_files: 是否清理临时文件

        Returns:
            dict: 包含备份文件路径的字典
        """
        timestamp = _get_timestamp()

        # 分别备份结构和数据
        schema_file = self.backup_schema(
            filepath=os.path.join(self.backup_dir, f"schema_backup_{timestamp}.sql"),
            compress=False
        )
        if not schema_file:
            return None

        data_file = self.backup_data(
            filepath=os.path.join(self.backup_dir, f"data_backup_{timestamp}.sql"),
            compress=False
        )
        if not data_file:
            return None

        # 合并文件到zip
        try:
            if filepath is None:
                filepath = os.path.join(self.backup_dir, f"full_backup_{timestamp}.zip")

            with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # 添加结构文件到zip
                zipf.write(schema_file, os.path.basename(schema_file))
                # 添加数据文件到zip
                zipf.write(data_file, os.path.basename(data_file))

            if clean_temp_files:
                # 删除临时文件
                os.remove(schema_file)
                os.remove(data_file)

            file_size = os.path.getsize(filepath)
            print(f"完整数据库备份完成: {filepath} ({file_size} 字节)")

            return {
                'full': filepath,
                'timestamp': timestamp
            }

        except Exception as e:
            print(f"合并备份文件时出错: {str(e)}")
            return None

    def list_backups(self):
        """列出所有备份文件"""
        if not os.path.exists(self.backup_dir):
            return []

        backups = []
        for filename in os.listdir(self.backup_dir):
            if filename.endswith(('.sql', '.zip')):
                filepath = os.path.join(self.backup_dir, filename)
                stat = os.stat(filepath)
                backups.append({
                    'name': filename,
                    'path': filepath,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime)
                })

        # 按修改时间排序
        backups.sort(key=lambda x: x['modified'], reverse=True)
        return backups


# 便捷函数
def create_backup_tool(db, backup_dir="backups"):
    """创建备份工具实例的便捷函数"""
    return DatabaseBackup(db, backup_dir)


# 使用示例
if __name__ == "__main__":
    # 假设您已经有一个 Flask-SQLAlchemy 实例
    # from yourapp import db

    # 创建备份工具
    # backup_tool = DatabaseBackup(db, "my_backups")

    # 备份数据库结构
    # schema_file = backup_tool.backup_schema()

    # 备份数据库数据
    # data_file = backup_tool.backup_data()

    # 完整备份（分开文件）
    # result = backup_tool.backup_all(separate_files=True)

    # 完整备份（单个文件）
    # result = backup_tool.backup_all(separate_files=False)

    # 列出所有备份
    # backups = backup_tool.list_backups()

    print("数据库备份工具库已加载")
