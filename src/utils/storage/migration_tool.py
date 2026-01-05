"""
S3存储迁移工具
用于将本地存储的文件迁移到S3兼容存储服务
"""
from pathlib import Path
from threading import Thread

from src.database import get_db
from src.models import FileHash
from src.setting import app_config
from src.utils.storage.s3_storage import s3_storage


def migrate_local_to_s3(batch_size=100, start_from=0):
    """
    将本地存储的文件迁移到S3存储
    
    Args:
        batch_size: 每次处理的文件数量
        start_from: 从第几个文件开始迁移
    """
    print("开始执行本地到S3的文件迁移...")
    
    # 检查S3是否已启用
    if not s3_storage.s3_enabled:
        print("错误：S3存储未启用，请先在配置中启用S3存储")
        return False
    
    with get_db() as db:
        try:
            # 查询所有非S3路径的文件记录
            query = db.query(FileHash).filter(~FileHash.storage_path.startswith('s3://'))
            total_count = query.count()
            print(f"待迁移文件总数: {total_count}")
            
            if total_count == 0:
                print("没有需要迁移的文件")
                return True
            
            # 分批处理文件
            offset = start_from
            migrated_count = 0
            failed_count = 0
            
            while offset < total_count:
                batch = query.offset(offset).limit(batch_size).all()
                
                if not batch:
                    break
                
                print(f"处理批次 {offset // batch_size + 1}，文件数量: {len(batch)}")
                
                for file_hash_record in batch:
                    try:
                        local_path = Path(app_config.base_dir) / file_hash_record.storage_path
                        
                        # 检查本地文件是否存在
                        if not local_path.exists():
                            print(f"本地文件不存在，跳过: {local_path}")
                            failed_count += 1
                            continue
                        
                        # 读取本地文件内容
                        with open(local_path, 'rb') as f:
                            file_data = f.read()
                        
                        # 上传到S3
                        new_storage_path = s3_storage.save_file(
                            file_hash_record.hash,
                            file_data,
                            file_hash_record.filename
                        )
                        
                        # 更新数据库记录
                        file_hash_record.storage_path = new_storage_path
                        db.commit()
                        
                        print(f"成功迁移文件: {file_hash_record.filename}")
                        migrated_count += 1
                        
                    except Exception as e:
                        print(f"迁移文件失败 {file_hash_record.filename}: {str(e)}")
                        db.rollback()
                        failed_count += 1
                
                offset += batch_size
            
            print(f"迁移完成！成功: {migrated_count}, 失败: {failed_count}")
            return True
            
        except Exception as e:
            print(f"迁移过程中发生错误: {str(e)}")
            return False


def migrate_local_to_s3_async(batch_size=100, start_from=0):
    """
    异步执行本地到S3的文件迁移
    """
    thread = Thread(target=migrate_local_to_s3, args=(batch_size, start_from))
    thread.daemon = True
    thread.start()
    return thread


def verify_migration():
    """
    验证迁移结果
    检查S3中文件是否存在
    """
    print("开始验证迁移结果...")
    
    with get_db() as db:
        try:
            # 查询所有S3路径的文件记录
            s3_files = db.query(FileHash).filter(FileHash.storage_path.startswith('s3://')).all()
            total_s3_files = len(s3_files)
            print(f"S3存储文件总数: {total_s3_files}")
            
            if total_s3_files == 0:
                print("没有S3存储的文件需要验证")
                return True
            
            verified_count = 0
            missing_count = 0
            
            for file_hash_record in s3_files:
                try:
                    # 检查S3中文件是否存在
                    exists = s3_storage.file_exists(file_hash_record.storage_path)
                    if exists:
                        verified_count += 1
                        if verified_count % 50 == 0:  # 每50个打印一次进度
                            print(f"已验证: {verified_count}/{total_s3_files}")
                    else:
                        print(f"S3中文件不存在: {file_hash_record.filename}")
                        missing_count += 1
                        
                except Exception as e:
                    print(f"验证文件失败 {file_hash_record.filename}: {str(e)}")
                    missing_count += 1
            
            print(f"验证完成！存在: {verified_count}, 缺失: {missing_count}")
            return missing_count == 0
            
        except Exception as e:
            print(f"验证过程中发生错误: {str(e)}")
            return False


def rollback_s3_to_local():
    """
    从S3回滚到本地存储（如果需要）
    """
    print("回滚功能尚未实现")
    # 这是一个复杂的操作，需要从S3下载文件并保存到本地
    # 一般情况下不建议执行此操作，因为S3是目标存储
    pass


if __name__ == "__main__":
    # 如果直接运行此脚本，执行迁移
    migrate_local_to_s3()