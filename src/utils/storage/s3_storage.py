from typing import Optional
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError


class S3Storage:
    """
    S3兼容存储实现类
    支持AWS S3、MinIO、阿里云OSS、腾讯云COS等S3兼容服务
    """
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """初始化应用配置"""
        self.app = app
        
        # S3配置 - 现在默认启用
        self.s3_enabled = app.config.get('S3_ENABLED', True)
        if not self.s3_enabled:
            print("警告: S3存储被禁用，但应用媒体需要存储功能。建议启用S3存储。")
            return
            
        self.s3_endpoint = app.config.get('S3_ENDPOINT_URL')
        self.s3_access_key = app.config.get('S3_ACCESS_KEY')
        self.s3_secret_key = app.config.get('S3_SECRET_KEY')
        self.s3_bucket_name = app.config.get('S3_BUCKET_NAME', 'media-bucket')
        self.s3_region = app.config.get('S3_REGION', 'us-east-1')
        self.s3_use_ssl = app.config.get('S3_USE_SSL', True)
        self.s3_signature_version = app.config.get('S3_SIGNATURE_VERSION', 's3v4')
        
        # 创建S3客户端
        self.s3_client = self._create_s3_client()

        # 如果S3客户端未成功创建，记录警告
        if self.s3_client is None:
            print("警告: S3客户端未成功初始化，媒体上传功能可能不可用")
    
    def _create_s3_client(self):
        """创建S3客户端"""
        if not self.s3_enabled:
            return None
            
        # 检查必要的配置
        if not all([self.s3_access_key, self.s3_secret_key, self.s3_bucket_name]):
            print("警告: S3配置不完整，将禁用S3存储功能")
            print(f"S3_ACCESS_KEY: {'已配置' if self.s3_access_key else '未配置'}")
            print(f"S3_SECRET_KEY: {'已配置' if self.s3_secret_key else '未配置'}")
            print(f"S3_BUCKET_NAME: {'已配置' if self.s3_bucket_name else '未配置'}")
            return None
        
        # 配置S3客户端参数
        client_config = {
            'aws_access_key_id': self.s3_access_key,
            'aws_secret_access_key': self.s3_secret_key,
            'region_name': self.s3_region,
        }
        
        # 如果有自定义端点（如MinIO），添加endpoint_url
        if self.s3_endpoint and self.s3_endpoint.strip():
            client_config['endpoint_url'] = self.s3_endpoint
            client_config['use_ssl'] = self.s3_use_ssl
            # 只有在使用SSL时才设置verify
            if self.s3_use_ssl:
                client_config['verify'] = True  # 对于自签名证书可以设为False，但默认设为True
        
        # 创建S3客户端
        s3_client = boto3.client('s3', **client_config)
        
        # 验证连接
        try:
            s3_client.head_bucket(Bucket=self.s3_bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                # 存储桶不存在，尝试创建
                try:
                    if self.s3_region == 'us-east-1':
                        # us-east-1区域创建存储桶不需要LocationConstraint
                        s3_client.create_bucket(Bucket=self.s3_bucket_name)
                    else:
                        s3_client.create_bucket(
                            Bucket=self.s3_bucket_name,
                            CreateBucketConfiguration={'LocationConstraint': self.s3_region}
                        )
                    print(f"S3存储桶 {self.s3_bucket_name} 创建成功")
                except ClientError as create_error:
                    print(f"无法创建S3存储桶: {create_error}")
                    raise
            else:
                print(f"无法访问S3存储桶: {e}")
                raise
        
        return s3_client
    
    def save_file(self, file_hash: str, file_data: bytes, original_filename: str) -> str:
        """
        保存文件到S3存储
        返回存储路径（格式：s3://bucket/key）
        """
        # 强制使用S3存储，不再支持本地存储
        try:
            # 构建S3对象键（路径）
            # 使用哈希的前两个字符作为目录，提高性能
            hash_prefix = file_hash[:2]
            key = f"hashed_files/{hash_prefix}/{file_hash}"
            
            # 上传文件到S3
            self.s3_client.put_object(
                Bucket=self.s3_bucket_name,
                Key=key,
                Body=file_data,
                Metadata={
                    'original_filename': original_filename,
                    'file_hash': file_hash
                }
            )
            
            # 返回S3路径格式
            storage_path = f"s3://{self.s3_bucket_name}/{key}"
            return storage_path
            
        except Exception as e:
            print(f"S3文件上传失败: {str(e)}")
            raise
    
    def load_file(self, storage_path: str) -> Optional[bytes]:
        """
        从S3存储加载文件
        """
        # 强制使用S3存储，不再支持本地存储
        try:
            if storage_path.startswith('s3://'):
                # 解析S3路径
                parsed = urlparse(storage_path)
                bucket = parsed.netloc
                key = parsed.path.lstrip('/')
                
                # 从S3下载文件
                response = self.s3_client.get_object(Bucket=bucket, Key=key)
                file_data = response['Body'].read()
                return file_data
            else:
                # 不再支持本地路径，直接报错
                print(f"错误: 不再支持本地存储路径: {storage_path}")
                return None
                
        except ClientError as e:
            print(f"从S3加载文件失败: {str(e)}")
            return None
        except Exception as e:
            print(f"从S3加载文件失败: {str(e)}")
            return None
    
    def delete_file(self, storage_path: str) -> bool:
        """
        从S3存储删除文件
        """
        # 强制使用S3存储，不再支持本地存储
        try:
            if storage_path.startswith('s3://'):
                # 解析S3路径
                parsed = urlparse(storage_path)
                bucket = parsed.netloc
                key = parsed.path.lstrip('/')
                
                # 从S3删除文件
                self.s3_client.delete_object(Bucket=bucket, Key=key)
                return True
            else:
                # 不再支持本地路径，直接报错
                print(f"错误: 不再支持本地存储路径: {storage_path}")
                return False
                
        except ClientError as e:
            print(f"从S3删除文件失败: {str(e)}")
            return False
        except Exception as e:
            print(f"从S3删除文件失败: {str(e)}")
            return False
    
    def file_exists(self, storage_path: str) -> bool:
        """
        检查S3中文件是否存在
        """
        # 强制使用S3存储，不再支持本地存储
        try:
            if storage_path.startswith('s3://'):
                # 解析S3路径
                parsed = urlparse(storage_path)
                bucket = parsed.netloc
                key = parsed.path.lstrip('/')
                
                # 检查S3中文件是否存在
                self.s3_client.head_object(Bucket=bucket, Key=key)
                return True
            else:
                # 不再支持本地路径，直接报错
                print(f"错误: 不再支持本地存储路径: {storage_path}")
                return False
                
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                return False
            else:
                print(f"检查S3文件存在性失败: {str(e)}")
                return False
        except Exception as e:
            print(f"检查S3文件存在性失败: {str(e)}")
            return False
    
    def get_file_url(self, storage_path: str, expires: int = 3600) -> Optional[str]:
        """
        生成S3文件的预签名URL（用于临时访问）
        """
        # 强制使用S3存储，不再支持本地存储
        try:
            if storage_path.startswith('s3://'):
                # 解析S3路径
                parsed = urlparse(storage_path)
                bucket = parsed.netloc
                key = parsed.path.lstrip('/')
                
                # 生成预签名URL
                url = self.s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': bucket, 'Key': key},
                    ExpiresIn=expires
                )
                return url
            else:
                # 不再支持本地路径
                print(f"错误: 不再支持本地存储路径: {storage_path}")
                return None
                
        except Exception as e:
            print(f"生成S3预签名URL失败: {str(e)}")
            return None

# 全局S3存储实例
s3_storage = S3Storage()