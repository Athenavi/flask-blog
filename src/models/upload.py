import uuid

from sqlalchemy.sql.functions import current_timestamp

from . import db


class UploadTask(db.Model):
    """上传任务表"""
    __tablename__ = 'upload_tasks'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    total_size = db.Column(db.BigInteger, nullable=False)  # 文件总大小
    total_chunks = db.Column(db.Integer, nullable=False)  # 总分块数
    uploaded_chunks = db.Column(db.Integer, default=0)  # 已上传分块数
    file_hash = db.Column(db.String(64))  # 文件哈希（用于秒传）
    status = db.Column(db.String(20), default='initialized')  # initialized, uploading, completed, cancelled
    created_at = db.Column(db.TIMESTAMP, server_default=current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=current_timestamp(), onupdate=current_timestamp())

    user = db.relationship('User', backref=db.backref('upload_tasks', lazy=True))
    chunks = db.relationship('UploadChunk', backref='task', lazy=True, cascade='all, delete-orphan')


class UploadChunk(db.Model):
    """上传分块表"""
    __tablename__ = 'upload_chunks'

    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.String(36), db.ForeignKey('upload_tasks.id'), nullable=False)
    chunk_index = db.Column(db.Integer, nullable=False)  # 分块索引
    chunk_hash = db.Column(db.String(64), nullable=False)  # 分块哈希
    chunk_size = db.Column(db.Integer, nullable=False)  # 分块大小
    chunk_path = db.Column(db.String(500), nullable=False)  # 分块存储路径
    created_at = db.Column(db.TIMESTAMP, server_default=current_timestamp())

    # 唯一约束，确保同一上传任务的每个分块索引唯一
    __table_args__ = (db.UniqueConstraint('upload_id', 'chunk_index', name='uix_upload_chunk'),)
