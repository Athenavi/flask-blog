from pathlib import Path


from wsgidav.dav_provider import DAVProvider, DAVCollection, DAVNonCollection

from src.database import get_db
from src.models import Media, FileHash
from src.utils.security.jwt_handler import JWTHandler


class MediaDAVProvider(DAVProvider):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.base_dir = app.config.get('base_dir', '.')

    def get_resource_inst(self, path, environ):
        """根据路径返回资源实例"""
        # 从请求中获取用户认证
        user_id = self._get_user_from_environ(environ)
        if not user_id:
            return None

        path_parts = path.strip('/').split('/')

        if len(path_parts) == 0 or path == '/':
            # 根目录 - 返回用户媒体库
            return MediaRootCollection(path, environ, user_id, self.app)
        else:
            # 具体文件
            filename = path_parts[-1]
            return self._get_media_file(user_id, filename, path, environ)

    def _get_user_from_environ(self, environ):
        """从 HTTP 请求中提取用户 ID"""
        auth_header = environ.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            try:
                payload = JWTHandler.decode_token(token)
                return payload.get('user_id')
            except:
                return None
        return None

    def _get_media_file(self, user_id, filename, path, environ):
        """获取用户的媒体文件"""
        with get_db() as db:
            media = db.query(Media).filter(
                Media.user_id == user_id,
                Media.original_filename == filename
            ).first()

            if media:
                file_hash = db.query(FileHash).filter(
                    FileHash.hash == media.hash
                ).first()

                if file_hash:
                    return MediaFile(path, environ, media, file_hash, self.base_dir)
        return None


class MediaRootCollection(DAVCollection):
    def __init__(self, path, environ, user_id, app):
        super().__init__(path, environ)
        self.user_id = user_id
        self.app = app

    def get_member_names(self):
        """返回目录中的文件列表"""
        with get_db() as db:
            media_files = db.query(Media).filter(
                Media.user_id == self.user_id
            ).all()
            return [m.original_filename for m in media_files]

    def get_member(self, name):
        """获取特定成员"""
        with get_db() as db:
            media = db.query(Media).filter(
                Media.user_id == self.user_id,
                Media.original_filename == name
            ).first()

            if media:
                file_hash = db.query(FileHash).filter(
                    FileHash.hash == media.hash
                ).first()

                if file_hash:
                    return MediaFile(
                        self.path + '/' + name,
                        self.environ,
                        media,
                        file_hash,
                        self.app.config.get('base_dir', '.')
                    )
        return None


class MediaFile(DAVNonCollection):
    def __init__(self, path, environ, media, file_hash, base_dir):
        super().__init__(path, environ)
        self.media = media
        self.file_hash = file_hash
        self.base_dir = base_dir

    def get_content_length(self):
        return self.file_hash.file_size

    def get_content_type(self):
        return self.file_hash.mime_type

    def get_content(self):
        """返回文件内容流"""
        file_path = Path(self.base_dir) / self.file_hash.storage_path
        return open(file_path, 'rb')

    def get_etag(self):
        return self.file_hash.hash