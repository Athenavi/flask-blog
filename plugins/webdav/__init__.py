import hashlib
import logging
import os
import urllib.parse
from decimal import Decimal

from flask import Blueprint, request, Response, jsonify, send_file

from blueprints.media import get_user_storage_used
from src.setting import app_config
from src.database import get_db
from src.models import Media, FileHash, User
from src.utils.security.jwt_handler import JWTHandler

logger = logging.getLogger(__name__)


def register_plugin(app):
    bp = Blueprint('webdav_plugin', __name__)

    # 安全的时间戳 - 确保在 Windows FileTime 有效范围内
    SAFE_TIMESTAMP = 1760321580  # 2025-10-01 00:00:00 UTC
    SAFE_DATE_STRING = "Sat, 11 Oct 2025 00:00:00 GMT"

    class WebDAVHandler:
        """支持文件上传的 WebDAV 处理器"""

        def __init__(self, app):
            self.base_dir = app_config.base_dir or os.getcwd()
            self.upload_dir = os.path.join(self.base_dir, 'hashed_files')
            print(f"WebDAV base dir: {self.base_dir}")
            print(f"WebDAV upload dir: {self.upload_dir}")

            # 确保上传目录存在
            os.makedirs(self.upload_dir, exist_ok=True)

        def _get_disk_usage(self, user_info):
            """获取当前用户的总大小、已使用大小和可用大小"""
            if user_info:
                disk_used = Decimal(user_info['disk_used'])
                disk_limit = Decimal(user_info['disk_limit'])
                disk_available = disk_limit - disk_used
                return disk_limit, disk_used, disk_available
            else:
                logger.error("无法获取用户信息")
                return Decimal(0), Decimal(0), Decimal(0)

        def handle_request(self, path, method, user_info):
            """处理 WebDAV 请求"""
            try:
                # 解析路径
                path_parts = [p for p in path.strip('/').split('/') if p]

                if len(path_parts) == 0:
                    # 根目录 - 返回目录列表
                    if method == 'PROPFIND':
                        return self._handle_propfind_root(user_info)
                    else:
                        return self._method_not_allowed()
                elif len(path_parts) == 1:
                    # 用户目录
                    if path_parts[0] != user_info['username']:
                        return self._not_found()

                    if method == 'PROPFIND':
                        return self._handle_propfind_root(user_info)
                    elif method == 'MKCOL':
                        return self._handle_mkcol(user_info)
                    else:
                        return self._method_not_allowed()
                else:
                    # 文件请求
                    if path_parts[0] != user_info['username']:
                        return self._not_found()

                    filename = '/'.join(path_parts[1:])

                    if method in ['GET', 'HEAD']:
                        return self._handle_file_request(filename, method, user_info)
                    elif method == 'PUT':
                        return self._handle_put_file(filename, user_info, request)
                    elif method == 'PROPFIND':
                        return self._handle_propfind_file_request(filename, user_info)
                    elif method == 'DELETE':
                        return self._handle_delete_file(filename, user_info)
                    else:
                        return self._method_not_allowed()

            except Exception as e:
                logger.error(f"WebDAV request error: {e}", exc_info=True)
                return self._error_response(500, str(e))

        def _handle_delete_file(self, filename, user_info):
            """处理文件删除"""
            try:
                original_filename = urllib.parse.unquote(filename)

                with get_db() as db:
                    # 查找媒体记录
                    media = db.query(Media).filter(
                        Media.user_id == user_info['id'],
                        Media.original_filename == original_filename
                    ).first()

                    if not media:
                        return self._not_found()

                    file_hash = media.hash

                    # 删除媒体记录
                    db.delete(media)

                    # 检查是否还有其他用户引用此文件
                    other_media = db.query(Media).filter(Media.hash == file_hash).first()

                    if not other_media:
                        # 没有其他引用，删除文件哈希记录和物理文件
                        file_hash_record = db.query(FileHash).filter(FileHash.hash == file_hash).first()
                        if file_hash_record:
                            file_path = os.path.join(self.base_dir, file_hash_record.storage_path)
                            if os.path.exists(file_path):
                                os.remove(file_path)
                            db.delete(file_hash_record)

                    db.commit()

                return Response(status=204)

            except Exception as e:
                logger.error(f"File deletion error: {e}", exc_info=True)
                return self._error_response(500, f"Deletion failed: {str(e)}")

        def _handle_put_file(self, filename, user_info, request):
            """处理文件上传"""
            try:
                original_filename = urllib.parse.unquote(filename)
                # 动态获取当前用户的磁盘使用情况
                total_size, used_size, free_size = self._get_disk_usage(user_info)

                content_length = request.content_length or 0
                if content_length > free_size:
                    return self._error_response(507, "Insufficient Storage")

                # 计算文件哈希
                file_data = request.get_data()
                file_hash = hashlib.sha256(file_data).hexdigest()
                file_size = len(file_data)

                with get_db() as db:
                    # 检查是否已存在相同哈希的文件
                    existing_hash = db.query(FileHash).filter(FileHash.hash == file_hash).first()

                    if existing_hash:
                        # 文件已存在，检查用户是否已有此文件的记录
                        existing_media = db.query(Media).filter(
                            Media.user_id == user_info['id'],
                            Media.hash == file_hash
                        ).first()

                        if existing_media:
                            return self._error_response(409, "File already exists")

                        # 为用户创建新的媒体记录
                        new_media = Media(
                            user_id=user_info['id'],
                            original_filename=original_filename,
                            hash=file_hash
                        )
                        db.add(new_media)
                        db.commit()

                        return Response(
                            status=200,
                            headers={
                                'ETag': f'"{file_hash}"',
                            }
                        )
                    else:
                        # 新文件，保存到存储
                        # 创建哈希目录结构
                        hash_dir = os.path.join(self.upload_dir, file_hash[:2])
                        os.makedirs(hash_dir, exist_ok=True)

                        file_path = os.path.join(hash_dir, file_hash)

                        # 保存文件
                        with open(file_path, 'wb') as f:
                            f.write(file_data)

                        # 获取 MIME 类型
                        import mimetypes
                        mime_type, _ = mimetypes.guess_type(original_filename)

                        # 创建 FileHash 记录
                        new_file_hash = FileHash(
                            hash=file_hash,
                            filename=original_filename,
                            file_size=file_size,
                            mime_type=mime_type or 'application/octet-stream',
                            storage_path=os.path.relpath(file_path, self.base_dir)
                        )
                        db.add(new_file_hash)

                        # 创建 Media 记录
                        new_media = Media(
                            user_id=user_info['id'],
                            original_filename=original_filename,
                            hash=file_hash
                        )
                        db.add(new_media)

                        db.commit()

                        return Response(
                            status=201,
                            headers={
                                'ETag': f'"{file_hash}"',
                            }
                        )

            except Exception as e:
                logger.error(f"File upload error: {e}", exc_info=True)
                return self._error_response(500, f"Upload failed: {str(e)}")

        @staticmethod
        def _handle_mkcol(user_info):
            """处理创建目录请求"""
            # WebDAV 要求创建目录，但我们这里只支持用户根目录
            return Response(status=405)

        def _handle_propfind_root(self, user_info):
            """处理根目录的 PROPFIND 请求"""
            # 动态获取当前用户的磁盘使用情况
            total_size, used_size, free_size = self._get_disk_usage(user_info)

            with get_db() as db:
                media_files = db.query(Media).filter(
                    Media.user_id == user_info['id']
                ).all()

                # 生成目录列表 XML
                xml_parts = []
                xml_parts.append('<?xml version="1.0" encoding="utf-8"?>')
                xml_parts.append('<D:multistatus xmlns:D="DAV:">')

                # 添加当前目录
                xml_parts.append(f'<D:response>')
                xml_parts.append(f'<D:href>/dav/{user_info["username"]}/</D:href>')
                xml_parts.append(f'<D:propstat>')
                xml_parts.append(f'<D:prop>')
                xml_parts.append(f'<D:resourcetype><D:collection/></D:resourcetype>')
                xml_parts.append(f'<D:displayname>{user_info["username"]}\'s Media</D:displayname>')
                xml_parts.append(f'<D:creationdate>2025-10-01T00:00:00Z</D:creationdate>')
                xml_parts.append(f'<D:getlastmodified>{SAFE_DATE_STRING}</D:getlastmodified>')
                xml_parts.append(f'<D:getcontentlength>{total_size}</D:getcontentlength>')
                xml_parts.append(f'<D:quota-used-bytes>{used_size}</D:quota-used-bytes>')
                xml_parts.append(f'<D:quota-available-bytes>{free_size}</D:quota-available-bytes>')
                xml_parts.append(f'<D:supportedlock>')
                xml_parts.append(f'<D:lockentry>')
                xml_parts.append(f'<D:lockscope><D:exclusive/></D:lockscope>')
                xml_parts.append(f'<D:locktype><D:write/></D:locktype>')
                xml_parts.append(f'</D:lockentry>')
                xml_parts.append(f'</D:supportedlock>')
                xml_parts.append(f'</D:prop>')
                xml_parts.append(f'<D:status>HTTP/1.1 200 OK</D:status>')
                xml_parts.append(f'</D:propstat>')
                xml_parts.append(f'</D:response>')

                # 添加文件
                for media in media_files:
                    file_hash = db.query(FileHash).filter(
                        FileHash.hash == media.hash
                    ).first()

                    if file_hash:
                        safe_filename = urllib.parse.quote(media.original_filename)
                        xml_parts.append(f'<D:response>')
                        xml_parts.append(f'<D:href>/dav/{user_info["username"]}/{safe_filename}</D:href>')
                        xml_parts.append(f'<D:propstat>')
                        xml_parts.append(f'<D:prop>')
                        xml_parts.append(f'<D:resourcetype/>')
                        xml_parts.append(f'<D:displayname>{media.original_filename}</D:displayname>')
                        xml_parts.append(f'<D:creationdate>2025-10-01T00:00:00Z</D:creationdate>')
                        xml_parts.append(f'<D:getlastmodified>{SAFE_DATE_STRING}</D:getlastmodified>')
                        xml_parts.append(f'<D:getcontentlength>{file_hash.file_size}</D:getcontentlength>')
                        xml_parts.append(
                            f'<D:getcontenttype>{file_hash.mime_type or "application/octet-stream"}</D:getcontenttype>')
                        xml_parts.append(f'<D:getetag>"{file_hash.hash}"</D:getetag>')
                        xml_parts.append(f'<D:supportedlock>')
                        xml_parts.append(f'<D:lockentry>')
                        xml_parts.append(f'<D:lockscope><D:exclusive/></D:lockscope>')
                        xml_parts.append(f'<D:locktype><D:write/></D:locktype>')
                        xml_parts.append(f'</D:lockentry>')
                        xml_parts.append(f'</D:supportedlock>')
                        xml_parts.append(f'</D:prop>')
                        xml_parts.append(f'<D:status>HTTP/1.1 200 OK</D:status>')
                        xml_parts.append(f'</D:propstat>')
                        xml_parts.append(f'</D:response>')

                xml_parts.append('</D:multistatus>')
                xml_response = '\n'.join(xml_parts)

                return Response(
                    response=xml_response,
                    status=207,
                    content_type='application/xml; charset="utf-8"',
                    headers={
                        'DAV': '1, 2',
                        'Allow': 'OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE',
                    }
                )

        def _handle_file_request(self, filename, method, user_info):
            """处理文件请求"""
            try:
                original_filename = urllib.parse.unquote(filename)
            except:
                original_filename = filename

            with get_db() as db:
                media = db.query(Media).filter(
                    Media.user_id == user_info['id'],
                    Media.original_filename == original_filename
                ).first()

                if not media:
                    return self._not_found()

                file_hash = db.query(FileHash).filter(
                    FileHash.hash == media.hash
                ).first()

                if not file_hash:
                    return self._not_found()

                if method == 'GET':
                    return self._serve_file(file_hash, original_filename)
                elif method == 'HEAD':
                    return self._file_headers(file_hash, original_filename)
                else:
                    return self._method_not_allowed()

        def _handle_propfind_file_request(self, filename, user_info):
            """处理文件的 PROPFIND 请求"""
            try:
                original_filename = urllib.parse.unquote(filename)
            except:
                original_filename = filename

            with get_db() as db:
                media = db.query(Media).filter(
                    Media.user_id == user_info['id'],
                    Media.original_filename == original_filename
                ).first()

                if not media:
                    return self._not_found()

                file_hash = db.query(FileHash).filter(
                    FileHash.hash == media.hash
                ).first()

                if not file_hash:
                    return self._not_found()

                return self._handle_propfind_file(file_hash, media, user_info)

        def _serve_file(self, file_hash, filename):
            """提供文件下载"""
            storage_path = file_hash.storage_path
            if not os.path.isabs(storage_path):
                file_path = os.path.join(self.base_dir, storage_path)
            else:
                file_path = storage_path

            file_path = os.path.normpath(file_path)

            if not os.path.exists(file_path):
                return self._not_found()

            try:
                # 使用 Flask 的 send_file 替代手动文件操作
                return send_file(
                    file_path,
                    as_attachment=False,
                    download_name=filename,
                    mimetype=file_hash.mime_type or 'application/octet-stream',
                    last_modified=SAFE_TIMESTAMP,
                    etag=file_hash.hash
                )
            except Exception as e:
                logger.error(f"Error serving file {file_path}: {e}")
                return self._error_response(500, "File serving error")

        @staticmethod
        def _file_headers(file_hash, filename):
            """返回文件头部信息"""
            return Response(
                status=200,
                headers={
                    'Content-Type': file_hash.mime_type or 'application/octet-stream',
                    'Content-Length': str(file_hash.file_size),
                    'Last-Modified': SAFE_DATE_STRING,
                    'ETag': f'"{file_hash.hash}"',
                    'Accept-Ranges': 'bytes',
                }
            )

        def _handle_propfind_file(self, file_hash, media, user_info):
            """处理文件的 PROPFIND 请求"""
            # 动态获取当前用户的磁盘使用情况
            total_size, used_size, free_size = self._get_disk_usage(user_info)

            safe_filename = urllib.parse.quote(media.original_filename)

            xml_parts = []
            xml_parts.append('<?xml version="1.0" encoding="utf-8"?>')
            xml_parts.append('<D:multistatus xmlns:D="DAV:">')
            xml_parts.append(f'<D:response>')
            xml_parts.append(f'<D:href>/dav/{user_info["username"]}/{safe_filename}</D:href>')
            xml_parts.append(f'<D:propstat>')
            xml_parts.append(f'<D:prop>')
            xml_parts.append(f'<D:resourcetype/>')
            xml_parts.append(f'<D:displayname>{media.original_filename}</D:displayname>')
            xml_parts.append(f'<D:creationdate>2025-10-01T00:00:00Z</D:creationdate>')
            xml_parts.append(f'<D:getlastmodified>{SAFE_DATE_STRING}</D:getlastmodified>')
            xml_parts.append(f'<D:getcontentlength>{file_hash.file_size}</D:getcontentlength>')
            xml_parts.append(
                f'<D:getcontenttype>{file_hash.mime_type or "application/octet-stream"}</D:getcontenttype>')
            xml_parts.append(f'<D:getetag>"{file_hash.hash}"</D:getetag>')
            xml_parts.append(f'<D:supportedlock>')
            xml_parts.append(f'<D:lockentry>')
            xml_parts.append(f'<D:lockscope><D:exclusive/></D:lockscope>')
            xml_parts.append(f'<D:locktype><D:write/></D:locktype>')
            xml_parts.append(f'</D:lockentry>')
            xml_parts.append(f'</D:supportedlock>')
            xml_parts.append(f'</D:prop>')
            xml_parts.append(f'<D:status>HTTP/1.1 200 OK</D:status>')
            xml_parts.append(f'</D:propstat>')
            xml_parts.append(f'</D:response>')
            xml_parts.append('</D:multistatus>')

            xml_response = '\n'.join(xml_parts)

            return Response(
                response=xml_response,
                status=207,
                content_type='application/xml; charset="utf-8"',
                headers={
                    'DAV': '1, 2',
                }
            )

        @staticmethod
        def _authenticate_user(request):
            """用户认证"""
            # 检查 Basic Auth
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Basic '):
                try:
                    import base64
                    auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    username, refresh_token = auth_decoded.split(':', 1)

                    with get_db() as db:
                        user_id = JWTHandler.authenticate_refresh_token(refresh_token)
                        user = db.query(User).filter(User.id == user_id).first()

                        if user and user.username == username:
                            return {
                                'id': user.id,
                                'username': user.username,
                                'vip_level': user.vip_level,
                                'created_at': user.created_at,
                                'disk_used': get_user_storage_used(user.id),
                                'disk_limit': app_config.USER_FREE_STORAGE_LIMIT,
                            }
                except Exception as e:
                    logger.error(f"Basic Auth error: {e}")

            return None

        @staticmethod
        def _not_found():
            return Response(
                response="Not Found",
                status=404,
                content_type='text/plain'
            )

        @staticmethod
        def _method_not_allowed():
            return Response(
                response="Method Not Allowed",
                status=405,
                content_type='text/plain'
            )

        @staticmethod
        def _error_response(status, message):
            return Response(
                response=message,
                status=status,
                content_type='text/plain'
            )

    # 创建处理器实例
    handler = WebDAVHandler(app)

    # WebDAV 路由
    @bp.route('/dav/', defaults={'path': ''},
              methods=['OPTIONS', 'GET', 'HEAD', 'PROPFIND', 'PUT', 'DELETE', 'MKCOL'])
    @bp.route('/dav/<path:path>',
              methods=['OPTIONS', 'GET', 'HEAD', 'PROPFIND', 'PUT', 'DELETE', 'MKCOL'])
    def webdav_handler(path=''):
        # 用户认证
        user_info = handler._authenticate_user(request)
        if not user_info:
            return Response(
                response="Authentication required",
                status=401,
                headers={'WWW-Authenticate': 'Basic realm="WebDAV"'},
                content_type='text/plain'
            )

        # 处理 OPTIONS 请求
        if request.method == 'OPTIONS':
            return Response(
                status=200,
                headers={
                    'DAV': '1, 2',
                    'Allow': 'OPTIONS, GET, HEAD, PROPFIND, PUT, DELETE, MKCOL',
                    'MS-Author-Via': 'DAV',
                }
            )

        # 处理其他 WebDAV 请求
        return handler.handle_request(path, request.method, user_info)

    # WebDAV 发现页面
    @bp.route('/dav/index.html', methods=['GET'])
    def webdav_root():
        return """
        <html>
            <head>
                <title>WebDAV Media Server</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    h1 { color: #333; }
                    .info { background: #f5f5f5; padding: 15px; border-radius: 5px; }
                </style>
            </head>
            <body>
                <h1>WebDAV Media Server</h1>
                <div class="info">
                    <p>Your media files are available via WebDAV protocol.</p>
                    <p><strong>Authentication methods:</strong></p>
                    <ul>
                        <li>Browser: Automatic Cookie-based authentication</li>
                        <li>WebDAV Clients: HTTP Basic Auth (username + refresh_token)</li>
                    </ul>
                    <p><strong>Supported methods:</strong> OPTIONS, GET, HEAD, PROPFIND, PUT, DELETE</p>
                    <p><a href="/dav/">Browse your files via WebDAV</a></p>
                </div>
            </body>
        </html>
        """

    plugin = type('Plugin', (), {
        'name': 'WebDAV Media Server',
        'version': '2.0.0',
        'description': '支持读写操作的 WebDAV 媒体服务器，支持文件上传和下载',
        'author': 'System',
        'blueprint': bp,
        'enabled': True,
        'handler': handler
    })()

    return plugin
