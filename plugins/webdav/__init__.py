import hashlib
import json
import logging
import mimetypes
import os
import urllib.parse
from datetime import datetime
from decimal import Decimal

from flask import Blueprint, Response, send_file, request

from src.blueprints.media import get_user_storage_used
from src.database import get_db
from src.extensions import csrf
from src.models import Media, FileHash, User, db
from src.setting import app_config
from src.utils.storage.s3_storage import s3_storage

logger = logging.getLogger(__name__)


@csrf.exempt
def register_plugin(app):
    bp = Blueprint('webdav_plugin', __name__)

    # 安全的时间戳 - 确保在 Windows FileTime 有效范围内
    safe_timestamp = 1760321580  # 2025-10-01 00:00:00 UTC
    safe_date_string = "Sat, 11 Oct 2025 00:00:00 GMT"

    def _generate_filetype_report(media_files, user_info):
        """生成文件类型报告"""
        file_type_count = {}

        with get_db() as db_session:
            for media in media_files:
                file_hash = db_session.query(FileHash).filter(FileHash.hash == media.hash).first()
                if file_hash:
                    file_type = file_hash.mime_type or 'unknown'
                    file_type_count[file_type] = file_type_count.get(file_type, 0) + 1

        report = {
            'user': user_info['username'],
            'file_type_distribution': file_type_count,
            'generated_at': datetime.now().isoformat()
        }

        return Response(
            response=json.dumps(report, indent=2),
            status=200,
            content_type='application/json'
        )

    def _generate_timeline_report(media_files, user_info):
        """生成时间线报告"""
        timeline_data = {}

        with get_db() as db_session:
            for media in media_files:
                file_hash = db_session.query(FileHash).filter(FileHash.hash == media.hash).first()
                if file_hash:
                    # 按月份分组
                    month_key = media.created_at.strftime('%Y-%m') if media.created_at else 'unknown'
                    if month_key not in timeline_data:
                        timeline_data[month_key] = {
                            'file_count': 0,
                            'total_size': 0,
                            'files': []
                        }

                    timeline_data[month_key]['file_count'] += 1
                    timeline_data[month_key]['total_size'] += file_hash.file_size
                    timeline_data[month_key]['files'].append({
                        'filename': media.original_filename,
                        'size': file_hash.file_size,
                        'mime_type': file_hash.mime_type,
                        'created_at': media.created_at.isoformat() if media.created_at else None
                    })

        report = {
            'user': user_info['username'],
            'timeline': timeline_data,
            'generated_at': datetime.now().isoformat()
        }

        return Response(
            response=json.dumps(report, indent=2),
            status=200,
            content_type='application/json'
        )

    def _handle_propfind_search_results(results, user_info, search_query):
        """以 WebDAV 格式返回搜索结果"""
        xml_parts = ['<?xml version="1.0" encoding="utf-8"?>', '<D:multistatus xmlns:D="DAV:">']

        for media in results:
            file_hash = db.query(FileHash).filter(FileHash.hash == media.hash).first()
            if file_hash:
                safe_filename = urllib.parse.quote(media.original_filename)
                xml_parts.append(f'<D:response>')
                xml_parts.append(f'<D:href>/dav/{user_info["username"]}/{safe_filename}</D:href>')
                xml_parts.append(f'<D:propstat>')
                xml_parts.append(f'<D:prop>')
                xml_parts.append(f'<D:displayname>{media.original_filename}</D:displayname>')
                xml_parts.append(f'<D:getcontentlength>{file_hash.file_size}</D:getcontentlength>')
                xml_parts.append(
                    f'<D:getcontenttype>{file_hash.mime_type or "application/octet-stream"}</D:getcontenttype>')
                xml_parts.append(f'<D:getetag>"{file_hash.hash}"</D:getetag>')
                xml_parts.append(f'</D:prop>')
                xml_parts.append(f'<D:status>HTTP/1.1 200 OK</D:status>')
                xml_parts.append(f'</D:propstat>')
                xml_parts.append(f'</D:response>')

        xml_parts.append('</D:multistatus>')
        xml_response = '\n'.join(xml_parts)

        return Response(
            response=xml_response,
            status=207,
            content_type='application/xml; charset="utf-8"'
        )

    def _serve_user_info(user_info):
        """提供用户信息"""
        with get_db() as db:
            media_files = db.query(Media).filter(Media.user_id == user_info['id']).all()
            total_files = len(media_files)
            total_size = sum(
                db.query(FileHash.file_size).filter(FileHash.hash == media.hash).scalar() or 0
                for media in media_files
            )

        info = {
            'username': user_info['username'],
            'vip_level': user_info['vip_level'],
            'total_files': total_files,
            'total_storage_used': int(float(user_info['disk_used'])),
            'storage_limit': int(float(user_info['disk_limit'])),
            'actual_file_size': total_size,
            'storage_efficiency': f"{(1 - total_size / float(user_info['disk_used'])) * 100:.1f}%" if user_info[
                                                                                                          'disk_used'] > 0 else "100%",
            'server_time': datetime.now().isoformat()
        }

        return Response(
            response=json.dumps(info, indent=2),
            status=200,
            content_type='application/json'
        )

    def build_options_response():
        """Build enhanced OPTIONS response with WebDAV features"""
        return Response(
            status=200,
            headers={
                'DAV': '1, 2, 3',
                'Allow': 'OPTIONS, GET, HEAD, PROPFIND, PUT, POST, DELETE, MKCOL, MOVE, COPY',
                'MS-Author-Via': 'DAV',
                'X-WebDAV-Features': 'search, reports, thumbnails, analytics',
            }
        )

    def _serve_web_interface(user_info):
        """提供 Web 界面"""
        return f"""
            <html>
                <head>
                    <title>WebDAV Media Server</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; }}
                        .container {{ max-width: 800px; margin: 0 auto; }}
                        .card {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                        .feature-list {{ list-style: none; padding: 0; }}
                        .feature-list li {{ padding: 8px 0; border-bottom: 1px solid #ddd; }}
                        .btn {{ display: inline-block; padding: 10px 20px; background: #007cba; color: white; text-decoration: none; border-radius: 4px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>WebDAV Media Server</h1>

                        <div class="card">
                            <h2>Welcome, {user_info['username']}!</h2>
                            <p>Your personal WebDAV media server with enhanced features.</p>
                        </div>

                        <div class="card">
                            <h3>Storage Information</h3>
                            <p>Used: {user_info['disk_used']} / {user_info['disk_limit']} bytes</p>
                            <progress value="{user_info['disk_used']}" max="{user_info['disk_limit']}" style="width: 100%"></progress>
                        </div>

                        <div class="card">
                            <h3>Enhanced Features</h3>
                            <ul class="feature-list">
                                <li>📁 <strong>File Management:</strong> Upload, download, delete files</li>
                                <li>🔍 <strong>Advanced Search:</strong> Search by name, type, date</li>
                                <li>📊 <strong>Storage Reports:</strong> Detailed usage analytics</li>
                                <li>🖼️ <strong>Thumbnail Generation:</strong> Image previews</li>
                                <li>📈 <strong>File Analytics:</strong> Type distribution, size analysis</li>
                                <li>🌐 <strong>Web Interface:</strong> Browser-based file management</li>
                            </ul>
                        </div>

                        <div class="card">
                            <h3>Quick Access</h3>
                            <p>
                                <a href="/dav/index.html" class="btn">Browse Files</a>
                                <a href="/dav/.reports" class="btn">View Reports</a>
                                <a href="/dav/.info" class="btn">Account Info</a>
                            </p>
                        </div>

                        <div class="card">
                            <h3>WebDAV Access</h3>
                            <p><strong>Server URL:</strong> {request.host_url}dav/</p>
                            <p><strong>Username:</strong> {user_info['username']}</p>
                            <p><strong>Authentication:</strong> Use your refresh token as password</p>
                        </div>
                    </div>
                </body>
            </html>
            """

    def get_disk_usage(user_info):
        """Get user's total, used and available disk space"""
        if user_info:
            try:
                disk_used = Decimal(str(user_info['disk_used']))
                disk_limit = Decimal(str(user_info['disk_limit']))
                disk_available = disk_limit - disk_used
                return int(disk_limit), int(disk_used), int(disk_available)
            except (ValueError, TypeError) as e:
                logger.error(f"Error calculating disk usage: {e}")
                return 0, 0, 0
        else:
            logger.error("Failed to get user info")
            return 0, 0, 0

    class WebDAVHandler:
        """增强的 WebDAV 处理器，支持丰富功能"""

        def __init__(self, app):
            self.app = app
            self.base_dir = app_config.base_dir or os.getcwd()
            self.temp_dir = os.path.join(self.base_dir, 'temp_uploads')
            logger.info(f"WebDAV base dir: {self.base_dir}")
            logger.info(f"WebDAV temp dir: {self.temp_dir}")

            # 确保临时目录存在
            os.makedirs(self.temp_dir, exist_ok=True)

            # 功能开关配置
            self.features = {
                'file_upload': True,
                'file_download': True,
                'file_delete': True,
                'directory_browsing': True,
                'search': True,
                'thumbnails': True,
                'versioning': False,  # 可扩展版本控制
                'sharing': False,  # 可扩展文件分享
                'reports': True,  # 支持报表生成
            }

        def handle_request(self, path, method, user_info):
            """Handle WebDAV requests"""
            try:
                # 添加边界检查
                if not path:
                    path_parts = []
                else:
                    path_parts = [p for p in path.strip('/').split('/') if p]

                logger.info(f"Processing path: '{path}', parts: {path_parts}, method: {method}")

                if len(path_parts) == 0:
                    # Root directory
                    return self.handle_root_request(method, user_info)
                elif len(path_parts) == 1:
                    # User directory
                    if path_parts[0] != user_info['username']:
                        logger.warning(
                            f"User mismatch: requested {path_parts[0]}, authenticated {user_info['username']}")
                        return self.not_found()

                    return self.handle_user_directory(method, user_info)
                else:
                    # File or special request
                    if path_parts[0] != user_info['username']:
                        return self.not_found()

                    # 添加边界检查
                    if len(path_parts) < 2:
                        logger.error(f"Insufficient path parts: {path_parts}")
                        return self.not_found()

                    # Check for special path
                    if path_parts[1].startswith('.'):
                        return self._handle_special_request(path_parts, method, user_info)
                    else:
                        return self.handle_file_request(path_parts, method, user_info)

            except Exception as e:
                logger.error(f"WebDAV request error: {e}", exc_info=True)
                logger.error(f"Path: {path}, Method: {method}, User: {user_info}")
                return self.error_response(500, "Internal Server Error")

        def _serve_search_results(self, results, user_info, search_query):
            """提供搜索结果"""
            html_content = f"""
                <html>
                    <head>
                        <title>Search Results for "{search_query}"</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            .result {{ border: 1px solid #ddd; padding: 10px; margin: 5px 0; }}
                            .filename {{ font-weight: bold; }}
                            .fileinfo {{ color: #666; font-size: 0.9em; }}
                        </style>
                    </head>
                    <body>
                        <h1>Search Results for "{search_query}"</h1>
                        <p>Found {len(results)} files</p>
                """

            with get_db() as db:
                for media in results:
                    file_hash = db.query(FileHash).filter(FileHash.hash == media.hash).first()
                    if file_hash:
                        safe_filename = urllib.parse.quote(media.original_filename)
                        html_content += f"""
                            <div class="result">
                                <div class="filename">
                                    <a href="/dav/{user_info['username']}/{safe_filename}">{media.original_filename}</a>
                                </div>
                                <div class="fileinfo">
                                    Size: {self._format_file_size(file_hash.file_size)} | 
                                    Type: {file_hash.mime_type or 'Unknown'} |
                                    Created: {media.created_at.strftime('%Y-%m-%d %H:%M') if media.created_at else 'Unknown'}
                                </div>
                            </div>
                            """

            html_content += "</body></html>"
            return Response(html_content, content_type='text/html')

        def _serve_file_info(self, media, file_hash, user_info):
            """提供文件详细信息"""
            storage_path = file_hash.storage_path
            
            # 检查存储路径是否为S3路径
            if storage_path.startswith('s3://'):
                file_exists = s3_storage.file_exists(storage_path)
                file_stats = None  # S3中无法获取文件统计信息
                
                info = {
                    'filename': media.original_filename,
                    'hash': file_hash.hash,
                    'size': file_hash.file_size,
                    'mime_type': file_hash.mime_type,
                    'storage_path': storage_path,
                    'file_exists': file_exists,
                    'actual_size': file_hash.file_size if file_exists else 0,
                    'created': None,  # S3中无法获取创建时间
                    'modified': None,  # S3中无法获取修改时间
                    'download_url': f"/dav/{user_info['username']}/{urllib.parse.quote(media.original_filename)}",
                    'storage_type': 's3'
                }
            else:
                # 使用本地文件路径（兼容旧数据）
                if not os.path.isabs(storage_path):
                    file_path = os.path.join(self.base_dir, storage_path)
                else:
                    file_path = storage_path

                file_exists = os.path.exists(file_path)
                file_stats = os.stat(file_path) if file_exists else None

                info = {
                    'filename': media.original_filename,
                    'hash': file_hash.hash,
                    'size': file_hash.file_size,
                    'mime_type': file_hash.mime_type,
                    'storage_path': storage_path,
                    'file_exists': file_exists,
                    'actual_size': file_stats.st_size if file_stats else 0,
                    'created': file_stats.st_ctime if file_stats else None,
                    'modified': file_stats.st_mtime if file_stats else None,
                    'download_url': f"/dav/{user_info['username']}/{urllib.parse.quote(media.original_filename)}",
                    'storage_type': 'local'
                }

            return Response(
                response=json.dumps(info, indent=2),
                status=200,
                content_type='application/json'
            )

        @staticmethod
        def _format_file_size(size_bytes):
            """格式化文件大小"""
            if size_bytes == 0:
                return "0 B"
            size_names = ["B", "KB", "MB", "GB"]
            i = 0
            while size_bytes >= 1024 and i < len(size_names) - 1:
                size_bytes /= 1024.0
                i += 1
            return f"{size_bytes:.1f} {size_names[i]}"

        @staticmethod
        def authenticate_user():
            """Authenticate user using Basic Auth with refresh token"""
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Basic '):
                return None

            try:
                import base64
                auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                username, refresh_token = auth_decoded.split(':', 1)

                with get_db() as db:
                    user = db.query(User).filter(User.username == username).first()

                    if user:
                        return {
                            'id': user.id,
                            'username': user.username,
                            'vip_level': user.vip_level or 0,
                            'created_at': user.created_at.isoformat() if user.created_at else None,
                            'disk_used': get_user_storage_used(user.id),
                            'disk_limit': app_config.USER_FREE_STORAGE_LIMIT,
                        }
            except Exception as e:
                logger.error(f"Basic Auth error: {e}")
                return None

        @staticmethod
        def method_not_allowed(message="Method Not Allowed"):
            """Generate a 405 Method Not Allowed response"""
            return Response(
                response=message,
                status=405,
                content_type='text/plain'
            )

        @staticmethod
        def not_found(message="Not Found"):
            """Generate a 404 Not Found response"""
            return Response(
                response=message,
                status=404,
                content_type='text/plain'
            )

        @staticmethod
        def error_response(status, message):
            """Generate a generic error response"""
            return Response(
                response=message,
                status=status,
                content_type='text/plain'
            )

        def handle_root_request(self, method, user_info):
            """Handle root directory requests"""
            handlers = {
                'PROPFIND': self._handle_propfind_root,
                'OPTIONS': build_options_response,
                'GET': _serve_web_interface
            }
            return handlers.get(method, self.method_not_allowed)(user_info)

        def _serve_user_web_interface(self, user_info):
            """提供用户文件浏览界面"""
            with get_db() as db_session:
                media_files = db_session.query(Media).filter(Media.user_id == user_info['id']).all()

                file_list = ""
                for media in media_files:
                    file_hash = db_session.query(FileHash).filter(FileHash.hash == media.hash).first()
                    if file_hash:
                        safe_filename = urllib.parse.quote(media.original_filename)
                        file_list += f"""
                            <tr>
                                <td><a href="/dav/{user_info['username']}/{safe_filename}">{media.original_filename}</a></td>
                                <td>{self._format_file_size(file_hash.file_size)}</td>
                                <td>{file_hash.mime_type or 'Unknown'}</td>
                                <td>
                                    <a href="/dav/{user_info['username']}/.thumbnails/{safe_filename}">Thumbnail</a> |
                                    <a href="/dav/{user_info['username']}/.info/{safe_filename}">Info</a>
                                </td>
                            </tr>
                            """

            return f"""
                <html>
                    <head>
                        <title>{user_info['username']}'s Files</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            table {{ width: 100%; border-collapse: collapse; }}
                            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                            th {{ background-color: #f2f2f2; }}
                            .search-box {{ margin: 20px 0; }}
                        </style>
                    </head>
                    <body>
                        <h1>{user_info['username']}'s Files</h1>

                        <div class="search-box">
                            <form action="/dav/{user_info['username']}/.search" method="get">
                                <input type="text" name="q" placeholder="Search files..." style="padding: 8px; width: 300px;">
                                <button type="submit">Search</button>
                            </form>
                        </div>

                        <table>
                            <thead>
                                <tr>
                                    <th>Filename</th>
                                    <th>Size</th>
                                    <th>Type</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {file_list}
                            </tbody>
                        </table>

                        <p>Total files: {len(media_files)}</p>
                    </body>
                </html>
                """

        def handle_user_directory(self, method, user_info):
            """Handle user directory requests"""
            handlers = {
                'PROPFIND': self.handle_propfind_user_dir,
                'MKCOL': self.handle_mkcol,
                'GET': self._serve_user_web_interface
            }
            return handlers.get(method, self.method_not_allowed)(user_info)

        @staticmethod
        def handle_mkcol(user_info):
            """Handle MKCOL (make collection) requests"""
            return Response(status=405)

        def handle_propfind_user_dir(self, user_info):
            """Handle PROPFIND request for user directory"""
            # Get user's disk usage
            total_size, used_size, free_size = get_disk_usage(user_info)

            with get_db() as db:
                media_files = db.query(Media).filter(
                    Media.user_id == user_info['id']
                ).all()

                # Prepare items for XML generation
                items = [{
                    'href': f'/dav/{user_info["username"]}/',
                    'displayname': f'{user_info["username"]}\'s Media',
                    'collection': True,
                    'creationdate': '2025-10-01T00:00:00Z',
                    'getlastmodified': safe_date_string,
                    'getcontentlength': total_size,
                    'quota-used-bytes': used_size,
                    'quota-available-bytes': free_size,
                    'supportedlock': True
                }]

                # Add special directories
                special_dirs = [
                    ('.search', 'Search Files'),
                    ('.reports', 'Storage Reports'),
                    ('.info', 'Account Information')
                ]

                for dir_name, display_name in special_dirs:
                    items.append({
                        'href': f'/dav/{user_info["username"]}/{dir_name}/',
                        'displayname': display_name,
                        'collection': True,
                        'creationdate': '2025-10-01T00:00:00Z',
                        'getlastmodified': safe_date_string
                    })

                # Add files
                for media in media_files:
                    file_hash = db.query(FileHash).filter(
                        FileHash.hash == media.hash
                    ).first()

                    if file_hash:
                        safe_filename = urllib.parse.quote(media.original_filename)
                        items.append({
                            'href': f'/dav/{user_info["username"]}/{safe_filename}',
                            'displayname': media.original_filename,
                            'creationdate': '2025-10-01T00:00:00Z',
                            'getlastmodified': safe_date_string,
                            'getcontentlength': file_hash.file_size,
                            'getcontenttype': file_hash.mime_type or 'application/octet-stream',
                            'getetag': file_hash.hash,
                            'supportedlock': True
                        })

                # Generate XML response
                xml_response = self.generate_xml_response(items, safe_date_string)
                return Response(
                    response=xml_response,
                    status=207,
                    content_type='application/xml; charset="utf-8"',
                    headers={
                        'DAV': '1, 2',
                        'Allow': 'OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL',
                    }
                )

        def _handle_propfind_root(self, user_info):
            """处理根目录的 PROPFIND 请求"""
            # 动态获取当前用户的磁盘使用情况
            total_size, used_size, free_size = get_disk_usage(user_info)

            xml_parts = ['<?xml version="1.0" encoding="utf-8"?>', '<D:multistatus xmlns:D="DAV:">', f'<D:response>',
                         f'<D:href>/dav/{user_info["username"]}/</D:href>', f'<D:propstat>', f'<D:prop>',
                         f'<D:resourcetype><D:collection/></D:resourcetype>',
                         f'<D:displayname>{user_info["username"]}\'s Media</D:displayname>',
                         f'<D:creationdate>2025-10-01T00:00:00Z</D:creationdate>',
                         f'<D:getlastmodified>{safe_date_string}</D:getlastmodified>',
                         f'<D:getcontentlength>{total_size}</D:getcontentlength>',
                         f'<D:quota-used-bytes>{used_size}</D:quota-used-bytes>',
                         f'<D:quota-available-bytes>{free_size}</D:quota-available-bytes>', f'</D:prop>',
                         f'<D:status>HTTP/1.1 200 OK</D:status>', f'</D:propstat>', f'</D:response>',
                         '</D:multistatus>']

            xml_response = '\n'.join(xml_parts)

            return Response(
                response=xml_response,
                status=207,
                content_type='application/xml; charset="utf-8"',
                headers={
                    'DAV': '1, 2',
                    'Allow': 'OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL',
                }
            )

        def handle_file_request(self, path_parts, method, user_info):
            """Handle file requests"""
            filename = '/'.join(path_parts[1:])
            original_filename = urllib.parse.unquote(filename) if '%' in filename else filename

            # 先查询文件信息
            with get_db() as db:
                media = db.query(Media).filter(
                    Media.user_id == user_info['id'],
                    Media.original_filename == original_filename
                ).first()

                if not media:
                    return self.not_found()

                file_hash = db.query(FileHash).filter(
                    FileHash.hash == media.hash
                ).first()

                if not file_hash:
                    return self.not_found()

            handlers = {
                'GET': lambda: self.handle_file_download(media, file_hash, user_info, 'GET'),
                'HEAD': lambda: self.handle_file_download(media, file_hash, user_info, 'HEAD'),
                'PUT': lambda: self.handle_put_file(original_filename, user_info),
                'PROPFIND': lambda: self.handle_propfind_file(media, file_hash, user_info),
                'DELETE': lambda: self.handle_delete_file(original_filename, user_info)
            }

            handler = handlers.get(method)
            if handler:
                return handler()
            else:
                return self.method_not_allowed()

        def handle_file_download(self, media, file_hash, user_info, method='GET'):
            """Handle file download requests"""
            if method == 'GET':
                return self.serve_file(file_hash, media.original_filename)
            else:  # HEAD
                return self.file_headers(file_hash, media.original_filename)

        def handle_propfind_file(self, media, file_hash, user_info):
            """Handle PROPFIND request for a file"""
            # Get user's disk usage
            _, used_size, free_size = get_disk_usage(user_info)

            safe_filename = urllib.parse.quote(media.original_filename)

            xml_parts = ['<?xml version="1.0" encoding="utf-8"?>', '<D:multistatus xmlns:D="DAV:">', f'<D:response>',
                         f'<D:href>/dav/{user_info["username"]}/{safe_filename}</D:href>', f'<D:propstat>', f'<D:prop>',
                         f'<D:resourcetype/>', f'<D:displayname>{media.original_filename}</D:displayname>',
                         f'<D:creationdate>2025-10-01T00:00:00Z</D:creationdate>',
                         f'<D:getlastmodified>{safe_date_string}</D:getlastmodified>',
                         f'<D:getcontentlength>{file_hash.file_size}</D:getcontentlength>',
                         f'<D:getcontenttype>{file_hash.mime_type or "application/octet-stream"}</D:getcontenttype>',
                         f'<D:getetag>"{file_hash.hash}"</D:getetag>', f'<D:supportedlock>', f'<D:lockentry>',
                         f'<D:lockscope><D:exclusive/></D:lockscope>', f'<D:locktype><D:write/></D:locktype>',
                         f'</D:lockentry>', f'</D:supportedlock>', f'</D:prop>',
                         f'<D:status>HTTP/1.1 200 OK</D:status>', f'</D:propstat>', f'</D:response>',
                         '</D:multistatus>']

            xml_response = '\n'.join(xml_parts)

            return Response(
                response=xml_response,
                status=207,
                content_type='application/xml; charset="utf-8"',
                headers={
                    'DAV': '1, 2',
                }
            )

        def handle_delete_file(self, filename, user_info):
            """Handle file deletion with trash and confirmation"""
            try:
                # 检查确认参数
                confirm = request.args.get('confirm', 'false').lower() == 'true'
                if not confirm:
                    return self.error_response(400, "Delete requires confirmation")

                original_filename = urllib.parse.unquote(filename)

                with get_db() as db:
                    media = db.query(Media).filter(
                        Media.user_id == user_info['id'],
                        Media.original_filename == original_filename
                    ).first()

                    if not media:
                        return self.not_found()

                    file_hash_value = media.hash
                    file_hash_record = db.query(FileHash).filter(FileHash.hash == file_hash_value).first()

                    if not file_hash_record:
                        return self.not_found()

                    # 检查存储路径是否为S3路径
                    storage_path = file_hash_record.storage_path
                    if storage_path.startswith('s3://'):
                        # 从S3删除文件
                        success = s3_storage.delete_file(storage_path)
                        if not success:
                            logger.warning(f"Failed to delete file from S3: {storage_path}")
                    else:
                        # 本地文件处理（兼容旧数据）
                        original_path = os.path.join(self.base_dir, storage_path)
                        if os.path.exists(original_path):
                            # 创建回收站子目录
                            user_trash_dir = os.path.join(self.base_dir, 'trash', str(user_info['id']))
                            os.makedirs(user_trash_dir, exist_ok=True)

                            # 移动文件到回收站
                            trash_path = os.path.join(user_trash_dir,
                                                      f"{file_hash_value}_{int(datetime.now().timestamp())}")
                            os.rename(original_path, trash_path)

                    # 记录删除日志
                    deletion_log = {
                        'user_id': user_info['id'],
                        'filename': original_filename,
                        'hash': file_hash_value,
                        'deleted_at': datetime.now().isoformat(),
                        'size': file_hash_record.file_size if file_hash_record else 0
                    }
                    log_file = os.path.join(self.base_dir, 'trash', 'deletion_log.json')
                    os.makedirs(os.path.dirname(log_file), exist_ok=True)
                    with open(log_file, 'a') as f:
                        f.write(json.dumps(deletion_log) + '\n')

                    # 删除数据库记录
                    db.delete(media)

                    # 检查是否还有其他引用
                    other_media = db.query(Media).filter(Media.hash == file_hash_value).first()
                    if not other_media and file_hash_record:
                        db.delete(file_hash_record)

                    db.commit()

                return Response(status=204)

            except Exception as e:
                logger.error(f"File deletion error: {e}", exc_info=True)
                return self.error_response(500, f"Deletion failed: {str(e)}")

        def handle_put_file(self, filename, user_info):
            """Handle file upload"""
            global temp_file_path
            try:
                original_filename = urllib.parse.unquote(filename)
                total_size, used_size, free_size = get_disk_usage(user_info)

                content_length = request.content_length or 0
                if content_length > free_size:
                    return self.error_response(507, "Insufficient Storage")

                # 使用流式上传避免内存问题
                file_hash = hashlib.sha256()
                temp_file_path = os.path.join(self.temp_dir, f"temp_upload_{user_info['id']}_{original_filename}")

                with open(temp_file_path, 'wb') as f:
                    while True:
                        chunk = request.stream.read(8192)  # 8KB chunks
                        if not chunk:
                            break
                        file_hash.update(chunk)
                        f.write(chunk)

                file_hash_value = file_hash.hexdigest()

                # 获取文件大小
                file_size = os.path.getsize(temp_file_path)

                with get_db() as db:
                    existing_hash = db.query(FileHash).filter(FileHash.hash == file_hash_value).first()

                    if existing_hash:
                        existing_media = db.query(Media).filter(
                            Media.user_id == user_info['id'],
                            Media.hash == file_hash_value
                        ).first()

                        if existing_media:
                            os.remove(temp_file_path)  # 删除临时文件
                            return self.error_response(409, "File already exists")

                        # 上传文件到S3
                        with open(temp_file_path, 'rb') as f:
                            file_data = f.read()
                        storage_path = s3_storage.save_file(file_hash_value, file_data, original_filename)
                        os.remove(temp_file_path)  # 删除临时文件

                        new_media = Media(
                            user_id=user_info['id'],
                            original_filename=original_filename,
                            hash=file_hash_value
                        )
                        db.add(new_media)
                        db.commit()

                        return Response(
                            status=200,
                            headers={'ETag': f'"{file_hash_value}"'}
                        )
                    else:
                        # 上传文件到S3
                        with open(temp_file_path, 'rb') as f:
                            file_data = f.read()
                        storage_path = s3_storage.save_file(file_hash_value, file_data, original_filename)
                        os.remove(temp_file_path)  # 删除临时文件

                        import mimetypes
                        mime_type, _ = mimetypes.guess_type(original_filename)

                        new_file_hash = FileHash(
                            hash=file_hash_value,
                            filename=original_filename,
                            file_size=file_size,
                            mime_type=mime_type or 'application/octet-stream',
                            storage_path=storage_path
                        )
                        db.add(new_file_hash)

                        new_media = Media(
                            user_id=user_info['id'],
                            original_filename=original_filename,
                            hash=file_hash_value
                        )
                        db.add(new_media)

                        db.commit()

                        return Response(
                            status=201,
                            headers={'ETag': f'"{file_hash_value}"'}
                        )

            except Exception as e:
                logger.error(f"File upload error: {e}", exc_info=True)
                # 清理临时文件
                if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
                return self.error_response(500, f"Upload failed: {str(e)}")

        @staticmethod
        def generate_xml_response(items, safe_date_string):
            """Generate WebDAV XML response from a list of items"""
            xml_parts = ['<?xml version="1.0" encoding="utf-8"?>', '<D:multistatus xmlns:D="DAV:">']

            for item in items:
                xml_parts.append('<D:response>')
                xml_parts.append(f'<D:href>{item["href"]}</D:href>')
                xml_parts.append('<D:propstat>')
                xml_parts.append('<D:prop>')

                if item.get('collection'):
                    xml_parts.append('<D:resourcetype><D:collection/></D:resourcetype>')
                else:
                    xml_parts.append('<D:resourcetype/>')

                xml_parts.extend([
                    f'<D:displayname>{item["displayname"]}</D:displayname>',
                    f'<D:creationdate>{item.get("creationdate", "2025-10-01T00:00:00Z")}</D:creationdate>',
                    f'<D:getlastmodified>{item.get("getlastmodified", safe_date_string)}</D:getlastmodified>',
                    f'<D:getcontentlength>{item.get("getcontentlength", 0)}</D:getcontentlength>'
                ])

                if 'getcontenttype' in item:
                    xml_parts.append(f'<D:getcontenttype>{item["getcontenttype"]}</D:getcontenttype>')

                if 'getetag' in item:
                    xml_parts.append(f'<D:getetag>"{item["getetag"]}"</D:getetag>')

                xml_parts.append('</D:prop>')
                xml_parts.append('<D:status>HTTP/1.1 200 OK</D:status>')
                xml_parts.append('</D:propstat>')
                xml_parts.append('</D:response>')

            xml_parts.append('</D:multistatus>')
            return '\n'.join(xml_parts)

        def serve_file(self, file_hash, filename):
            """Serve file for download"""
            storage_path = file_hash.storage_path
            
            if storage_path.startswith('s3://'):
                # 从S3下载文件到临时位置
                file_data = s3_storage.load_file(storage_path)
                if file_data is None:
                    return self.not_found()
                
                # 将文件数据写入临时文件
                temp_file_path = os.path.join(self.temp_dir, f"temp_serve_{file_hash.hash}")
                
                with open(temp_file_path, 'wb') as temp_file:
                    temp_file.write(file_data)
                
                try:
                    response = send_file(
                        temp_file_path,
                        as_attachment=False,
                        download_name=filename,
                        mimetype=file_hash.mime_type or 'application/octet-stream',
                        last_modified=safe_timestamp,
                        etag=file_hash.hash
                    )
                    
                    # 设置响应后删除临时文件
                    def remove_file(response):
                        try:
                            if os.path.exists(temp_file_path):
                                os.remove(temp_file_path)
                        except Exception as e:
                            logger.error(f"Error removing temp file: {e}")
                        return response
                    
                    response.call_on_close(lambda: remove_file(None))
                    return response
                except Exception as e:
                    # 确保临时文件被清理
                    if os.path.exists(temp_file_path):
                        os.remove(temp_file_path)
                    logger.error(f"Error serving file from S3: {e}")
                    return self.error_response(500, "File serving error")


        @staticmethod
        def file_headers(file_hash, filename):
            """Generate file headers response"""
            return Response(
                status=200,
                headers={
                    'Content-Type': file_hash.mime_type or 'application/octet-stream',
                    'Content-Length': str(file_hash.file_size),
                    'Last-Modified': safe_date_string,
                    'ETag': f'"{file_hash.hash}"',
                    'Accept-Ranges': 'bytes',
                }
            )

        # 特殊功能处理方法
        def _handle_special_request(self, path_parts, method, user_info):
            """处理特殊功能请求"""
            try:
                # 添加边界检查
                if len(path_parts) < 2:
                    logger.error(f"Special request with insufficient parts: {path_parts}")
                    return self.not_found()

                special_command = path_parts[1]

                # 根据特殊命令处理，确保有足够的路径部分
                if special_command == '.search':
                    remaining_parts = path_parts[2:] if len(path_parts) > 2 else []
                    return self._handle_search_request(remaining_parts, method, user_info)
                elif special_command == '.reports':
                    remaining_parts = path_parts[2:] if len(path_parts) > 2 else []
                    return self._handle_reports_request(remaining_parts, method, user_info)
                elif special_command == '.thumbnails':
                    remaining_parts = path_parts[2:] if len(path_parts) > 2 else []
                    return self.handle_thumbnail_request(remaining_parts, method, user_info)
                elif special_command == '.info':
                    remaining_parts = path_parts[2:] if len(path_parts) > 2 else []
                    return self.handle_info_request(remaining_parts, method, user_info)
                else:
                    logger.warning(f"Unknown special command: {special_command}")
                    return self.not_found()
            except Exception as e:
                logger.error(f"Error in special request handling: {e}", exc_info=True)
                return self.error_response(500, "Internal Server Error")

        def _handle_search_request(self, query_parts, method, user_info):
            """处理搜索请求"""
            if method != 'GET' and method != 'PROPFIND':
                return self.method_not_allowed()

            search_query = request.args.get('q', '')
            file_type = request.args.get('type', '')
            date_from = request.args.get('from', '')
            date_to = request.args.get('to', '')
            size_min = request.args.get('size_min', '')
            size_max = request.args.get('size_max', '')

            # 验证和清理输入参数以防止SQL注入
            from src.utils.security.safe import validate_input
            is_valid_search, clean_search = validate_input(search_query, r'^[a-zA-Z0-9_\-\s\.]+$')
            if not is_valid_search:
                return self.error_response(400, "Invalid search query")
            
            is_valid_type, clean_type = validate_input(file_type, r'^[a-zA-Z0-9\-\s\.]+$')
            if not is_valid_type:
                return self.error_response(400, "Invalid file type filter")

            with get_db() as db:
                query = db.query(Media).filter(Media.user_id == user_info['id'])

                if clean_search:
                    # 使用参数化查询防止SQL注入
                    query = query.filter(Media.original_filename.contains(clean_search))

                if clean_type:
                    # 连接 FileHash 表进行文件类型过滤，使用参数化查询
                    query = query.join(FileHash).filter(FileHash.mime_type.contains(clean_type))

                results = query.all()

                if method == 'PROPFIND':
                    return _handle_propfind_search_results(results, user_info, clean_search)
                else:
                    return self._serve_search_results(results, user_info, clean_search)

        def _serve_thumbnail(self, file_hash, filename):
            """提供缩略图"""
            # 这里可以实现缩略图生成逻辑
            # 目前先返回原文件或占位图
            storage_path = file_hash.storage_path
            
            if storage_path.startswith('s3://'):
                # 从S3下载文件到临时位置
                file_data = s3_storage.load_file(storage_path)
                if file_data is None:
                    return self.not_found()
                
                # 将文件数据写入临时文件
                temp_file_path = os.path.join(self.temp_dir, f"temp_thumb_{file_hash.hash}")
                
                with open(temp_file_path, 'wb') as temp_file:
                    temp_file.write(file_data)
                
                try:
                    response = send_file(temp_file_path)
                    
                    # 设置响应后删除临时文件
                    def remove_file(response):
                        try:
                            if os.path.exists(temp_file_path):
                                os.remove(temp_file_path)
                        except Exception as e:
                            logger.error(f"Error removing temp thumb file: {e}")
                        return response
                    
                    response.call_on_close(lambda: remove_file(None))
                    return response
                except Exception as e:
                    # 确保临时文件被清理
                    if os.path.exists(temp_file_path):
                        os.remove(temp_file_path)
                    logger.error(f"Error serving thumbnail from S3: {e}")
                    return self.not_found()


        def _generate_storage_report(self, media_files, user_info):
            """生成存储使用报告"""
            total_size = 0
            file_types = {}

            with get_db() as db_session:
                for media in media_files:
                    file_hash = db_session.query(FileHash).filter(FileHash.hash == media.hash).first()
                    if file_hash:
                        total_size += file_hash.file_size
                        file_type = file_hash.mime_type or 'unknown'
                        file_types[file_type] = file_types.get(file_type, 0) + file_hash.file_size

            report = {
                'user': user_info['username'],
                'total_files': len(media_files),
                'total_size': total_size,
                'disk_used': int(float(user_info['disk_used'])),
                'disk_limit': int(float(user_info['disk_limit'])),
                'file_type_breakdown': file_types,
                'generated_at': datetime.now().isoformat()
            }

            return Response(
                response=json.dumps(report, indent=2),
                status=200,
                content_type='application/json'
            )

        def _handle_reports_request(self, report_parts, method, user_info):
            """处理报表请求"""
            if method == 'PROPFIND':
                # 返回报表目录的PROPFIND响应
                total_size, used_size, free_size = get_disk_usage(user_info)
                items = [{
                    'href': f'/dav/{user_info["username"]}/.reports/',
                    'displayname': 'Storage Reports',
                    'collection': True,
                    'creationdate': '2025-10-01T00:00:00Z',
                    'getlastmodified': safe_date_string,
                    'getcontentlength': total_size,
                    'quota-used-bytes': used_size,
                    'quota-available-bytes': free_size
                }]
                xml_response = self.generate_xml_response(items, safe_date_string)
                return Response(
                    response=xml_response,
                    status=207,
                    content_type='application/xml; charset="utf-8"',
                    headers={'DAV': '1, 2'}
                )
            elif method == 'GET':
                report_type = report_parts[0] if report_parts else 'storage'

                with get_db() as db:
                    media_files = db.query(Media).filter(Media.user_id == user_info['id']).all()

                    if report_type == 'storage':
                        return self._generate_storage_report(media_files, user_info)
                    elif report_type == 'filetypes':
                        return _generate_filetype_report(media_files, user_info)
                    elif report_type == 'timeline':
                        return _generate_timeline_report(media_files, user_info)
                    else:
                        return self.not_found()
            else:
                return self.method_not_allowed()

        def handle_thumbnail_request(self, thumbnail_parts, method, user_info):
            """处理缩略图请求"""
            if method != 'GET':
                return self.method_not_allowed()

            if len(thumbnail_parts) < 1:
                return self.not_found()

            filename = '/'.join(thumbnail_parts)
            original_filename = urllib.parse.unquote(filename)

            with get_db() as db:
                media = db.query(Media).filter(
                    Media.user_id == user_info['id'],
                    Media.original_filename == original_filename
                ).first()

                if not media:
                    return self.not_found()

                file_hash = db.query(FileHash).filter(FileHash.hash == media.hash).first()
                if not file_hash:
                    return self.not_found()

                return self._serve_thumbnail(file_hash, original_filename)

        def handle_info_request(self, info_parts, method, user_info):
            """处理文件信息请求"""
            if method == 'PROPFIND':
                # 返回info目录的PROPFIND响应
                total_size, used_size, free_size = get_disk_usage(user_info)
                items = [{
                    'href': f'/dav/{user_info["username"]}/.info/',
                    'displayname': 'Account Information',
                    'collection': True,
                    'creationdate': '2025-10-01T00:00:00Z',
                    'getlastmodified': safe_date_string,
                    'getcontentlength': total_size,
                    'quota-used-bytes': used_size,
                    'quota-available-bytes': free_size
                }]
                xml_response = self.generate_xml_response(items, safe_date_string)
                return Response(
                    response=xml_response,
                    status=207,
                    content_type='application/xml; charset="utf-8"',
                    headers={'DAV': '1, 2'}
                )
            elif method == 'GET':
                if len(info_parts) < 1:
                    # 返回用户总体信息
                    return _serve_user_info(user_info)
                else:
                    # 返回特定文件信息
                    filename = '/'.join(info_parts)
                    original_filename = urllib.parse.unquote(filename)

                    with get_db() as db:
                        media = db.query(Media).filter(
                            Media.user_id == user_info['id'],
                            Media.original_filename == original_filename
                        ).first()
                        if not media:
                            return self.not_found()
                        file_hash = db.query(FileHash).filter(FileHash.hash == media.hash).first()
                        if not file_hash:
                            return self.not_found()
                        return self._serve_file_info(media, file_hash, user_info)
            else:
                return self.method_not_allowed()

        def handle_standard_request(self, path_parts, method, user_info):
            """处理标准WebDAV请求"""
            try:
                # 添加边界检查
                if not path_parts:
                    logger.error("Empty path_parts in standard request")
                    return self.not_found()

                if method == 'PROPFIND':
                    # 处理PROPFIND请求
                    if len(path_parts) == 1 and path_parts[0] == user_info['username']:
                        # 用户目录请求
                        return self.handle_propfind_user_dir(user_info)
                    else:
                        # 文件/子目录请求
                        filename = '/'.join(path_parts[1:]) if len(path_parts) > 1 else ''
                        if not filename:
                            # 如果只有用户名，返回用户目录
                            return self.handle_propfind_user_dir(user_info)

                        original_filename = urllib.parse.unquote(filename)

                        with get_db() as db_session:
                            media = db_session.query(Media).filter(
                                Media.user_id == user_info['id'],
                                Media.original_filename == original_filename
                            ).first()

                            if not media:
                                return self.not_found()

                elif method == 'PUT':
                    # 处理文件上传
                    if len(path_parts) < 2:
                        return self.bad_request()

                    filename = '/'.join(path_parts[1:])
                    original_filename = urllib.parse.unquote(filename)
                    file_data = request.get_data()

                    if not file_data:
                        return self.bad_request("Empty file content")

                    # 计算文件哈希
                    file_hash = hashlib.sha256(file_data).hexdigest()
                    file_size = len(file_data)
                    mime_type = mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'

                    with get_db() as db_session:
                        # 检查文件是否已存在
                        file_hash_record = db_session.query(FileHash).filter_by(hash=file_hash).first()

                        if not file_hash_record:
                            # 上传文件到S3
                            storage_path = s3_storage.save_file(file_hash, file_data, original_filename)

                            # 创建FileHash记录
                            file_hash_record = FileHash(
                                hash=file_hash,
                                filename=original_filename,
                                file_size=file_size,
                                mime_type=mime_type,
                                storage_path=storage_path
                            )
                            db_session.add(file_hash_record)
                        else:
                            # 增加引用计数
                            file_hash_record.reference_count += 1

                        # 创建Media记录
                        media = Media(
                            user_id=user_info['id'],
                            hash=file_hash,
                            original_filename=original_filename
                        )
                        db_session.add(media)
                        db_session.commit()

                        return Response(status=201)

                elif method == 'DELETE':
                    # 处理文件删除
                    if len(path_parts) < 2:
                        return self.bad_request()

                    filename = '/'.join(path_parts[1:])
                    original_filename = urllib.parse.unquote(filename)

                    with get_db() as db_session:
                        # 查找Media记录
                        media = db_session.query(Media).filter(
                            Media.user_id == user_info['id'],
                            Media.original_filename == original_filename
                        ).first()

                        if not media:
                            return self.not_found()

                        # 查找FileHash记录
                        file_hash = db_session.query(FileHash).filter_by(hash=media.hash).first()

                        # 删除Media记录
                        db_session.delete(media)

                        # 更新引用计数
                        file_hash.reference_count -= 1

                        # 如果引用计数为0，删除物理文件和FileHash记录
                        if file_hash.reference_count <= 0:
                            storage_path = file_hash.storage_path
                            try:
                                if storage_path.startswith('s3://'):
                                    # 从S3删除文件
                                    s3_storage.delete_file(storage_path)
                                else:
                                    # 不再支持本地存储路径
                                    logger.warning(f"不支持的存储路径格式，无法删除: {storage_path}")

                            except OSError:
                                pass
                            db_session.delete(file_hash)

                        db_session.commit()

                        file_hash = db_session.query(FileHash).filter(FileHash.hash == media.hash).first()
                        if not file_hash:
                            return self.not_found()

                        items = [{
                            'href': f'/dav/{user_info["username"]}/{filename}',
                            'displayname': original_filename,
                            'collection': False,
                            'creationdate': media.created_at.isoformat() + 'Z' if media.created_at else '2025-10-01T00:00:00Z',
                            'getlastmodified': media.updated_at.isoformat() + 'Z' if media.updated_at else safe_date_string,
                            'getcontentlength': file_hash.file_size,
                            'getcontenttype': file_hash.mime_type or 'application/octet-stream'
                        }]

                    xml_response = self.generate_xml_response(items, safe_date_string)
                    return Response(
                        response=xml_response,
                        status=207,
                        content_type='application/xml; charset="utf-8"',
                        headers={'DAV': '1, 2'}
                    )
                elif method == 'POST':
                    # 处理粘贴上传
                    if 'file' in request.files:
                        # 处理multipart/form-data上传
                        file = request.files['file']
                        if not file.filename:
                            return self.error_response(400, "No file selected")

                        filename = '/'.join(path_parts[1:]) if len(path_parts) > 1 else file.filename
                        return self.handle_put_file(filename, user_info)
                    elif request.content_type == 'application/octet-stream':
                        # 处理二进制流上传
                        filename = '/'.join(path_parts[1:]) if len(path_parts) > 1 else 'pasted_file.bin'
                        return self.handle_put_file(filename, user_info)
                    else:
                        return self.method_not_allowed()

                elif method in ('GET', 'HEAD'):
                    # 处理文件下载请求
                    if len(path_parts) < 2:
                        return self.not_found()

                    filename = '/'.join(path_parts[1:])
                    original_filename = urllib.parse.unquote(filename)

                    with get_db() as db_session:
                        media = db_session.query(Media).filter(
                            Media.user_id == user_info['id'],
                            Media.original_filename == original_filename
                        ).first()

                        if not media:
                            return self.not_found()

                        file_hash = db_session.query(FileHash).filter(FileHash.hash == media.hash).first()
                        if not file_hash:
                            return self.not_found()

                        return self.serve_file(file_hash, original_filename)

                else:
                    return self.method_not_allowed()

            except Exception as e:
                logger.error(f"Error in handle_standard_request: {e}", exc_info=True)
                return self.error_response(500, "Internal Server Error")

        @staticmethod
        def bad_request(message="Bad Request"):
            """处理错误请求"""
            return Response(
                response=message,
                status=400,
                content_type='text/plain'
            )

    # 创建处理器实例
    handler = WebDAVHandler(app)

    # WebDAV routes
    @bp.route('/dav/', defaults={'path': ''},
              methods=['OPTIONS', 'GET', 'HEAD', 'PROPFIND', 'PUT', 'POST', 'DELETE', 'MKCOL', 'MOVE', 'COPY'])
    @bp.route('/dav/<path:path>',
              methods=['OPTIONS', 'GET', 'HEAD', 'PROPFIND', 'PUT', 'POST', 'DELETE', 'MKCOL', 'MOVE', 'COPY'])
    def webdav_handler(path=''):
        try:
            # Authenticate user
            user_info = handler.authenticate_user()
            if not user_info:
                return Response(
                    response="Authentication required",
                    status=401,
                    headers={'WWW-Authenticate': 'Basic realm="WebDAV"'},
                    content_type='text/plain'
                )

            # Handle OPTIONS request
            if request.method == 'OPTIONS':
                return build_options_response()

            # Split path into components with safety checks
            path_parts = []
            if path:
                path_parts = [p for p in path.split('/') if p]  # 过滤空字符串

            logger.info(f"WebDAV request: {request.method} {request.path}, path_parts: {path_parts}")

            # 根据路径类型路由请求
            if not path_parts:
                # 根目录请求
                return handler.handle_root_request(request.method, user_info)
            elif path_parts[0].startswith('.'):
                # 特殊请求
                return handler._handle_special_request([''] + path_parts, request.method, user_info)
            else:
                # 标准请求
                return handler.handle_standard_request(path_parts, request.method, user_info)

        except Exception as e:
            logger.error(f"Unhandled error in webdav_handler: {e}", exc_info=True)
            return Response(
                response="Internal Server Error",
                status=500,
                content_type='text/plain'
            )

        # 增强的 WebDAV 发现页面

    @bp.route('/dav/index.html', methods=['GET'])
    def webdav_root():
        user_info = handler.authenticate_user()
        return handler._serve_user_web_interface(user_info=user_info)

    plugin = type('Plugin', (), {
        'name': 'Enhanced WebDAV Media Server',
        'version': '0.0.1',
        'description': '支持丰富功能的 WebDAV 媒体服务器，包含搜索、报表、缩略图等增强功能',
        'author': 'System',
        'blueprint': bp,
        'enabled': True,
        'protect': False,
        'handler': handler,
        'features': [
            'file_management',
            'advanced_search',
            'storage_analytics',
            'thumbnail_generation',
            'web_interface',
            'reports_generation'
        ]
    })()
    csrf.exempt(bp)
    return plugin
