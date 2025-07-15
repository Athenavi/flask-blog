import base64
import hashlib
import io
import json
import os
import re
import uuid
from datetime import timedelta
from pathlib import Path

import markdown
import qrcode
import requests
from PIL import Image
from bs4 import BeautifulSoup
from flask import Flask, render_template, redirect, request, url_for, jsonify, send_file, \
    make_response
from flask_caching import Cache
from flask_siwadoc import SiwaDoc
from jinja2 import select_autoescape, TemplateNotFound
from werkzeug.middleware.proxy_fix import ProxyFix

from src.blog.article.core.content import delete_article, save_article_changes, get_article_content_by_title_or_id
from src.blog.article.core.crud import get_articles_by_owner, delete_db_article, fetch_articles, \
    get_articles_recycle
from src.blog.article.metadata.handlers import get_article_metadata, upsert_article_metadata, upsert_article_content
from src.blog.article.security.password import update_article_password
from src.blog.comment import get_comments, create_comment, delete_comment
from src.blog.tag import update_article_tags, query_article_tags
from src.blueprints.auth import auth_bp
from src.blueprints.dashboard import dashboard_bp
from src.blueprints.media import create_media_blueprint
from src.blueprints.theme import create_theme_blueprint
from src.blueprints.website import create_website_blueprint
from src.config.general import get_general_config
from src.config.mail import zy_mail_conf
from src.config.theme import db_get_theme
from src.database import get_db_connection
from src.error import error
from src.media.permissions import verify_file_permissions
from src.media.processing import handle_cover_resize
from src.other.report import report_add
from src.other.search import search_handler
from src.upload.admin_upload import admin_upload_file
from src.upload.public_upload import handle_user_upload, save_bulk_article_db, process_single_upload, bulk_content_save
from src.user.authz.core import secret_key, get_username
from src.user.authz.decorators import jwt_required, admin_required, origin_required
from src.user.authz.login import tp_mail_login
from src.user.authz.password import update_password, validate_password
from src.user.entities import authorize_by_aid, get_user_sub_info, check_user_conflict, \
    db_save_avatar, db_save_bio, db_change_username, db_bind_email, authorize_by_aid_deleted
from src.user.profile.social import get_following_count, get_can_followed, get_follower_count
from src.utils.http.etag import generate_etag
from src.utils.security.ip_utils import get_client_ip, anonymize_ip_address
from src.utils.security.safe import run_security_checks, random_string, gen_qr_token
from src.utils.user_agent.parser import user_agent_info, sanitize_user_agent

global_encoding = 'utf-8'
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(f"running at: {base_dir}")
app = Flask(__name__, template_folder=f'{base_dir}/templates', static_folder=f'{base_dir}/static')
app.config['CACHE_TYPE'] = 'simple'
cache = Cache(app)

app.secret_key = secret_key

domain, sitename, beian, sys_version, api_host, app_id, app_key, DEFAULT_KEY = get_general_config()
print("sys information")
print("++++++++++==========================++++++++++")
print(
    f'\n domain: {domain} \n title: {sitename} \n beian: {beian} \n Version: {sys_version} \n 三方登录api: {api_host} \n')
print("++++++++++==========================++++++++++")

siwa = SiwaDoc(
    app,
    title=f'{sitename} API 文档',
    version=sys_version,
    description=f'系统版本: {sys_version} | 备案号: {beian}'
)

app.register_blueprint(auth_bp)
app.register_blueprint(create_website_blueprint(cache, domain, sitename))
app.register_blueprint(create_theme_blueprint(cache, domain, sys_version, base_dir))
app.register_blueprint(create_media_blueprint(cache, domain, base_dir))
app.register_blueprint(dashboard_bp)
app.config['SESSION_COOKIE_NAME'] = 'zb_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=48)
app.config['TEMP_FOLDER'] = 'temp/upload'
# 定义随机头像服务器
app.config['AVATAR_SERVER'] = "https://api.7trees.cn/avatar"
# 定义允许上传的文件类型/文件大小
app.config['ALLOWED_MIMES'] = [
    # 常见图片格式
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff',
    'image/webp',

    # 常见视频格式
    'video/mp4',
    'video/avi',
    'video/mpeg',
    'video/quicktime',
    'video/x-msvideo',
    'video/mp2t',
    'video/x-flv',
    'video/webm',
    'video/x-m4v',
    'video/3gpp',

    # 常见音频格式
    'audio/wav',
    'audio/mpeg',
    'audio/ogg',
    'audio/flac',
    'audio/aac',
    'audio/mp3'
]
app.config['UPLOAD_LIMIT'] = 60 * 1024 * 1024
# 定义文件最大可编辑的行数
app.config['MAX_LINE'] = 1000
# 定义rss和站点地图的缓存时间（单位:s）
app.config['MAX_CACHE_TIMESTAMP'] = 7200
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)  # 添加 ProxyFix 中间件

# 移除默认的日志处理程序
app.logger.handlers = []

# 配置 Jinja2 环境
app.jinja_env.autoescape = select_autoescape(['html', 'xml'])
app.jinja_env.add_extension('jinja2.ext.loopcontrols')

# 新增日志处理程序
app.logger.info("app.py logging已启动，并使用全局日志配置。")


@app.context_processor
def inject_variables():
    return dict(
        beian=beian,
        title=sitename,
        username=get_username(),
        domain=domain
    )


@app.route('/search', methods=['GET', 'POST'])
@jwt_required
def search(user_id):
    return search_handler(user_id, domain, global_encoding, app.config['MAX_CACHE_TIMESTAMP'])


import threading
import time
from collections import defaultdict
from functools import wraps
from flask import Response

# 全局计数器和锁
view_counts = defaultdict(int)
counter_lock = threading.Lock()
stop_event = threading.Event()
PERSIST_INTERVAL = 60  # 每60秒持久化一次


def persist_views():
    """定时将内存中的浏览量持久化到数据库"""
    while not stop_event.is_set():
        time.sleep(PERSIST_INTERVAL)

        try:
            # 创建计数器快照并清空
            with counter_lock:
                if not view_counts:
                    continue

                counts_snapshot = view_counts.copy()
                view_counts.clear()

            # 批量更新数据库
            update_success = False
            try:
                with get_db_connection() as db:
                    with db.cursor() as cursor:
                        for blog_id, count in counts_snapshot.items():
                            query = """
                                    UPDATE `articles`
                                    SET `views` = `views` + %s
                                    WHERE `article_id` = %s \
                                    """
                            cursor.execute(query, (count, blog_id))
                        db.commit()
                        update_success = True

            except Exception as db_error:
                app.logger.error(
                    f"Database update failed: {str(db_error)}",
                    exc_info=True
                )
                db.rollback()

            # 如果更新失败，恢复计数器
            if not update_success:
                with counter_lock:
                    for blog_id, count in counts_snapshot.items():
                        view_counts[blog_id] += count

        except Exception as e:
            app.logger.error(
                f"View persistence error: {str(e)}",
                exc_info=True
            )

    # 程序关闭时执行最后一次持久化
    final_persist()


def final_persist():
    """应用关闭时执行最终持久化"""
    with counter_lock:
        if not view_counts:
            return

        counts_snapshot = view_counts.copy()
        view_counts.clear()

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                for blog_id, count in counts_snapshot.items():
                    cursor.execute(
                        "UPDATE `articles` SET `views` = `views` + %s WHERE `article_id` = %s",
                        (count, blog_id)
                    )
                db.commit()
    except Exception as e:
        app.logger.error(
            f"Final persist failed: {str(e)}",
            exc_info=True
        )


# 启动持久化线程
persist_thread = threading.Thread(target=persist_views, daemon=True)
persist_thread.start()


@cache.memoize(7200)
def get_id_by_title(title):
    """根据标题获取文章ID（带缓存）"""
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = """
                        SELECT `article_id`
                        FROM `articles`
                        WHERE `title` = %s
                          AND `Hidden` = 0
                          AND `Status` = 'Published' \
                        """
                cursor.execute(query, (title,))
                result = cursor.fetchone()
                return result[0] if result else None
    except Exception as e:
        app.logger.error(
            f"Failed to get ID for title '{title}': {str(e)}",
            exc_info=True
        )
        return None


def view_filter(func):
    """浏览量计数装饰器（线程安全）"""

    @wraps(func)
    def wrapper(article_name, *args, **kwargs):
        blog_id = get_id_by_title(article_name)
        if not blog_id:
            return func(article_name, blog_id=None, *args, **kwargs)

        # 原子性增加计数
        with counter_lock:
            view_counts[blog_id] += 1

        return func(article_name, blog_id=blog_id, *args, **kwargs)

    return wrapper


def create_response(content, max_age, content_type='text/markdown'):
    """创建带缓存控制的响应"""
    response = Response(content, mimetype=content_type)
    response.headers['Cache-Control'] = f'public, max-age={max_age}'
    return response


@cache.memoize(300)  # 5分钟缓存
@app.route('/blog/api/<article_name>.md', methods=['GET'])
@origin_required
@view_filter
def get_article_content(article_name, blog_id=None):
    """
    获取文章内容和实时浏览量
    返回格式：
    <!-- 浏览量: 123 -->
    文章内容...
    """
    if not blog_id:
        return create_response('# 文章不可用', 30)

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                # 获取内容和当前浏览量
                query = """
                        SELECT c.content, a.views
                        FROM article_content c
                                 JOIN articles a ON a.article_id = c.aid
                        WHERE c.aid = %s \
                        """
                cursor.execute(query, (blog_id,))
                result = cursor.fetchone()

                if not result:
                    return create_response('# 页面不见了！', 120)

                content, views = result
                # 在内容前添加浏览量注释
                marked_content = f"<!-- 浏览量: {views} -->\n{content}"
                return create_response(marked_content, 300)

    except Exception as e:
        app.logger.error(
            f"Failed to fetch article {blog_id}: {str(e)}",
            exc_info=True
        )
        return create_response('# 服务暂时不可用', 30)


def clear_article_cache(article_name):
    """清除文章相关缓存"""
    blog_id = get_id_by_title(article_name)
    if blog_id:
        # 清除ID缓存
        cache.delete_memoized(get_id_by_title, article_name)
        # 清除内容缓存
        cache.delete_memoized(get_article_content, article_name)
        app.logger.info(f"Cleared cache for article: {article_name} (ID: {blog_id})")


@app.route('/confirm-password', methods=['GET', 'POST'])
@jwt_required
def confirm_password(user_id):
    return validate_password(user_id)


@app.route('/change-password', methods=['GET', 'POST'])
@jwt_required
def change_password(user_id):
    ip = get_client_ip(request)
    return update_password(user_id, ip)


@app.route('/api/theme/upload', methods=['POST'])
@siwa.doc(
    summary='上传主题文件',
    description='上传主题文件',
    tags=['主题']
)
@admin_required
def api_theme_upload(user_id):
    app.logger.info(f'{user_id} : Try Upload file')
    return admin_upload_file(app.config['UPLOAD_LIMIT'])


@app.route('/login/<provider>')
def cc_login(provider):
    if run_security_checks(api_host):
        pass
    else:
        return error(message="彩虹聚合登录API接口配置错误,您的程序无法使用第三方登录", status_code='503'), 503
    if provider not in ['qq', 'wx', 'alipay', 'sina', 'baidu', 'huawei', 'xiaomi', 'dingtalk', 'douyin']:
        return jsonify({'message': 'Invalid login provider'})

    redirect_uri = domain + "callback/" + provider

    api_safe_check = [api_host, app_id, app_key]
    if 'error' in api_safe_check:
        return error(message=api_safe_check, status_code='503'), 503
    login_url = f'{api_host}connect.php?act=login&appid={app_id}&appkey={app_key}&type={provider}&redirect_uri={redirect_uri}'
    response = requests.get(login_url)
    data = response.json()
    code = data.get('code')
    msg = data.get('msg')
    if code == 0:
        cc_url = data.get('url')
    else:
        return error(message=msg, status_code='503')

    return redirect(cc_url, 302)


@app.route('/callback/<provider>')
def callback(provider):
    if provider not in ['qq', 'wx', 'alipay', 'sina', 'baidu', 'huawei', 'xiaomi', 'dingtalk']:
        return jsonify({'message': 'Invalid login provider'})

    authorization_code = request.args.get('code')

    callback_url = f'{api_host}connect.php?act=callback&appid={app_id}&appkey={app_key}&type={provider}&code={authorization_code}'

    response = requests.get(callback_url)
    data = response.json()
    code = data.get('code')
    msg = data.get('msg')
    if code == 0:
        social_uid = data.get('social_uid')
        ip = get_client_ip(request)
        user_email = social_uid + f"@{provider}.com"
        return tp_mail_login(user_email, ip)

    return render_template('LoginRegister.html', error=msg)


@app.route('/favicon.ico', methods=['GET'])
def favicon():
    return send_file('../static/favicon.ico', mimetype='image/png', max_age=3600)


@cache.memoize(180)
@app.route('/blog/<title>', methods=['GET', 'POST'])
def blog_detail(title):
    if request.method == 'POST':
        query = """
                SELECT *
                FROM `articles`
                WHERE `Hidden` = 0
                  AND `Status` = 'Published'
                  AND `title` = %s
                ORDER BY `article_id` DESC
                LIMIT 1;
                """
        try:
            with get_db_connection() as db:
                with db.cursor() as cursor:
                    cursor.execute(query, (title,))
                    result = cursor.fetchone()
                    if result:
                        return jsonify(result)
                    else:
                        return jsonify({"error": "Article not found"}), 404
        except Exception as e:
            app.logger.error(e)
            return jsonify({"error": "Internal server error"}), 500

    # 处理GET请求
    try:
        aid, article_tags = query_article_tags(title)
        response = make_response(render_template(
            'zyDetail.html',
            article_content=1,
            aid=aid,
            articleName=title,
            domain=domain,
            url_for=url_for,
            article_tags=article_tags
        ))
        response.cache_control.max_age = 180
        return response

    except FileNotFoundError:
        return error(message="页面不见了", status_code=404)


@cache.memoize(180)
@app.route('/blog/<title>/images/<file_name>', methods=['GET'])
def blog_file(title, file_name):
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                # 1. 通过文章标题获取用户ID（元组索引访问）
                cursor.execute(
                    "SELECT user_id FROM articles WHERE title = %s LIMIT 1",
                    (title,)
                )
                article = cursor.fetchone()
                if not article or not article[0]:  # 使用索引[0]访问user_id
                    return jsonify({"error": "Article not found"}), 404

                # 2. 通过用户ID+文件名获取hash（元组索引访问）
                cursor.execute(
                    """SELECT hash
                       FROM media
                       WHERE user_id = %s
                         AND original_filename = %s
                       ORDER BY id DESC
                       LIMIT 1""",
                    (article[0], file_name)  # 使用article[0]
                )
                media = cursor.fetchone()
                if not media:
                    return jsonify({"error": "File not found"}), 404

                # 3. 通过hash获取文件路径（元组索引访问）
                cursor.execute(
                    "SELECT storage_path, mime_type FROM file_hashes WHERE hash = %s LIMIT 1",
                    (media[0],)  # 使用media[0]
                )
                file_record = cursor.fetchone()
                if not file_record:
                    return jsonify({"error": "File path not found"}), 404

                file_path = Path(base_dir) / file_record[0]
                return send_file(file_path, mimetype=file_record[1], max_age=7200)  # mime_type在索引1

    except Exception as e:
        app.logger.error(e)
        return jsonify({"error": "Internal server error"}), 500


@app.route('/preview', methods=['GET'])
@jwt_required
def sys_out_prev_page(user_id):
    user = request.args.get('user')
    file_name = request.args.get('file_name')
    prev_file_path = os.path.join(base_dir, 'media', str(user), file_name)
    if not os.path.exists(prev_file_path):
        return error(message=f'{file_name}不存在', status_code=404)
    else:
        app.logger.info(f'{user_id} preview: {file_name}')
        return render_template('zyDetail.html', article_content=1,
                               articleName=f"prev_{file_name}", domain=domain,
                               url_for=url_for, article_Surl='-')


# @app.route('/api/mail')
# @jwt_required
def api_mail(user_id, body_content):
    from src.notification import send_email
    subject = f'{sitename} - 通知邮件'

    smtp_server, stmp_port, sender_email, password = zy_mail_conf()
    receiver_email = sender_email
    body = body_content + "\n\n\n此邮件为系统自动发送，请勿回复。"
    send_email(sender_email, password, receiver_email, smtp_server, int(stmp_port), subject=subject,
               body=body)
    app.logger.info(f'{user_id} sendMail')
    return True


from functools import lru_cache
from threading import Lock

# 用线程锁保证缓存操作的原子性
cache_lock = Lock()


# 自定义LRU缓存管理器
class FollowCache:
    def __init__(self, max_size=2048):
        self.max_size = max_size
        self.cache = {}

    def get(self, user_id):
        with cache_lock:
            # 获取并更新最近使用
            if user_id in self.cache:
                value = self.cache.pop(user_id)
                self.cache[user_id] = value
                return value.copy()  # 返回副本防止外部修改
            return None

    def set(self, user_id, value):
        with cache_lock:
            if len(self.cache) >= self.max_size:
                # 移除最久未使用的条目
                self.cache.pop(next(iter(self.cache)))
            self.cache[user_id] = set(value) if value else set()

    def delete(self, user_id):
        with cache_lock:
            if user_id in self.cache:
                del self.cache[user_id]


follow_cache = FollowCache(max_size=2048)


@app.route('/api/follow', methods=['POST'])
@siwa.doc(
    summary='关注用户',
    description='关注用户',
    tags=['关注']
)
@jwt_required
def follow_user(user_id):
    current_user_id = user_id
    follow_id = request.args.get('fid')

    # 参数校验
    if not follow_id:
        return jsonify({'code': 'failed', 'message': '参数错误'}), 400

    try:
        current_user_id = int(current_user_id)
        follow_id = int(follow_id)
    except ValueError:
        return jsonify({'code': 'failed', 'message': '参数类型错误'}), 400

    # 检查自我关注
    if current_user_id == follow_id:
        return jsonify({'code': 'failed', 'message': '不能关注自己'}), 400

    db = None
    try:
        db = get_db_connection()
        cursor = db.cursor()

        # 检查是否已关注（缓存 -> 数据库）
        cached_follows = follow_cache.get(current_user_id)
        if cached_follows is not None:
            is_following = follow_id in cached_follows
        else:
            cursor.execute(
                "SELECT subscribed_user_id FROM user_subscriptions WHERE subscriber_id = %s",
                (current_user_id,)
            )
            follows = {row[0] for row in cursor.fetchall()}
            follow_cache.set(current_user_id, follows)
            is_following = follow_id in follows

        # 如果已存在关注关系
        if is_following:
            return jsonify({'code': 'success', 'message': '已关注'})

        # 执行关注操作
        cursor.execute(
            "INSERT INTO user_subscriptions (subscriber_id, subscribed_user_id) VALUES (%s, %s)",
            (current_user_id, follow_id)
        )
        db.commit()

        # 更新缓存
        if follow_cache.get(current_user_id) is not None:
            follow_cache.get(current_user_id).add(follow_id)
        else:
            follow_cache.delete(current_user_id)

        return jsonify({'code': 'success'})

    except Exception as e:
        app.logger.error(f"系统异常: {e}")
        if db: db.rollback()
        return jsonify({'code': 'failed', 'message': '服务异常'}), 500

    finally:
        if db: db.close()


@app.route('/api/unfollow', methods=['POST'])
@siwa.doc(
    summary='取关用户',
    tags=['关注']
)
@jwt_required
def unfollow_user(user_id):
    unfollow_id = request.args.get('fid')

    if not unfollow_id:
        return jsonify({'code': 'failed', 'message': '参数错误'})

    try:
        user_id = int(user_id)
        unfollow_id = int(unfollow_id)
    except ValueError as e:
        app.logger.error(f"ID类型转换失败: {e}")
        return jsonify({'code': 'failed', 'message': '非法用户ID'})

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                delete_query = """
                               DELETE \
                               FROM user_subscriptions
                               WHERE subscriber_id = %s \
                                 AND subscribed_user_id = %s \
                               """
                cursor.execute(delete_query, (user_id, unfollow_id))
                affected_rows = cursor.rowcount  # 正确获取影响行数
                db.commit()

                if affected_rows > 0:
                    # 更新缓存
                    cached_data = follow_cache.get(user_id)
                    if cached_data is not None:
                        try:
                            cached_data.remove(unfollow_id)  # 使用remove确保数据一致性
                            follow_cache.set(user_id, cached_data)
                        except KeyError:
                            pass
                    else:
                        follow_cache.delete(user_id)

                    return jsonify({'code': 'success', 'message': '取关成功'})
                else:
                    return jsonify({'code': 'failed', 'message': '未找到关注关系'})

    except Exception as e:
        db.rollback()
        app.logger.error(f"取关操作失败: {e}, 用户: {user_id}, 目标: {unfollow_id}")
        return jsonify({'code': 'failed', 'message': '服务器错误'})


@app.route("/qrlogin")
def qrlogin():
    ct = str(int(time.time()))
    user_agent = sanitize_user_agent(request.headers.get('User-Agent'))
    token = gen_qr_token(user_agent, ct, sys_version, global_encoding)
    token_expire = str(int(time.time() + 180))
    qr_data = f"{domain}api/phone/scan?login_token={token}"

    # 生成二维码
    qr_img = qrcode.make(qr_data)
    buffered = io.BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode(global_encoding)

    # 存储二维码状态（可以根据需要扩展）
    token_json = {'status': 'pending', 'created_at': ct, 'expire_at': token_expire}
    cache.set(f"QR-token_{token}", token_json, timeout=200)

    return jsonify({
        'qr_code': f"data:image/png;base64,{qr_code_base64}",
        'token': token,
        'expire': token_expire
    })


@app.route("/checkQRLogin")
def check_qr_login():
    token = request.args.get('token')
    cache_qr_token = cache.get(f"QR-token_{token}")
    if cache_qr_token:
        expire_at = cache_qr_token['expire_at']
        if int(expire_at) > int(time.time()):
            cache_qr_allowed = cache.get(f"QR-allow_{token}")
            if token and cache_qr_allowed:
                # 扫码成功调用此接口
                token_expire = cache_qr_allowed['expire_at']
                if int(token_expire) > int(time.time()):
                    return jsonify(cache_qr_allowed)
                return None
            else:
                token_json = {'status': 'failed'}
                return jsonify(token_json)

        else:
            return jsonify({'status': 'pending'})
    else:
        return jsonify({'status': 'invalid_token'})


@app.route("/api/phone/scan")
@siwa.doc(
    summary='<UNK>',
    description='手机扫码登录',
    tags=['登录']
)
@jwt_required
def phone_scan(user_id):
    # 用户扫码调用此接口
    token = request.args.get('login_token')
    phone_token = request.cookies.get('jwt')
    refresh_token = request.cookies.get('refresh_token')
    if token:
        cache_qr_token = cache.get(f"QR-token_{token}")
        if cache_qr_token:
            ct = str(int(time.time()))
            token_expire = str(int(time.time() + 30))
            page_json = {'status': 'success', 'created_at': ct, 'expire_at': token_expire}
            cache.set(f"QR-token_{token}", page_json, timeout=60)
            allow_json = {'status': 'success', 'created_at': ct, 'expire_at': token_expire, 'token': phone_token,
                          'refresh_token': refresh_token}
            cache.set(f"QR-allow_{token}", allow_json, timeout=60)
            return render_template('inform.html', status_code=200, message='授权成功，请在30秒内完成登录')
        return None
    else:
        app.logger.info(f"Invalid token: {token} for user {user_id}")
        token_json = {'status': 'failed'}
        return jsonify(token_json)


@cache.memoize(timeout=300)
def api_view_content(article, auth_key):
    html_content = '<p>没有找到内容</p>'
    if auth_key != DEFAULT_KEY:
        return html_content
    articles_dir = os.path.join(base_dir, 'articles', article + ".md")
    try:
        with open(articles_dir, 'r', encoding=global_encoding) as file:
            content = file.read()
            html_content = markdown.markdown(content)
            return html_content
    finally:
        return html_content


@cache.cached(timeout=600, key_prefix='article_passwd')
def article_passwd(aid):
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            query = "SELECT `pass` FROM article_content WHERE aid = %s"
            cursor.execute(query, (int(aid),))
            result = cursor.fetchone()
            if result:
                return result[0]
    except ValueError as e:
        app.logger.error(f"Value error: {e}")
        pass
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        pass
    finally:
        db.close()


@app.route('/api/article/unlock', methods=['GET', 'POST'])
@siwa.doc(
    summary='文章解锁',
    description='文章解锁',
    tags=['文章']
)
def api_article_unlock():
    try:
        aid = int(request.args.get('aid'))
    except (TypeError, ValueError):
        return jsonify({"message": "Invalid Article ID"}), 400

    entered_password = request.args.get('passwd')
    temp_url = ''
    view_uuid = random_string(16)

    response_data = {
        'aid': aid,
        'temp_url': temp_url,
    }

    # 验证密码长度
    if len(entered_password) != 4:
        return jsonify({"message": "Invalid Password"}), 400

    passwd = article_passwd(aid) or None
    # print(passwd)

    if passwd is None:
        return jsonify({"message": "Authentication failed"}), 401

    if entered_password == passwd:
        cache.set(f"temp-url_{view_uuid}", aid, timeout=900)
        temp_url = f'{domain}tmpView?url={view_uuid}'
        response_data['temp_url'] = temp_url
        return jsonify(response_data), 200
    else:
        referrer = request.referrer
        app.logger.error(f"{referrer} Failed access attempt {view_uuid}")
        return jsonify({"message": "Authentication failed"}), 401


@app.route('/tmpView', methods=['GET', 'POST'])
def temp_view():
    url = request.args.get('url')
    if url is None:
        return jsonify({"message": "Missing URL parameter"}), 400

    aid = cache.get(f"temp-url_{url}")

    if aid:
        content = '<p>无法加载文章内容</p>'
        db = get_db_connection()

        try:
            with db.cursor() as cursor:
                query = "SELECT `Title` FROM articles WHERE article_id = %s"
                cursor.execute(query, (int(aid),))
                result = cursor.fetchone()
                if result:
                    a_title = result[0]

                    content = api_view_content(a_title, DEFAULT_KEY)
        except ValueError as e:
            app.logger.error(f"Value error: {e}")
            return jsonify({"message": "Invalid article_id"}), 400
        except Exception as e:
            app.logger.error(f"Unexpected error: {e}")
            return jsonify({"message": "Internal server error"}), 500

        finally:
            cursor.close()
            db.close()
            referrer = request.referrer
            app.logger.info(f"Request from {referrer} with url {url}")
            return content
    else:
        return jsonify({"message": "Temporary URL expired or invalid"}), 404


@app.route('/api/article/PW', methods=['POST'])
@siwa.doc(
    summary='更新文章密码',
    tags=['文章']
)
@jwt_required
def api_article_password(user_id):
    try:
        aid = int(request.args.get('aid'))
    except (TypeError, ValueError):
        return jsonify({"message": "无效的文章ID"}), 400

    if aid == cache.get(f"PWLock_{user_id}"):
        return jsonify({"message": "操作过于频繁"}), 400

    new_password = request.args.get('new-passwd')

    if len(new_password) != 4:
        return jsonify({"message": "无效的密码"}), 400

    auth = authorize_by_aid(aid, user_id)

    if auth:
        cache.set(f"PWLock_{user_id}", aid, timeout=30)
        result = update_article_password(aid, new_password)
        return jsonify({'aid': aid, 'changed': result}), 200
    else:
        return jsonify({"message": "身份验证失败"}), 401


@app.route('/api/comment', methods=['POST'])
@siwa.doc(
    summary='添加评论',
    tags=['评论']
)
@jwt_required
def api_comment(user_id):
    try:
        aid = int(request.json.get('aid'))
        pid = int(request.json.get('pid')) or 0
    except (TypeError, ValueError):
        return jsonify({"message": "Invalid Article ID"}), 400

    if aid == cache.get(f"CommentLock_{user_id}"):
        return jsonify({"message": "操作过于频繁"}), 400

    new_comment = request.json.get('new-comment')
    if not new_comment:
        return jsonify({"message": "评论内容不能为空"}), 400

    user_ip = get_client_ip(request) or ''
    masked_ip = ''
    if user_ip:
        masked_ip = anonymize_ip_address(user_ip)

    user_agent = request.headers.get('User-Agent') or ''
    user_agent = user_agent_info(user_agent)

    cache.set(f"CommentLock_{user_id}", aid, timeout=30)
    result = create_comment(aid, user_id, pid, new_comment, masked_ip, user_agent)

    if result:
        return jsonify({'aid': aid, 'changed': True}), 201
    else:
        return jsonify({"message": "评论失败"}), 500


@app.route("/Comment")
@jwt_required
def comment(user_id):
    aid = request.args.get('aid')
    if not aid:
        pass
    page = request.args.get('page', default=1, type=int)

    if page <= 0:
        page = 1

    comments, has_next_page, has_previous_page = get_comments(aid, page=page, per_page=30)
    return render_template('Comment.html', aid=aid, user_id=user_id, comments=comments,
                           has_next_page=has_next_page, has_previous_page=has_previous_page, current_page=page)


@app.route('/api/delete/<filename>', methods=['DELETE'])
@siwa.doc(
    summary='删除文件',
    description='删除文件',
    tags=['文件']
)
@jwt_required
def api_delete_file(user_id, filename):
    user_name = get_username()
    arg_type = request.args.get('type')
    if arg_type == 'article':
        db = get_db_connection()
        try:
            with db.cursor() as cursor:
                cursor.execute("DELETE FROM `articles` WHERE `Title` = %s AND `user_id` = %s", (filename, user_id))
                db.commit()
                article_path = os.path.join(base_dir, 'articles', f"{filename}.md")
                if os.path.exists(article_path):
                    os.remove(article_path)
                return jsonify({'Deleted': True}), 200
        except Exception as e:
            db.rollback()
            app.logger.error(f"Error deleting article {filename}: {str(e)}")
            return jsonify({'Deleted': False}), 500
        finally:
            db.close()
            return None

    file_path = os.path.join('media', user_name, filename)
    if verify_file_permissions(file_path, user_name):
        os.remove(file_path) if os.path.exists(file_path) else None
        return jsonify({'filename': filename, 'Deleted': True}), 201
    else:
        app.logger.info(f'Delete error for {filename} by user {user_id}')
        return jsonify({'filename': filename, 'Deleted': False}), 503


@app.route('/api/report', methods=['POST'])
@siwa.doc(
    summary='举报内容',
    description='举报内容',
    tags=['举报']
)
@jwt_required
def api_report(user_id):
    try:
        report_id = int(request.json.get('report-id'))
        report_type = request.json.get('report-type') or ''
        report_reason = request.json.get('report-reason') or ''
        reason = report_type + report_reason
    except (TypeError, ValueError):
        return jsonify({"message": "Invalid Report ID"}), 400

    if report_id == cache.get(f"reportLock{report_id}_{user_id}"):
        return jsonify({"message": "操作过于频繁"}), 400

    result = report_add(user_id, "Comment", report_id, reason)

    if result:
        cache.set(f"reportLock{report_id}_{user_id}", report_id, timeout=3600)
        return jsonify({'report-id': report_id, 'info': '举报已记录'}), 201
    else:
        return jsonify({"message": "举报失败"}), 500


@app.route('/api/comment', methods=['delete'])
@siwa.doc(
    description='删除评论',
    tags=['评论']
)
@jwt_required
def api_delete_comment(user_id):
    try:
        comment_id = int(request.json.get('comment_id'))
    except (TypeError, ValueError):
        return jsonify({"message": "Invalid Comment ID"}), 400

    if comment_id == cache.get(f"deleteCommentLock_{user_id}"):
        return jsonify({"message": "操作过于频繁"}), 400

    result = delete_comment(user_id, comment_id)

    if result:
        cache.set(f"deleteCommentLock_{user_id}", comment_id, timeout=15)
        return jsonify({"message": "删除成功"}), 201
    else:
        return jsonify({"message": "操作失败"}), 500


@app.template_filter('fromjson')
def json_filter(value):
    """将 JSON 字符串解析为 Python 对象"""
    # 如果已经是字典直接返回
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        # print(f"Unexpected type for value: {type(value)}. Expected a string.")
        return None

    try:
        result = json.loads(value)
        return result
    except (ValueError, TypeError) as e:
        app.logger.error(f"Error parsing JSON: {e}, Value: {value}")
        return None


@app.template_filter('string.split')
def string_split(value, delimiter=','):
    """
    在模板中对字符串进行分割
    :param value: 要分割的字符串
    :param delimiter: 分割符，默认为逗号
    :return: 分割后的列表
    """
    if not isinstance(value, str):
        app.logger.error(f"Unexpected type for value: {type(value)}. Expected a string.")
        return []

    try:
        result = value.split(delimiter)
        return result
    except Exception as e:
        app.logger.error(f"Error splitting string: {e}, Value: {value}")
        return []


@app.template_filter('Author')
@lru_cache(maxsize=128)  # 设置缓存大小为128
def article_author(user_id):
    """通过 user_id 搜索作者名称"""
    author_name = '未知作者'
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute("SELECT `username` FROM `users` WHERE `id` = %s", (user_id,))
                result = cursor.fetchone()
                if result:
                    author_name = result[0]
    except (ValueError, TypeError) as e:
        app.logger.error(f"Error getting author name for user_id {user_id}: {e}")
    finally:
        return author_name


@cache.memoize(120)
@app.route('/api/user/avatar', methods=['GET'])
@siwa.doc(
    description='获取用户头像',
    tags=['用户']
)
def api_user_avatar(user_identifier=None, identifier_type='id'):
    user_id = request.args.get('id')
    if user_id is not None:
        user_identifier = int(user_id)
        identifier_type = 'id'
    avatar_url = app.config['AVATAR_SERVER']  # 默认头像服务器地址
    if not user_identifier:
        return avatar_url
    query_map = {
        'id': "select profile_picture from users where id = %s",
        'username': "select profile_picture from users where username = %s"
    }

    if identifier_type not in query_map:
        raise ValueError("identifier_type must be 'id' or 'username'")

    db = None
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            cursor.execute(query_map[identifier_type], (user_identifier,))
            result = cursor.fetchone()
            if result and result[0]:
                avatar_url = f"{domain}api/avatar/{result[0]}.webp"
    except Exception as e:
        app.logger.error(f"Error getting avatar for {user_identifier} with type {identifier_type}: {e}")
    finally:
        if db is not None:
            db.close()
    return avatar_url


@app.route('/api/avatar/<avatar_uuid>.webp', methods=['GET'])
def api_avatar_image(avatar_uuid):
    return send_file(f'{base_dir}/avatar/{avatar_uuid}.webp', mimetype='image/webp')


@app.route('/api/edit/<int:aid>', methods=['POST', 'PUT'])
@siwa.doc(
    summary='编辑文章',
    description='编辑文章',
    tags=['文章']
)
@jwt_required
def api_edit(user_id, aid):
    a_name = request.form.get('title') or None
    auth = authorize_by_aid(aid, user_id)
    if auth is False:
        return jsonify({'show_edit_code': 'failed'}), 403
    try:
        content = request.form.get('content') or ''
        status = request.form.get('status') or 'Draft'
        excerpt = request.form.get('excerpt')[:145] or ''
        hidden_status = request.form.get('hiddenStatus') or 0
        cover_image = request.files.get('coverImage') or None
        cover_image_path = 'cover'
        if status == 'Deleted':
            if delete_article(a_name, app.config['TEMP_FOLDER']):
                return delete_db_article(user_id, aid)
        if cover_image:
            # 保存封面图片
            cover_image_path = os.path.join('cover', f"{aid}.png")
            os.makedirs(os.path.dirname(cover_image_path), exist_ok=True)
            with open(cover_image_path, 'wb') as f:
                cover_image.save(f)
        if save_article_changes(aid, int(hidden_status), status, cover_image_path, excerpt) and zy_save_edit(aid,
                                                                                                             content,
                                                                                                             a_name):
            return jsonify({'show_edit_code': 'success'}), 200
        return None
    except Exception as e:
        app.logger.error(f"保存文章 article id: {aid} 时出错: {e} by user {user_id} ")
        return jsonify({'show_edit_code': 'failed'}), 500


def zy_save_edit(aid, content, a_name):
    if content is None:
        raise ValueError("Content cannot be None")
    if a_name is None or a_name.strip() == "":
        raise ValueError("Article name cannot be None or empty")
    current_content_hash = hashlib.md5(content.encode(global_encoding)).hexdigest()

    # 从缓存中获取之前的哈希值
    previous_content_hash = cache.get(f"{aid}_lasted_hash")

    # 检查内容是否与上一次提交相同
    if current_content_hash == previous_content_hash:
        return True

    try:
        # 更新文章内容
        with get_db_connection() as db:
            with db.cursor() as cursor:
                cursor.execute("UPDATE `article_content` SET `Content` = %s WHERE `aid` = %s", (content, aid))
                db.commit()
    except Exception as e:
        app.logger.error(f"Error updating article content for article id {aid}: {e}")
        return False
    # 更新缓存中的哈希值
    cache.set(f"{aid}_lasted_hash", current_content_hash, timeout=28800)
    return True


@app.route('/api/edit/tag/<int:aid>', methods=['PUT'])
@siwa.doc(
    summary='更新文章标签',
    description='更新文章标签',
    tags=['文章']
)
@jwt_required
def api_update_article_tags(user_id, aid):
    tags_input = request.get_json().get('tags')

    # 如果 tags_input 不是字符串，尝试将其转换为字符串
    if not isinstance(tags_input, str):
        tags_input = str(tags_input)

    tags_input = tags_input.replace("，", ",")
    tags_list = [
        tag.strip() for tag in re.split(",", tags_input, maxsplit=4) if len(tag.strip()) <= 10
    ]
    current_tag_hash = hashlib.md5(tags_input.encode(global_encoding)).hexdigest()
    previous_content_hash = cache.get(f"{aid}:tag_hash")
    # 检查内容是否与上一次提交相同
    if current_tag_hash == previous_content_hash:
        return jsonify({'show_edit': 'success'})
    # 更新缓存中的标签哈希值
    cache.set(f"{aid}:tag_hash", current_tag_hash, timeout=28800)
    # 写入更新后的标签到数据库
    auth = authorize_by_aid(aid, user_id)
    if auth is False:
        return jsonify({'show_edit': 'failed'}), 403
    update_article_tags(aid, tags_list)
    return jsonify({'show_edit': "success"})


@app.route('/api/cover/<cover_img>', methods=['GET'])
@app.route('/edit/cover/<cover_img>', methods=['GET'])
def api_cover(cover_img):
    require_format = request.args.get('format') or False
    if not require_format:
        cache.set(f"cover_{cover_img}", None)
        return send_file(f'../cover/{cover_img}', mimetype='image/png')
    cached_cover = cache.get(f"cover_{cover_img}")
    if cached_cover:
        return send_file(io.BytesIO(cached_cover), mimetype='image/webp', max_age=600)
    cover_path = f'cover/{cover_img}'
    if os.path.isfile(cover_path):
        with Image.open(cover_path) as img:
            cover_data = handle_cover_resize(img, 480, 270)
        cache.set(f"cover_{cover_img}", cover_data, timeout=28800)
        return send_file(io.BytesIO(cover_data), mimetype='image/webp', max_age=600)
    else:
        app.logger.warning("File not found, returning default image")
        return None


@app.route('/', methods=['GET'])
@app.route('/index.html', methods=['GET'])
@cache.cached(timeout=180, query_string=True)
def index_html():
    page = request.args.get('page', 1, type=int)
    page = max(page, 1)
    page_size = 45
    offset = (page - 1) * page_size

    query = """
            SELECT article_id,
                   Title,
                   user_id,
                   Views,
                   Likes,
                   cover_image,
                   article_type,
                   excerpt,
                   is_featured,
                   tags
            FROM `articles`
            WHERE `Hidden` = 0
              AND `Status` = 'Published'
            ORDER BY `article_id` DESC
            LIMIT %s OFFSET %s \
            """

    try:
        article_info, total_articles = fetch_articles(query, (page_size, offset))
        total_pages = (total_articles + page_size - 1) // page_size
    except Exception as e:
        return error(str(e), 500)
    html_content, etag = proces_page_data(total_articles, article_info, page, total_pages)
    # 设置响应头
    response = make_response(html_content)
    response.set_etag(etag)
    response.headers['Cache-Control'] = 'public, max-age=180'
    return response.make_conditional(request.environ)


def proces_page_data(total_articles, article_info, page, total_pages):
    current_theme = get_current_theme()
    template_rel_path = f'theme/{current_theme}/index.html' if current_theme != 'default' else 'index.html'

    try:
        loader = app.jinja_loader
        loader.get_source(app.jinja_env, template_rel_path)
    except TemplateNotFound:
        cache.set('display_theme', 'default')
        template_rel_path = 'index.html'
    html_content = render_template(template_rel_path, article_info=article_info, page=page, total_pages=total_pages)
    etag = generate_etag(total_articles, article_info, page, current_theme)
    return html_content, etag


@app.route('/tag/<tag_name>', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def tag_page(tag_name):
    if len(tag_name.encode(global_encoding)) > 10:
        return error("Tag 名称不能超过 10 字节。", status_code=400)

    page = request.args.get('page', 1, type=int)
    page = max(page, 1)
    page_size = 45
    offset = (page - 1) * page_size

    query = """
            SELECT article_id,
                   Title,
                   user_id,
                   Views,
                   Likes,
                   cover_image,
                   article_type,
                   excerpt,
                   is_featured,
                   tags
            FROM `articles`
            WHERE `Hidden` = 0
              AND `Status` = 'Published'
              AND `tags` LIKE %s
            ORDER BY `article_id` DESC
            LIMIT %s OFFSET %s \
            """

    try:
        article_info, total_articles = fetch_articles(query, ('%' + tag_name + '%', page_size, offset))
        total_pages = (total_articles + page_size - 1) // page_size
    except ValueError as e:
        app.logger.error(f"值错误: {e}")
        return error("参数传递错误。", status_code=400)
    except Exception as e:
        app.logger.error(f"未知错误: {e}")
        return error("获取文章时发生未知错误。", status_code=500)

    html_content, etag = proces_page_data(total_articles, article_info, page, total_pages)

    # 设置响应头
    response = make_response(html_content)
    response.set_etag(etag)
    response.headers['Cache-Control'] = 'public, max-age=180'
    return response


@app.route('/featured', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def featured_page():
    page = request.args.get('page', 1, type=int)
    page = max(page, 1)
    page_size = 45
    offset = (page - 1) * page_size

    query = """
            SELECT article_id,
                   Title,
                   user_id,
                   Views,
                   Likes,
                   cover_image,
                   article_type,
                   excerpt,
                   is_featured,
                   tags
            FROM `articles`
            WHERE `Hidden` = 0
              AND `Status` = 'Published'
              AND `is_featured` >= 127
            ORDER BY `article_id` DESC
            LIMIT %s OFFSET %s \
            """

    try:
        article_info, total_articles = fetch_articles(query, (page_size, offset))
        total_pages = (total_articles + page_size - 1) // page_size


    except ValueError as e:
        app.logger.error(f"值错误: {e}")
        return error("参数传递错误。", status_code=400)
    except Exception as e:
        app.logger.error(f"未知错误: {e}")
        return error("获取文章时发生未知错误。", status_code=500)
    html_content, etag = proces_page_data(total_articles, article_info, page, total_pages)
    response = make_response(html_content)
    response.set_etag(etag)
    response.headers['Cache-Control'] = 'public, max-age=180'
    return response


def validate_api_key(api_key):
    if api_key == DEFAULT_KEY:
        return True
    else:
        return False


@app.route('/upload/bulk', methods=['GET', 'POST'])
@jwt_required
def upload_bulk(user_id):
    upload_locked = cache.get(f"upload_locked_{user_id}") or False
    if request.method == 'POST':
        success_path_list = []
        success_file_list = []  # 存储文件名（不含扩展名）
        success_titles = []  # 存储用于查询的标题

        if upload_locked:
            return jsonify([{"filename": "无法上传", "status": "failed", "message": "上传已被锁定，请稍后再试"}]), 209

        try:
            api_key = request.form.get('API_KEY')
            if not validate_api_key(api_key):
                return jsonify([{"filename": "无法上传", "status": "failed", "message": "API_KEY 错误"}]), 403

            files = request.files.getlist('files')

            # 检查文件数量限制
            if len(files) > 50:
                return jsonify([{"filename": "无法上传", "status": "failed", "message": "最多只能上传50个文件"}]), 400

            upload_result = []
            cache.set(f"upload_locked_{user_id}", True, timeout=30)

            for file in files:
                current_file_result = {
                    "filename": file.filename,
                    "status": "",
                    "message": ""
                }

                # 原始文件名处理
                original_name = file.filename
                base_name = os.path.splitext(original_name)[0]  # 不含扩展名

                # 验证文件
                if not original_name.endswith('.md'):
                    current_file_result["status"] = "failed"
                    current_file_result["message"] = "仅支持.md文件"
                    upload_result.append(current_file_result)
                    continue

                if original_name.startswith('_'):
                    current_file_result["status"] = "failed"
                    current_file_result["message"] = "文件名不能以下划线开头"
                    upload_result.append(current_file_result)
                    continue

                if file.content_length > app.config['UPLOAD_LIMIT']:
                    current_file_result["status"] = "failed"
                    current_file_result[
                        "message"] = f"文件大小超过限制 ({app.config['UPLOAD_LIMIT'] // (1024 * 1024)}MB)"
                    upload_result.append(current_file_result)
                    continue

                # 创建上传目录
                upload_dir = "temp/upload"
                os.makedirs(upload_dir, exist_ok=True)
                file_path = os.path.join(upload_dir, original_name)

                # 检查文件是否已存在
                if os.path.exists(file_path):
                    current_file_result["status"] = "failed"
                    current_file_result["message"] = "存在同名文件"
                    upload_result.append(current_file_result)
                    continue

                # 保存文件
                file.save(file_path)

                # 保存到数据库 (articles表)
                if save_bulk_article_db(base_name, user_id):  # 使用不含扩展名的名称
                    current_file_result["status"] = "success"
                    current_file_result["message"] = "上传成功"

                    # 添加到成功列表
                    success_path_list.append(file_path)
                    success_file_list.append(base_name)  # 存储不含扩展名的名称
                    success_titles.append(base_name)  # 用于后续查询
                else:
                    current_file_result["status"] = "failed"
                    current_file_result["message"] = "数据库保存失败"

                upload_result.append(current_file_result)

            # 批量保存内容 (所有文件处理完成后)
            if success_path_list:
                if not bulk_content_save(success_path_list, success_titles):
                    app.logger.error("部分文件内容保存失败")
                    # 可选：标记失败的文件

            return jsonify({'upload_result': upload_result})

        except Exception as e:
            app.logger.error(f"批量上传错误: {str(e)}", exc_info=True)
            return jsonify({'message': '上传失败', 'error': str(e)}), 500

    tip_message = f"请不要上传超过 {app.config['UPLOAD_LIMIT'] / (1024 * 1024)}MB 的文件"
    return render_template('upload.html', upload_locked=upload_locked, message=tip_message)


@app.route('/new', methods=['GET', 'POST'])
@jwt_required
def create_article(user_id):
    upload_locked = cache.get(f"upload_locked_{user_id}") or False
    if request.method == 'POST':
        if upload_locked:
            return jsonify(
                {'message': '上传被锁定，请稍后再试。', 'upload_locked': upload_locked, 'Lock_countdown': -1}), 423

        file = request.files.get('file')
        if not file:
            return jsonify({'message': '未提供文件。', 'upload_locked': upload_locked, 'Lock_countdown': 15}), 400

        from src.upload.public_upload import upload_article
        error_message = upload_article(file, app.config['TEMP_FOLDER'], app.config['UPLOAD_LIMIT'])
        if error_message:
            app.logger.error(f"File upload error: {error_message[0]}")
            return jsonify({'message': error_message[0], 'upload_locked': upload_locked, 'Lock_countdown': 300}), 400

        file_name = os.path.splitext(file.filename)[0]
        aid = upsert_article_metadata(file_name, user_id)
        sav_content = upsert_article_content(aid=aid, file=file, upload_folder=app.config['TEMP_FOLDER'])
        if aid and sav_content:
            message = f'上传成功。但请您前往编辑页面进行编辑:<a href="/edit/{file_name}" target="_blank">编辑</a>'
            app.logger.info(f"Article info successfully saved for {file_name} by user:{user_id}.")
            cache.set(f'upload_locked_{user_id}', True, timeout=300)
            return jsonify({'message': message, 'upload_locked': True, 'Lock_countdown': 300}), 200
        else:
            message = f'上传中出现了问题，你可以检查是否可以编辑该文件。:<a href="/edit/{file_name}" target="_blank">编辑</a>'
            cache.set(f'upload_locked_{user_id}', True, timeout=120)
            app.logger.error("Failed to update article information in the database.")
            return jsonify({'message': message, 'upload_locked': True, 'Lock_countdown': 120}), 200
    tip_message = f"请不要上传超过 {app.config['UPLOAD_LIMIT'] / (1024 * 1024)}MB 的文件"
    return render_template('upload.html', message=tip_message, upload_locked=upload_locked)


@app.route('/profile', methods=['GET', 'POST'])
@jwt_required
def profile(user_id):
    avatar_url = api_user_avatar(user_id)
    user_bio = api_user_bio(user_id=user_id) or "这人很懒，什么也没留下"
    # 确保owner_articles是列表类型
    owner_articles = get_articles_by_owner(owner_id=user_id) or []
    user_follow = get_following_count(user_id=user_id) or 0
    follower = get_follower_count(user_id=user_id) or 0
    if not isinstance(owner_articles, list):
        owner_articles = list(owner_articles) if owner_articles is not None else []
    return render_template('Profile.html',
                           avatar_url=avatar_url,
                           userBio=user_bio,
                           following=user_follow,
                           follower=follower,
                           target_id=user_id,
                           user_id=user_id,
                           Articles=owner_articles,
                           recycle_bin=False)


@app.route('/profile/~recycle', methods=['GET', 'POST'])
@jwt_required
def recycle_bin(user_id):
    avatar_url = api_user_avatar(user_id)
    user_bio = api_user_bio(user_id) or "这人很懒，什么也没留下"
    recycle_articles = get_articles_recycle(user_id=user_id) or []
    user_follow = get_following_count(user_id=user_id) or 0
    follower = get_follower_count(user_id=user_id) or 0
    return render_template('Profile.html', url_for=url_for, avatar_url=avatar_url,
                           userBio=user_bio,
                           following=user_follow, follower=follower,
                           target_id=user_id, user_id=user_id,
                           Articles=recycle_articles, recycle_bin=True)


@app.route('/delete/blog/<int:aid>', methods=['DELETE'])
@jwt_required
def delete_blog(user_id, aid):
    auth = authorize_by_aid_deleted(aid, user_id)
    if auth is False:
        jsonify({"message": f"操作失败"}), 503
    try:
        with get_db_connection() as connection:
            with connection.cursor(dictionary=True) as cursor:
                query = "DELETE FROM `articles` WHERE `articles`.`article_id` = %s;"
                cursor.execute(query, (aid,))
                connection.commit()
        return jsonify({"message": "操作成功"}), 200
    except Exception as e:
        return jsonify({"message": f"操作失败{e}"}), 500


@app.route('/restore/blog/<int:aid>', methods=['POST'])
@jwt_required
def restore_blog(user_id, aid):
    auth = authorize_by_aid_deleted(aid, user_id)
    if auth is False:
        return jsonify({"message": f"操作失败"}), 503
    try:
        with get_db_connection() as connection:
            with connection.cursor(dictionary=True) as cursor:
                query = "UPDATE `articles` SET `status` = 'Draft' WHERE `articles`.`article_id` = %s;"
                cursor.execute(query, (aid,))
                connection.commit()
        return jsonify({"message": "操作成功"}), 200
    except Exception as e:
        return jsonify({"message": f"操作失败{e}"}), 500


@app.route('/fans/follow')
@jwt_required
def fans_follow(user_id):
    query = "SELECT `subscribed_user_id` FROM `user_subscriptions` WHERE `subscriber_id` = %s;"
    user_sub_info = get_user_sub_info(query, user_id)
    return render_template('fans.html', sub_info=user_sub_info, avatar_url=api_user_avatar(user_id),
                           userBio=api_user_bio(user_id), page_title="我的关注")


@app.route('/fans/fans')
@jwt_required
def fans_fans(user_id):
    query = "SELECT `subscriber_id` FROM `user_subscriptions` WHERE `subscribed_user_id` = %s"
    user_sub_info = get_user_sub_info(query, user_id)
    return render_template('fans.html', sub_info=user_sub_info, avatar_url=api_user_avatar(user_id),
                           userBio=api_user_bio(user_id), page_title="粉丝")


@app.route('/space/<target_id>', methods=['GET', 'POST'])
@jwt_required
def user_space(user_id, target_id):
    user_bio = api_user_bio(user_id=target_id)
    can_followed = 1
    if user_id != 0 and target_id != 0:
        can_followed = get_can_followed(user_id, target_id)
    owner_articles = get_articles_by_owner(owner_id=target_id) or []
    target_username = api_user_profile(user_id=target_id)[1] or "佚名"
    return render_template('Profile.html', url_for=url_for, avatar_url=api_user_avatar(target_id, 'id'),
                           target_username=target_username,
                           userBio=user_bio, follower=get_follower_count(user_id=target_id, subscribe_type='User'),
                           following=get_following_count(user_id=target_id, subscribe_type='User'),
                           target_id=target_id, user_id=user_id,
                           Articles=owner_articles, canFollowed=can_followed)


@app.route('/edit/blog/<int:aid>', methods=['GET', 'POST', 'PUT'])
@jwt_required
def markdown_editor(user_id, aid):
    auth = authorize_by_aid(aid, user_id)
    if auth:
        all_info = get_article_metadata(aid)
        if request.method == 'GET':
            edit_html, *_ = get_article_content_by_title_or_id(identifier=aid, is_title=False, limit=9999)
            # print(edit_html)
            return render_template('editor.html', edit_html=edit_html, aid=aid,
                                   user_id=user_id, coverImage=f"/api/cover/{aid}.png",
                                   all_info=all_info)
        else:
            return render_template('editor.html')

    else:
        return error(message='您没有权限', status_code=503)


@app.route('/setting/profiles', methods=['GET'])
@jwt_required
def setting_profiles(user_id):
    user_info = api_user_profile(user_id=user_id)
    if user_info is None:
        # 处理未找到用户信息的情况
        return "用户信息未找到", 404
    avatar_url = user_info[5] if len(user_info) > 5 and user_info[5] else app.config['AVATAR_SERVER']
    bio = user_info[6] if len(user_info) > 6 and user_info[6] else "这人很懒，什么也没留下"
    user_name = user_info[1] if len(user_info) > 1 else "匿名用户"
    user_email = user_info[2] if len(user_info) > 2 else "未绑定邮箱"

    return render_template(
        'setting.html',
        avatar_url=avatar_url,
        username=user_name,
        limit_username_lock=cache.get(f'limit_username_lock_{user_id}'),
        Bio=bio,
        userEmail=user_email,
    )


@app.route('/setting/profiles', methods=['PUT'])
@jwt_required
def change_profiles(user_id):
    change_type = request.args.get('change_type')
    if not change_type:
        return jsonify({'error': 'Change type is required'}), 400
    if change_type not in ['avatar', 'username', 'email', 'password', 'bio']:
        return jsonify({'error': 'Invalid change type'}), 400
    cache.delete_memoized(api_user_profile, user_id=user_id)
    if change_type == 'avatar':
        if 'avatar' not in request.files:
            return jsonify({'error': 'Avatar is required'}), 400
        avatar_file = request.files['avatar']
        if avatar_file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # 生成UUID
        avatar_uuid = uuid.uuid4()
        save_path = Path('avatar') / f'{avatar_uuid}.webp'

        # 确保目录存在
        save_path.parent.mkdir(parents=True, exist_ok=True)

        # 使用with语句保存文件
        with save_path.open('wb') as avatar_path:
            avatar_file.save(avatar_path)
            db_save_avatar(user_id, str(avatar_uuid))

        return jsonify({'message': 'Avatar updated successfully', 'avatar_id': str(avatar_uuid)}), 200
    if change_type == 'bio':
        bio = request.json.get('bio')
        db_save_bio(user_id, bio)
        return jsonify({'message': 'Bio updated successfully'}), 200
    if change_type == 'username':
        limit_username_lock = cache.get(f'limit_username_lock_{user_id}')
        if limit_username_lock:
            return jsonify({'error': 'Cannot change username more than once a week'}), 400
        username = request.json.get('username')
        if not username:
            return jsonify({'error': 'Username is required'}), 400
        if not re.match(r'^[a-zA-Z0-9_]{4,16}$', username):
            return jsonify({'error': 'Username should be 4-16 characters, letters, numbers or underscores'}), 400
        if check_user_conflict(zone='username', value=username):
            return jsonify({'error': 'Username already exists'}), 400
        db_change_username(user_id, new_username=username)
        cache.set(f'limit_username_lock_{user_id}', True, timeout=604800)
        return jsonify({'message': 'Username updated successfully'}), 200
    if change_type == 'email':
        email = request.json.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'error': 'Invalid email format'}), 400
        if check_user_conflict(zone='email', value=email):
            return jsonify({'error': 'Email already exists'}), 400
        request_email_change(user_id, email)
        return jsonify({'message': 'Email updated successfully'}), 200

    return None


def request_email_change(user_id, new_email):
    # 生成唯一令牌
    token = str(uuid.uuid4())
    temp_email_value = {
        'token': token,
        'new_email': new_email
    }

    cache.set(f"temp_email_{user_id}", temp_email_value, timeout=600)

    # 生成临时访问链接 (实际应用中应通过邮件发送)
    temp_link = f'{domain}api/change-email/confirm/{token}'
    if api_mail(user_id=user_id,
                body_content=f'您可以通过点击如下的链接来完成邮箱更新\n\n{temp_link}\n\n如果不是您发起的请求，请忽略该邮件'):
        print(temp_link)


# 验证并执行换绑的路由
@app.route('/api/change-email/confirm/<token>', methods=['GET'])
@jwt_required
def confirm_email_change(user_id, token):
    new_email = cache.get(f"temp_email_{user_id}").get('new_email')
    token_value = cache.get(f"temp_email_{user_id}").get('token')

    # 验证令牌匹配
    if token != token_value:
        return jsonify({"error": "Invalid verification data"}), 400

    db_bind_email(user_id, new_email)
    cache.delete_memoized(api_user_profile, user_id=user_id)

    return jsonify({
        "message": "Email updated successfully",
        "new_email": new_email
    }), 200


@cache.cached(timeout=2 * 60, key_prefix='current_theme')
@app.route('/api/theme', methods=['GET'])
@siwa.doc(
    summary='获取当前主题',
    tags=['主题'],
)
def get_current_theme():
    return db_get_theme()


@app.route("/@<user_name>")
def user_diy_space(user_name):
    @cache.cached(timeout=300, key_prefix=f'current_{user_name}')
    def _user_diy_space():
        user_path = Path(base_dir) / 'media' / user_name / 'index.html'
        if user_path.exists():
            with user_path.open('r', encoding=global_encoding) as f:
                return f.read()
        else:
            return "用户主页未找到", 404

    return _user_diy_space()


@app.route('/diy/space', methods=['GET'])
@jwt_required
def diy_space(user_id):
    avatar_url = api_user_avatar(user_id)
    profiles = api_user_profile(user_id=user_id)
    user_bio = profiles[6] or "这人很懒，什么也没留下"
    return render_template('diy_space.html', user_id=user_id, avatar_url=avatar_url,
                           profiles=profiles, userBio=user_bio)


@app.route("/diy/space", methods=['PUT'])
@jwt_required
def diy_space_upload(user_id):
    # 验证身份
    user_name = get_username()
    index_data = request.get_json()
    if not index_data or 'html' not in index_data:
        return jsonify({'error': '缺少 HTML 内容'}), 400
    html_content = index_data['html']
    soup = BeautifulSoup(html_content, 'html.parser')
    # for tag in soup.find_all(['script', 'iframe', 'form']):
    #    tag.decompose()
    tailwind_css = soup.new_tag(
        'link',
        rel='stylesheet',
        href='/static/css/tailwind.min.css'
    )
    if soup.head:
        soup.head.append(tailwind_css)
    else:
        head = soup.new_tag('head')
        head.append(tailwind_css)
        if soup.html:
            soup.html.insert(0, head)
        else:
            # 重建完整 HTML 结构
            html = soup.new_tag('html')
            html.append(head)
            body = soup.new_tag('body')
            html.append(body)
            soup.append(html)
    try:
        user_dir = Path(base_dir) / 'media' / user_name
        user_dir.mkdir(parents=True, exist_ok=True)
        index_path = user_dir / 'index.html'
        index_path.write_text(str(soup), encoding=global_encoding)
    except Exception as e:
        app.logger.error(f"Error in file upload: {e} by {user_id}")
        return jsonify({'error': f'保存失败: {str(e)}'}), 500

    return jsonify({'message': '主页更新成功'}), 200


@app.route('/dashboard/v2/user', methods=['GET', 'POST'])
@jwt_required
def dashboard_v2_user(user_id):
    if request.method == 'POST':
        try:
            with get_db_connection() as connection:
                with connection.cursor(dictionary=True) as cursor:
                    # 查询所有用户数据
                    json_data = []
                    query = "SELECT `id`, `username`, `updated_at`,`email`,`bio`, `profile_picture` FROM `users`"
                    cursor.execute(query)
                    user_data = cursor.fetchall()
                    if not user_data:
                        return jsonify({"message": "没有用户数据"}), 404
                    for user in user_data:
                        formatted_data = {
                            'id': user['id'],
                            'username': user['username'],
                            'email': user['email'],
                            'bio': user['bio'] if user['bio'] else '',
                            'profilePicture': user['profile_picture'] if user['profile_picture'] else None,
                            'lastActive': user['updated_at'].strftime('%Y-%m-%d') if user['updated_at'] else None
                        }
                        json_data.append(formatted_data)
            return jsonify(json_data), 200

        except Exception as e:
            app.logger.error(f"Error in searching users: {e} by {user_id}")
            referrer = request.referrer
            app.logger.info(f"{referrer}: queried all users")
            return jsonify({"message": "操作失败", "error": str(e)}), 500
    return render_template('dashboardV2/user.html', menu_active='user')


def query_dashboard_data(route, template, table_name, menu_active=None):
    @jwt_required
    def route_function(user_id):
        if request.method == 'GET':
            return render_template(template, menu_active=menu_active)
        try:
            with get_db_connection() as connection:
                with connection.cursor(dictionary=True) as cursor:
                    query = f"SELECT * FROM `{table_name}`"
                    cursor.execute(query)
                    data = cursor.fetchall()
                    if not data:
                        return jsonify({"message": f"没有{table_name}数据"}), 404
            return jsonify(data), 200
        except Exception as e:
            referrer = request.referrer
            app.logger.error(f"{referrer}.user_{user_id}: queried all {table_name}")
            return jsonify({"message": "操作失败", "error": str(e)}), 500

    # 为每个路由函数设置唯一的名称以避免端点冲突
    route_function.__name__ = f"route_function_{table_name}"
    app.route(route, methods=['GET', 'POST'])(route_function)
    return route_function


# 定义路由
dashboard_v2_blog = query_dashboard_data('/dashboard/v2/blog', 'dashboardV2/blog.html', 'articles', menu_active='blog')
dashboard_v2_comment = query_dashboard_data('/dashboard/v2/comment', 'dashboardV2/comment.html', 'comments',
                                            menu_active='comment')
dashboard_v2_media = query_dashboard_data('/dashboard/v2/media', 'dashboardV2/media.html', 'media', menu_active='media')
dashboard_v2_notification = query_dashboard_data('/dashboard/v2/notification', 'dashboardV2/notification.html',
                                                 'notifications', menu_active='notification')
dashboard_v2_report = query_dashboard_data('/dashboard/v2/report', 'dashboardV2/report.html', 'reports',
                                           menu_active='report')
dashboard_v2_url = query_dashboard_data('/dashboard/v2/url', 'dashboardV2/url.html', 'urls', menu_active='url')


@app.route('/api/user/bio/<int:user_id>', methods=['GET'])
@siwa.doc(
    description="获取用户的个人简介",
    tags=["用户"]
)
def api_user_bio(user_id):
    user_info = api_user_profile(user_id=user_id)
    bio = user_info[6] if len(user_info) > 6 and user_info[6] else ""
    return bio


@app.route('/api/user/profile/<int:user_id>', methods=['GET'])
@cache.memoize(timeout=300)
@siwa.doc(
    summary="获取用户的个人信息",
    description="获取用户的个人信息，包括用户名、邮箱、个人简介、头像等。",
    tags=["用户"]
)
def api_user_profile(user_id):
    if not user_id:
        return []
    info_list = []
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            query = "SELECT * FROM users WHERE `id` = %s;"
            params = (user_id,)
            cursor.execute(query, params)
            info = cursor.fetchone()

            if info:
                info_list = list(info)
                if len(info_list) > 2:
                    del info_list[2]
    except Exception as e:
        app.logger.error(f"An error occurred: {e}")
    finally:
        db.close()
        return info_list


@cache.cached(timeout=600, key_prefix='username_check')
def api_username_check(username):
    user_id = None
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            query = "SELECT `id` FROM `users` WHERE `username` = %s;"
            params = (username,)
            cursor.execute(query, params)
            result = cursor.fetchone()
            if result:
                user_id = str(result[0])
    except Exception as e:
        app.logger.error(f"An error occurred: {e}")
    finally:
        db.close()
        return user_id


@app.route('/message', methods=['GET'])
@jwt_required
def api_message(user_id):
    return render_template('Message.html')


@app.route('/message/read')
@jwt_required
def read_notification(user_id):
    nid = request.args.get('nid')
    is_notice_read = False
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                # 直接更新所读通知
                cursor.execute("""UPDATE notifications
                                  SET is_read = 1
                                  WHERE id = %s
                                    AND user_id = %s;""",
                               (nid, user_id))
                db.commit()
    except Exception as e:
        print(f"获取通知时发生错误: {e}")

    response = jsonify({"is_notice_read": is_notice_read})
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response


@app.route('/message/fetch', methods=['GET'])
@jwt_required
def fetch_message(user_id):
    messages = []
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            cursor.execute("""SELECT *
                              FROM notifications
                              WHERE user_id = %s;""",
                           (user_id,))
            messages = cursor.fetchall()
    except Exception as e:
        print(f"获取消息时发生错误: {e}")
    finally:
        db.close()
        return jsonify(messages)


@app.route('/message/read_all', methods=['POST'])
@jwt_required
def mark_all_as_read(user_id):
    success = False
    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                # 批量更新所有未读通知
                cursor.execute("""UPDATE notifications
                                  SET is_read = 1
                                  WHERE user_id = %s
                                    AND is_read = 0""",
                               (user_id,))
                db.commit()
    except Exception as e:
        print(f"批量更新已读状态失败: {e}")

    response = jsonify({"success": success, "updated_count": cursor.rowcount if success else 0})
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response


@app.route('/api/media/upload', methods=['POST'])
@siwa.doc(
    summary="上传文件",
    description="上传文件，返回外链 URL。",
    tags=["文件"]
)
@jwt_required
def upload_user_path(user_id):
    return handle_user_upload(user_id=user_id, allowed_size=app.config['UPLOAD_LIMIT'],
                              allowed_mimes=app.config['ALLOWED_MIMES'], check_existing=False)


def get_outer_url(file_hash):
    """
    根据文件哈希生成外链 URL
    """
    outer_url = domain + 'shared?data=' + file_hash
    # print(outer_url)
    return outer_url


@app.route('/api/upload/files', methods=['POST'])
@siwa.doc(
    summary="编辑时上传文件",
    description="上传文件，返回外链 URL。",
    tags=["文件"]
)
@jwt_required
def handle_file_upload(user_id):
    """处理文件上传（严格匹配 Vditor 格式）"""
    if 'file' not in request.files:
        return jsonify({
            "code": 400,
            "msg": "未上传文件",
            "data": {"errFiles": [], "succMap": {}}
        }), 400

    succ_map = {}
    err_files = []
    allowed_size = app.config['UPLOAD_LIMIT']
    allowed_mimes = app.config['ALLOWED_MIMES']

    try:
        with get_db_connection() as db:
            # 遍历所有上传的文件
            for f in request.files.getlist('file'):
                try:
                    _, file_hash = process_single_upload(f, user_id, allowed_size, allowed_mimes, db)
                    # 生成供外部访问的 URL
                    file_url = get_outer_url(file_hash)
                    succ_map[f.filename] = file_url
                except Exception as e:
                    err_files.append({
                        "name": f.filename,
                        "error": str(e)
                    })
            db.commit()
    except Exception as e:
        return jsonify({
            "code": 500,
            "msg": "服务器处理错误: " + str(e),
            "data": {"errFiles": err_files, "succMap": succ_map}
        }), 500

    response_code = 0 if succ_map else 500
    if succ_map and err_files:
        response_msg = "部分成功"
    elif succ_map:
        response_msg = "成功"
    else:
        response_msg = "失败"

    return jsonify({
        "code": response_code,
        "msg": response_msg,
        "data": {
            "errFiles": err_files,
            "succMap": succ_map
        }
    })


@app.route('/like', methods=['POST'])
def like():
    aid = request.args.get('aid')
    if not aid:
        return jsonify({'like_code': 'failed', 'message': "error"})

    cache_key = f"aid_{aid}_likes"

    # 修复：SimpleCache.get() 不接受默认值参数
    current_likes = cache.get(cache_key)
    if current_likes is None:
        current_likes = 0

    new_likes = current_likes + 1
    cache.set(cache_key, new_likes, timeout=None)

    if new_likes == 5:
        try:
            with get_db_connection() as db, db.cursor() as cursor:
                cursor.execute("UPDATE `articles` SET `Likes` = `Likes` + 5 WHERE `article_id` = %s;", (int(aid),))
                db.commit()
                cache.set(cache_key, 0, timeout=None)
                return jsonify({'like_code': 'success'})
        except Exception as e:
            return jsonify({'like_code': 'failed', 'message': str(e)})
    else:
        return jsonify({'like_code': 'success'})


@app.errorhandler(404)
def page_not_found(error_message):
    app.logger.error(error_message)
    return error(error_message, status_code=404)


@app.errorhandler(500)
def internal_server_error(error_message):
    app.logger.error(error_message)
    return error(error_message, status_code=500)


@app.route('/<path:undefined_path>')
def undefined_route(undefined_path):
    app.logger.error(undefined_path)
    return error("Not Found", status_code=404)


@app.errorhandler(Exception)
def handle_unexpected_error(error_message):
    app.logger.error(error_message)
    return error(error_message, status_code=500)


if __name__ == "__main__":
    app.run()
