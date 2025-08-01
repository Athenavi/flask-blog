import hashlib
import io
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PIL import Image
from flask import Flask, stream_with_context, redirect
from flask import render_template, request, url_for, jsonify, send_file, \
    make_response
from flask_caching import Cache
from flask_siwadoc import SiwaDoc
from jinja2 import select_autoescape, TemplateNotFound
from werkzeug.exceptions import NotFound
from werkzeug.middleware.proxy_fix import ProxyFix

from plugins.manager import PluginManager
from src.blog.article.core.content import delete_article, save_article_changes, get_article_content_by_title_or_id, \
    get_blog_temp_view
from src.blog.article.core.crud import get_articles_by_owner, delete_db_article, fetch_articles, \
    get_articles_recycle, post_blog_detail, blog_restore, blog_delete, get_aid_by_title, blog_update
from src.blog.article.metadata.handlers import get_article_metadata, upsert_article_metadata, upsert_article_content, \
    persist_views, view_counts
from src.blog.article.security.password import set_article_password, get_article_password
from src.blog.comment import get_comments, create_comment, delete_comment
from src.blog.tag import update_article_tags, query_article_tags
from src.blueprints.auth import auth_bp
from src.blueprints.dashboard import dashboard_bp
from src.blueprints.media import create_media_blueprint
from src.blueprints.theme import create_theme_blueprint
from src.blueprints.website import create_website_blueprint
from src.config.mail import get_mail_conf
from src.config.theme import db_get_theme
from src.database import get_db_connection
from src.error import error
from src.media.file import get_file, delete_file
from src.media.processing import handle_cover_resize
from src.notification import read_all_notifications, get_notifications, read_current_notification
from src.other.diy import diy_space_put
from src.other.report import report_add
from src.other.search import search_handler
from src.plugin import plugin_bp
from src.setting import AppConfig
from src.upload.admin_upload import admin_upload_file
from src.upload.public_upload import handle_user_upload, bulk_save_articles, save_bulk_content, \
    handle_editor_upload
from src.user.authz.cclogin import cc_login, callback
from src.user.authz.core import get_current_username
from src.user.authz.decorators import jwt_required, admin_required, origin_required
from src.user.authz.password import update_password, validate_password
from src.user.authz.qrlogin import qr_login
from src.user.entities import authorize_by_aid, get_user_sub_info, check_user_conflict, \
    change_username, bind_email, username_exists, get_avatar
from src.user.follow import unfollow_user, userFollow_lock, follow_user
from src.user.profile.edit import edit_profile
from src.user.profile.social import get_following_count, can_follow_user, get_follower_count, get_user_info, \
    get_user_name_by_id
from src.utils.http.etag import generate_etag
from src.utils.security.ip_utils import get_client_ip, anonymize_ip_address
from src.utils.security.safe import random_string
from src.utils.user_agent.parser import parse_user_agent

app = Flask(__name__, template_folder=f'{AppConfig.base_dir}/templates', static_folder=f'{AppConfig.base_dir}/static')
app.config.from_object(AppConfig)

# 初始化 Cache
cache = Cache(app)

# 打印运行信息
print(f"running at: {AppConfig.base_dir}")
print("sys information")
print("++++++++++==========================++++++++++")
print(
    f'\n domain: {AppConfig.domain} \n title: {AppConfig.sitename} \n beian: {AppConfig.beian} \n Version: {AppConfig.sys_version} \n 三方登录api: {AppConfig.api_host} \n')
print("++++++++++==========================++++++++++")

# 初始化 SiwaDoc
siwa = SiwaDoc(
    app,
    title=f'{AppConfig.sitename} API 文档',
    version=AppConfig.sys_version,
    description=f'系统版本: {AppConfig.sys_version} | 备案号: {AppConfig.beian}'
)

# 注册蓝图
app.register_blueprint(auth_bp)
app.register_blueprint(create_website_blueprint(cache, AppConfig.domain, AppConfig.sitename))
app.register_blueprint(create_theme_blueprint(cache, AppConfig.domain, AppConfig.sys_version, AppConfig.base_dir))
app.register_blueprint(create_media_blueprint(cache, AppConfig.domain, AppConfig.base_dir))
app.register_blueprint(dashboard_bp)
app.register_blueprint(plugin_bp)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)  # 添加 ProxyFix 中间件

# 初始化插件管理器
plugins_manager = PluginManager(app)
plugins_manager.load_plugins()
plugins_manager.register_blueprints()

# 移除默认的日志处理程序
app.logger.handlers = []

# 配置 Jinja2 环境
app.jinja_env.autoescape = select_autoescape(['html', 'xml'])
app.jinja_env.add_extension('jinja2.ext.loopcontrols')

# 新增日志处理程序
app.logger.info("app.py logging已启动，并使用全局日志配置。")

domain = AppConfig.domain
global_encoding = AppConfig.global_encoding
base_dir = AppConfig.base_dir


@app.context_processor
def inject_variables():
    return dict(
        beian=AppConfig.beian,
        title=AppConfig.sitename,
        username=get_current_username(),
        domain=domain
    )


@app.route('/search', methods=['GET', 'POST'])
@jwt_required
def search(user_id):
    return search_handler(user_id, domain, global_encoding, app.config['MAX_CACHE_TIMESTAMP'])


import threading
import time
from functools import wraps, lru_cache
from flask import Response

# 启动持久化线程
persist_thread = threading.Thread(target=persist_views, daemon=True)
persist_thread.start()


@cache.memoize(7200)
def get_aid(title):
    return get_aid_by_title(title)


def view_filter(func):
    """浏览量计数装饰器（线程安全）"""

    @wraps(func)
    def wrapper(article_name, *args, **kwargs):
        blog_id = get_aid(article_name)
        if not blog_id:
            return func(article_name, blog_id=None, *args, **kwargs)

        # 原子性增加计数
        with userFollow_lock:
            view_counts[blog_id] += 1

        return func(article_name, blog_id=blog_id, *args, **kwargs)

    return wrapper


def create_response(content, max_age, content_type='text/markdown'):
    """创建带缓存控制的响应"""
    response = Response(content, mimetype=content_type)
    response.headers['Cache-Control'] = f'public, max-age={max_age}'
    return response


@app.route('/confirm-password', methods=['GET', 'POST'])
@jwt_required
def confirm_password(user_id):
    if request.method == 'POST':
        if validate_password(user_id):
            cache.set(f"tmp-change-key_{user_id}", True, timeout=300)
            return redirect("/change-password")
    return render_template('Authentication.html', form='confirm')


@app.route('/change-password', methods=['GET', 'POST'])
@jwt_required
def change_password(user_id):
    if not cache.get(f"tmp-change-key_{user_id}"):
        return redirect('/confirm-password')
    if request.method == 'POST':
        ip = get_client_ip(request)
        new_pass = request.form.get('new_password')
        repeat_pass = request.form.get('confirm_password')
        if update_password(user_id, new_password=new_pass, confirm_password=repeat_pass, ip=ip):
            return render_template('inform.html', status_code='200', message='密码修改成功！')
        else:
            return render_template('Authentication.html', form='change')
    return render_template('Authentication.html', form='change')


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
def cc_login_route(provider):
    return cc_login(provider, domain=AppConfig.domain, api_host=AppConfig.api_host, app_id=AppConfig.app_id,
                    app_key=AppConfig.app_key)


@app.route('/callback/<provider>')
def callback_route(provider):
    return callback(provider=provider, request=request, api_host=AppConfig.api_host, app_id=AppConfig.app_id,
                    app_key=AppConfig.app_key)


@app.route('/favicon.ico', methods=['GET'])
def favicon():
    return send_file('../static/favicon.ico', mimetype='image/png', max_age=3600)


@cache.memoize(1800)
@origin_required
@app.route('/api/blog/<int:aid>', methods=['GET'])
def api_blog_content(aid):
    content, date = get_article_content_by_title_or_id(identifier=aid, is_title=False, limit=9999)

    # 生成安全的文件名
    safe_date = re.sub(r'[^\w\-.]', '_', str(date))
    filename = f"blog_{aid}_{safe_date}.md"

    # 创建生成器函数用于流式传输
    def generate():
        chunk_size = 4096
        for i in range(0, len(content), chunk_size):
            yield content[i:i + chunk_size]

    # 设置响应头
    headers = {
        "Content-Disposition": f"attachment; filename={filename}",
        "Content-Type": "text/markdown; charset=utf-8",

        # 缓存控制头
        "Cache-Control": "public, max-age=600",
        "Expires": (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "Pragma": "cache",
        "ETag": f'"{hash(content)}"'  # 内容哈希作为ETag
    }

    # 使用流式响应
    return Response(
        stream_with_context(generate()),
        headers=headers
    )


@cache.memoize(180)
@app.route('/blog/<title>', methods=['GET', 'POST'])
def blog_detail(title):
    if request.method == 'POST':
        return post_blog_detail(title)
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
    return get_file(base_dir, file_name, title)


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
    subject = f'{AppConfig.sitename} - 通知邮件'

    smtp_server, stmp_port, sender_email, password = get_mail_conf()
    receiver_email = sender_email
    body = body_content + "\n\n\n此邮件为系统自动发送，请勿回复。"
    send_email(sender_email, password, receiver_email, smtp_server, int(stmp_port), subject=subject,
               body=body)
    app.logger.info(f'{user_id} sendMail')
    return True


@app.route('/api/follow', methods=['POST'])
@siwa.doc(
    summary='关注用户',
    description='关注用户',
    tags=['关注']
)
@jwt_required
def follow_user_route(user_id):
    return follow_user(user_id)


@app.route('/api/unfollow', methods=['POST'])
@siwa.doc(
    summary='取关用户',
    tags=['关注']
)
@jwt_required
def unfollow_user_route(user_id):
    return unfollow_user(user_id)


@app.route("/qrlogin")
def qr_login_route():
    token_json, qr_code_base64, token_expire, token = qr_login(sys_version=AppConfig.sys_version,
                                                               global_encoding=global_encoding,
                                                               domain=domain)
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


@cache.cached(timeout=600, key_prefix='article_passwd')
def article_passwd(aid):
    return get_article_password(aid)


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

    if aid is None:
        return jsonify({"message": "Temporary URL expired or invalid"}), 404
    else:
        return get_blog_temp_view(aid)


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
    user_agent = parse_user_agent(user_agent)

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
    username = get_current_username()
    arg_type = request.args.get('type')
    return delete_file(arg_type, filename, user_id, username, base_dir)


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
    return get_user_name_by_id(user_id)


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
    avatar_url = get_avatar(domain, user_identifier=user_identifier, identifier_type=identifier_type)
    if avatar_url:
        return avatar_url
    else:
        avatar_url = app.config['AVATAR_SERVER']  # 默认头像服务器地址
        return avatar_url


@app.route('/api/avatar/<avatar_uuid>.webp', methods=['GET'])
def api_avatar_image(avatar_uuid):
    return send_file(f'{base_dir}/avatar/{avatar_uuid}.webp', mimetype='image/webp')


def zy_save_edit(aid, content):
    if content is None:
        raise ValueError("Content cannot be None")
    current_content_hash = hashlib.md5(content.encode(global_encoding)).hexdigest()

    # 从缓存中获取之前的哈希值
    previous_content_hash = cache.get(f"{aid}_lasted_hash")

    # 检查内容是否与上一次提交相同
    if current_content_hash == previous_content_hash:
        return True

    if blog_update(aid, content):
        # 更新缓存中的哈希值
        cache.set(f"{aid}_lasted_hash", current_content_hash, timeout=28800)
    return True


# 标签管理 API
@app.route('/api/edit/tag/<int:aid>', methods=['PUT'])
@siwa.doc(
    summary='更新文章标签',
    description='更新文章标签',
    tags=['文章']
)
@jwt_required
def api_update_article_tags(user_id, aid):
    try:
        # 从表单数据获取标签，并将中文逗号替换为英文逗号
        tags_str = request.form.get('tags', '').replace('，', ',')
        tag_list = [tag.strip() for tag in tags_str.split(',') if tag.strip()]

        # 清理标签：移除所有空格和尾部的‘x’
        tag_list = [tag.replace(' ', '') for tag in tag_list]

        # 去重标签
        tag_list = list(set(tag_list))

        # 验证标签数量
        if len(tag_list) > 10:
            return jsonify({
                'code': -1,
                'message': '标签数量不能超过10个'
            }), 400

        # 更新数据库
        update_article_tags(aid, tag_list)

        # 返回新的标签HTML片段
        tags_html = ''.join([f'<span class="tag-badge">{tag}</span>' for tag in tag_list])
        return tags_html
    except Exception as e:
        app.logger.error(f"更新标签失败: {str(e)}")
        return jsonify({
            'code': -1,
            'message': '服务器内部错误'
        }), 500


@app.route('/api/tags/suggest', methods=['GET'])
def suggest_tags():
    prefix = request.args.get('prefix', '')
    # 从数据库获取匹配的标签
    tags = [2025, 2026, 2027]
    return jsonify(tags)


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
    if api_key == AppConfig.DEFAULT_KEY:
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
                if bulk_save_articles(base_name, user_id):  # 使用不含扩展名的名称
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
                if not save_bulk_content(success_path_list, success_titles):
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
    return blog_delete(aid, user_id)


@app.route('/restore/blog/<int:aid>', methods=['POST'])
@jwt_required
def restore_blog(user_id, aid):
    return blog_restore(aid, user_id)


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
        can_followed = can_follow_user(user_id, target_id)
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
        change_username(user_id, new_username=username)
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
    else:
        return edit_profile(request, change_type, user_id)


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

    bind_email(user_id, new_email)
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
    return diy_space_put(base_dir=base_dir, user_name=get_current_username(), encoding=global_encoding)


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
    return get_user_info(user_id)


@cache.cached(timeout=600, key_prefix='username_check')
def api_username_check(username):
    return username_exists(username)


@app.route('/message', methods=['GET'])
@jwt_required
def api_message(user_id):
    return render_template('Message.html')


@app.route('/message/read')
@jwt_required
def read_notification(user_id):
    nid = request.args.get('nid')
    return read_current_notification(user_id, nid)


@app.route('/message/fetch', methods=['GET'])
@jwt_required
def fetch_message(user_id):
    return get_notifications(user_id)


@app.route('/message/read_all', methods=['POST'])
@jwt_required
def mark_all_as_read(user_id):
    return read_all_notifications(user_id)


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


@app.route('/api/upload/files', methods=['POST'])
@siwa.doc(
    summary="编辑时上传文件",
    description="上传文件，返回外链 URL。",
    tags=["文件"]
)
@jwt_required
def handle_file_upload(user_id):
    return handle_editor_upload(domain=domain, user_id=user_id, allowed_size=app.config['UPLOAD_LIMIT'],
                                allowed_mimes=app.config['ALLOWED_MIMES'])


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


@app.route('/api/article/password-form/<int:aid>', methods=['GET'])
@jwt_required
def get_password_form(user_id, aid):
    return '''
    <div id="password-modal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full">
        <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div class="mt-3 text-center">
                <h3 class="text-lg leading-6 font-medium text-gray-900">更改文章密码</h3>
                <div class="mt-2 px-7 py-3">
                    <p class="text-sm text-gray-500 mb-3">
                        请输入新的文章访问密码（至少4位，包含字母和数字）
                    </p>
                    <input type="password" id="new-password" name="new-password"
                           class="w-full px-3 py-2 border border-gray-300 rounded-md" 
                           placeholder="输入新密码">
                </div>
                <div class="flex justify-center gap-4 px-4 py-3">
                    <button id="cancel-password" 
                            class="px-4 py-2 bg-gray-200 text-gray-800 rounded-md hover:bg-gray-300"
                            onclick="document.getElementById('password-modal').remove()">
                        取消
                    </button>
                    <button id="confirm-password" 
                            hx-post="/api/article/password/''' + str(aid) + '''"
                            hx-include="#new-password"
                            hx-target="#password-modal"
                            hx-swap="innerHTML"
                            class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                        确认更改
                    </button>
                </div>
            </div>
        </div>
    </div>
    '''


# 密码更改 API
@app.route('/api/article/password/<int:aid>', methods=['POST'])
@jwt_required
def api_update_article_password(user_id, aid):
    try:
        new_password = request.form.get('new-password')

        # 验证密码格式
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d).{4,}$', new_password):
            return '''
            <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
                <div class="mt-3 text-center">
                    <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100">
                        <svg class="h-6 w-6 text-red-600" stroke="currentColor" fill="none" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </div>
                    <h3 class="text-lg leading-6 font-medium text-gray-900">密码格式错误</h3>
                    <div class="mt-2 px-7 py-3">
                        <p class="text-sm text-gray-500">
                            密码需要至少4位且包含字母和数字！
                        </p>
                    </div>
                    <div class="px-4 py-3">
                        <button onclick="document.getElementById('password-modal').remove()"
                                class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                            关闭
                        </button>
                    </div>
                </div>
            </div>
            '''

        # 更新密码
        set_article_password(aid, new_password)

        # 返回成功响应
        return '''
        <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                <svg class="h-6 w-6 text-green-600" stroke="currentColor" fill="none" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
            </div>
            <div class="mt-3 text-center">
                <h3 class="text-lg leading-6 font-medium text-gray-900">密码更新成功</h3>
                <div class="mt-2 px-7 py-3">
                    <p class="text-sm text-gray-500">
                        新密码将在10分钟内生效
                    </p>
                </div>
                <div class="px-4 py-3">
                    <button onclick="document.getElementById('password-modal').remove()"
                            class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                        关闭
                    </button>
                </div>
            </div>
        </div>
        '''
    except Exception as e:
        app.logger.error(f"更新密码失败: {str(e)}")
        return '''
        <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100">
                <svg class="h-6 w-6 text-red-600" stroke="currentColor" fill="none" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
            </div>
            <h3 class="text-lg leading-6 font-medium text-gray-900">操作失败</h3>
            <div class="mt-2 px-7 py-3">
                <p class="text-sm text-gray-500">
                    服务器内部错误，请稍后再试
                </p>
            </div>
            <div class="px-4 py-3">
                <button onclick="document.getElementById('password-modal').remove()"
                        class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                    关闭
                </button>
            </div>
        </div>
        ''', 500


@app.route('/api/edit/<int:aid>', methods=['POST', 'PUT'])
@siwa.doc(
    summary='编辑文章',
    description="编辑文章内容、状态、封面等信息",
    tags=['文章']
)
@jwt_required
def api_edit(user_id, aid):
    """
    编辑文章接口
    ---
    # 权限说明
    - 需要JWT认证
    - 只能编辑自己的文章

    # 参数说明
    - title: 文章标题(可选)
    - content: 文章内容(必填)
    - status: 文章状态(Draft/Published/Deleted)(必填)
    - excerpt: 文章摘要(可选，最多145字符)
    - hiddenStatus: 可见性(0:可见,1:隐藏)(必填)
    - coverImage: 封面图片文件(可选)
    """
    # 权限验证
    if not authorize_by_aid(aid, user_id):
        app.logger.warning(f"用户 {user_id} 尝试编辑无权限的文章 {aid}")
        return jsonify({
            'code': -1,
            'message': '无权限操作此文章',
            'show_edit_code': 'failed'
        }), 403

    try:
        # 获取并验证参数
        content = request.form.get('content', '').strip()
        if not content:
            return jsonify({
                'code': -1,
                'message': '文章内容不能为空',
                'show_edit_code': 'failed'
            }), 400

        status = request.form.get('status', 'Draft').strip()
        if status not in ['Draft', 'Published', 'Deleted']:
            return jsonify({
                'code': -1,
                'message': '无效的文章状态',
                'show_edit_code': 'failed'
            }), 400

        excerpt = (request.form.get('excerpt', '')[:145]).strip()
        hidden_status = request.form.get('hiddenStatus', '0').strip()
        if hidden_status not in ['0', '1']:
            return jsonify({
                'code': -1,
                'message': '无效的可见性设置',
                'show_edit_code': 'failed'
            }), 400

        title = request.form.get('title', '').strip() or None
        cover_image = request.files.get('coverImage')

        # 处理删除操作
        if status == 'Deleted':
            if not delete_article(title, app.config['TEMP_FOLDER']):
                app.logger.error(f"删除文章 {aid} 的本地文件失败")
                return jsonify({
                    'code': -1,
                    'message': '删除文章失败',
                    'show_edit_code': 'failed'
                }), 500

            if not delete_db_article(user_id, aid):
                app.logger.error(f"删除文章 {aid} 的数据库记录失败")
                return jsonify({
                    'code': -1,
                    'message': '删除文章失败',
                    'show_edit_code': 'failed'
                }), 500

            app.logger.info(f"用户 {user_id} 成功删除文章 {aid}")
            return jsonify({
                'code': 0,
                'message': '文章已删除',
                'show_edit_code': 'deleted',
                'redirect': '/profile'
            })

        # 处理封面图片
        cover_image_path = None
        if cover_image:
            if not cover_image.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                return jsonify({
                    'code': -1,
                    'message': '仅支持PNG/JPG格式的封面图片',
                    'show_edit_code': 'failed'
                }), 400

            try:
                # 创建封面目录
                cover_image_path = os.path.join('cover', f"{aid}.png")
                os.makedirs(os.path.dirname(cover_image_path), exist_ok=True)
                with open(cover_image_path, 'wb') as f:
                    cover_image.save(f)
                app.logger.info(f"文章 {aid} 封面图片保存成功: {cover_image_path}")
            except Exception as e:
                app.logger.error(f"保存文章 {aid} 封面图片失败: {str(e)}")
                return jsonify({
                    'code': -1,
                    'message': '封面图片保存失败',
                    'show_edit_code': 'failed'
                }), 500

        # 保存文章修改
        if not save_article_changes(aid, int(hidden_status), status, cover_image_path, excerpt):
            app.logger.error(f"保存文章 {aid} 的基本信息失败")
            return jsonify({
                'code': -1,
                'message': '保存文章信息失败',
                'show_edit_code': 'failed'
            }), 500

        if not zy_save_edit(aid, content):
            app.logger.error(f"保存文章 {aid} 的内容失败")
            return jsonify({
                'code': -1,
                'message': '保存文章内容失败',
                'show_edit_code': 'failed'
            }), 500

        app.logger.info(f"用户 {user_id} 成功编辑文章 {aid}")
        return jsonify({'show_edit_code': 'success'
                        }), 201

    except Exception as e:
        app.logger.error(f"保存文章 {aid} 时出错: {str(e)}", exc_info=True)
        return jsonify({
            'code': -1,
            'message': '服务器内部错误',
            'show_edit_code': 'failed'
        }), 500


@app.route('/health')
def health_check():
    """健康检查端点"""
    return jsonify({
        "status": "healthy",
        "message": "Application is running",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200


@app.route('/reload-plugins')
def reload_plugins():
    plugins_manager.load_plugins()
    return "Plugins reloaded"


@app.route('/api/plugins/toggle/<plugin_name>', methods=['POST'])
def toggle_plugin(plugin_name):
    """切换插件状态"""
    data = request.get_json()
    new_state = data.get('state', False)

    if new_state:
        plugins_manager.enable_plugin(plugin_name)
        return jsonify({
            'status': 'success',
            'message': f'插件 {plugin_name} 已启用',
            'new_state': new_state
        })
    else:
        plugins_manager.disable_plugin(plugin_name)
        return jsonify({
            'status': 'success',
            'message': f'插件 {plugin_name} 已禁用',
            'new_state': new_state
        })


@app.route('/plugin')
def plugin_dashboard():
    plugins = plugins_manager.get_plugin_list()
    return render_template('plugins.html', plugins=plugins)


@app.errorhandler(404)
@app.errorhandler(500)
@app.errorhandler(Exception)
def handle_error(e):
    if isinstance(e, NotFound):
        return error(message="页面未找到", status_code=404)
    elif isinstance(e, Exception):
        return error(message="服务器错误", status_code=500)
    else:
        return error(message="未知错误", status_code=500)


@app.route('/<path:undefined_path>')
def undefined_route(undefined_path):
    error_message = f"Undefined path: {undefined_path}"
    app.logger.error(error_message)
    return error(message=error_message, status_code=500)


if __name__ == "__main__":
    app.run()
