import hashlib
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image
from flask import Flask
from flask import render_template, request, jsonify, send_file, \
    make_response
from flask_caching import Cache
from flask_siwadoc import SiwaDoc
from jinja2 import select_autoescape, TemplateNotFound
from werkzeug.exceptions import NotFound
from werkzeug.middleware.proxy_fix import ProxyFix

from plugins.manager import PluginManager
from src.blog.article.core.content import delete_article, save_article_changes, get_content, \
    get_blog_temp_view, get_i18n_content_by_aid
from src.blog.article.core.crud import get_articles_by_uid, delete_db_article, fetch_articles, \
    get_articles_recycle, blog_restore, blog_delete, get_aid_by_title, blog_update
from src.blog.article.core.views import blog_detail_back, blog_preview_back
from src.blog.article.metadata.handlers import persist_views, view_counts
from src.blog.article.security.password import get_article_password, get_apw_form, check_apw_form
from src.blog.comment import create_comment, delete_comment_back, comment_page
from src.blog.tag import update_tags_back
from src.blueprints.auth import auth_bp
from src.blueprints.dashboard import dashboard_bp
from src.blueprints.media import create_media_blueprint
from src.blueprints.theme import create_theme_blueprint
from src.blueprints.website import create_website_blueprint
from src.config.theme import db_get_theme
from src.database import get_db_connection
from src.error import error
from src.media.file import get_file, delete_file
from src.media.processing import handle_cover_resize
from src.notification import read_all_notifications, get_notifications, read_current_notification
from src.other.diy import diy_space_put
from src.other.report import report_back
from src.other.search import search_handler
from src.plugin import plugin_bp
from src.setting import AppConfig
from src.upload.admin_upload import admin_upload_file
from src.upload.public_upload import handle_user_upload, handle_editor_upload
from src.upload.views import upload_bulk_back, upload_single_back
from src.user.authz.cclogin import cc_login, callback
from src.user.authz.core import get_current_username
from src.user.authz.decorators import jwt_required, admin_required, origin_required
from src.user.authz.password import confirm_password_back, change_password_back
from src.user.authz.qrlogin import qr_login, phone_scan_back
from src.user.entities import auth_by_uid, bind_email, username_exists, get_avatar
from src.user.follow import unfollow_user, userFollow_lock, follow_user, fans_fans_back, fans_follow_back
from src.user.profile.social import get_following_count, get_follower_count, get_user_info, \
    get_user_name_by_id
from src.user.views import setting_profiles_back, user_space_back, markdown_editor_back, change_profiles_back
from src.utils.http.etag import generate_etag
from src.utils.http.generate_response import send_chunk_md
from src.utils.security.ip_utils import get_client_ip
from src.utils.security.safe import random_string, is_valid_iso_language_code

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


@app.route('/plugin')
def plugin_dashboard():
    plugins = plugins_manager.get_plugin_list()
    return render_template('plugins.html', plugins=plugins)


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
    return confirm_password_back(user_id, cache)


@app.route('/change-password', methods=['GET', 'POST'])
@jwt_required
def change_password(user_id):
    return change_password_back(user_id, cache)


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
    content, _ = get_content(identifier=aid, is_title=False, limit=9999)
    return send_chunk_md(content, aid)


@cache.memoize(1800)
@origin_required
@app.route('/api/blog/<int:aid>/i18n/<string:iso>', methods=['GET'])
def api_blog_i18n_content(iso, aid):
    if not is_valid_iso_language_code(iso):
        return jsonify({"error": "Invalid language code"}), 400
    content = get_i18n_content_by_aid(iso=iso, aid=aid)
    return send_chunk_md(content, aid, iso)


@cache.memoize(180)
@app.route('/blog/<blog_name>', methods=['GET', 'POST'])
def blog_detail(blog_name):
    return blog_detail_back(blog_name=blog_name)


@cache.memoize(180)
@app.route('/blog/<title>/images/<file_name>', methods=['GET'])
def blog_file(title, file_name):
    return get_file(base_dir, file_name, title)


@app.route('/preview', methods=['GET'])
@jwt_required
def sys_out_prev_page(user_id):
    return blog_preview_back(base_dir, domain=domain)


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
    return phone_scan_back(user_id, cache)


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
    new_comment = request.json.get('new-comment')
    if not new_comment:
        return jsonify({"message": "评论内容不能为空"}), 400
    return create_comment(aid=aid, pid=pid, user_id=user_id, comment_content=new_comment, ip=get_client_ip(request),
                          ua=request.headers.get('User-Agent'))


@app.route("/Comment")
@jwt_required
def comment(user_id):
    return comment_page(user_id)


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
    return report_back(user_id)


@app.route('/api/comment', methods=['delete'])
@siwa.doc(
    description='删除评论',
    tags=['评论']
)
@jwt_required
def api_delete_comment(user_id):
    return delete_comment_back(user_id)


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
    return update_tags_back(user_id, aid)


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
    api_key = request.form.get('API_KEY')
    if not validate_api_key(api_key):
        return jsonify([{"filename": "无法上传", "status": "failed", "message": "API_KEY 错误"}]), 403
    return upload_bulk_back(user_id, cache, app.config['UPLOAD_LIMIT'])


@app.route('/new', methods=['GET', 'POST'])
@jwt_required
def create_article(user_id):
    return upload_single_back(user_id, cache, app.config['UPLOAD_LIMIT'], app.config['TEMP_FOLDER'])


def render_profile(user_id, articles, recycle_bin_flag=False):
    avatar_url = api_user_avatar(user_id)
    user_bio = api_user_bio(user_id=user_id) or "这人很懒，什么也没留下"
    user_follow = get_following_count(user_id=user_id) or 0
    follower = get_follower_count(user_id=user_id) or 0
    return render_template('Profile.html',
                           avatar_url=avatar_url,
                           userBio=user_bio,
                           following=user_follow,
                           follower=follower,
                           target_id=user_id,
                           user_id=user_id,
                           Articles=articles,
                           recycle_bin=recycle_bin_flag)


@app.route('/profile', methods=['GET', 'POST'])
@jwt_required
def profile(user_id):
    owner_articles = get_articles_by_uid(user_id=user_id) or []
    if not isinstance(owner_articles, list):
        owner_articles = list(owner_articles) if owner_articles is not None else []
    return render_profile(user_id, owner_articles)


@app.route('/profile/~recycle', methods=['GET', 'POST'])
@jwt_required
def recycle_bin(user_id):
    recycle_articles = get_articles_recycle(user_id=user_id) or []
    return render_profile(user_id, recycle_articles, recycle_bin_flag=True)


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
    user_avatar = api_user_avatar(user_id)
    user_bio = api_user_bio(user_id=user_id) or "<UNK>"
    return fans_follow_back(user_id, user_avatar, user_bio)


@app.route('/fans/fans')
@jwt_required
def fans_fans(user_id):
    user_avatar = api_user_avatar(user_id)
    user_bio = api_user_bio(user_id=user_id) or "<UNK>"
    return fans_fans_back(user_id, user_avatar, user_bio)


@app.route('/space/<target_id>', methods=['GET', 'POST'])
@jwt_required
def user_space(user_id, target_id):
    user_bio = api_user_bio(user_id=target_id)
    target_username = api_user_profile(user_id=target_id)[1] or "佚名"
    return user_space_back(user_id, target_id, user_bio, target_username=target_username,
                           avatar_url=api_user_avatar(target_id))


@app.route('/edit/blog/<int:aid>', methods=['GET', 'POST', 'PUT'])
@jwt_required
def markdown_editor(user_id, aid):
    return markdown_editor_back(user_id, aid)


@app.route('/setting/profiles', methods=['GET'])
@jwt_required
def setting_profiles(user_id):
    user_info = api_user_profile(user_id=user_id)
    return setting_profiles_back(user_id, user_info, cache, app.config['AVATAR_SERVER'])


@app.route('/setting/profiles', methods=['PUT'])
@jwt_required
def change_profiles(user_id):
    return change_profiles_back(user_id, cache, domain)


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


@app.route('/api/messages/read', methods=['POST'])
@siwa.doc(
    summary="标记消息为已读",
    description="标记消息为已读。",
    tags=["消息"]
)
@jwt_required
def read_notification(user_id):
    nid = request.args.get('nid')
    return read_current_notification(user_id, nid)


@app.route('/api/messages', methods=['GET'])
@siwa.doc(
    summary="获取消息列表",
    description="获取消息列表。",
    tags=["消息"]
)
@jwt_required
def fetch_message(user_id):
    return get_notifications(user_id)


@app.route('/api/messages/read_all', methods=['POST'])
@siwa.doc(
    summary="标记所有消息为已读",
    description="标记所有消息为已读。",
    tags=["消息"]
)
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
    return get_apw_form(aid)


# 密码更改 API
@app.route('/api/article/password/<int:aid>', methods=['POST'])
@jwt_required
def api_update_article_password(user_id, aid):
    return check_apw_form(aid)


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
    if not auth_by_uid(aid, user_id):
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


@app.route('/api/plugins/toggle/<plugin_name>', methods=['POST'])
def toggle_plugin(plugin_name):
    data = request.get_json()
    new_state = data.get('state', False)

    if new_state:
        success = plugins_manager.enable_plugin(plugin_name)
    else:
        success = plugins_manager.disable_plugin(plugin_name)

    return jsonify({
        'status': 'success' if success else 'error',
        'message': f'插件 {plugin_name} 已{"启用" if new_state else "禁用"}',
        'new_state': new_state
    })


@app.route('/api/routes')
def list_all_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            "endpoint": rule.endpoint,
            "path": rule.rule,
            "methods": sorted(rule.methods)
        })
    return jsonify({"routes": routes})


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
