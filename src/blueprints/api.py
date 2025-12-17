import logging
from pathlib import Path

from flask import Blueprint, jsonify, current_app, request
from flask_login import login_required
from sqlalchemy import select, func

from src.auth_utils import jwt_required, admin_required, origin_required
from src.blog.article.password import check_apw_form, get_apw_form
from src.blog.comment import create_comment_with_anti_spam, comment_page_get
from src.blueprints.blog import get_site_domain
from src.extensions import cache, csrf
from src.models import ArticleI18n, Article, User, db
from src.other.report import report_back
from src.setting import app_config
from src.upload.admin_upload import admin_upload_file
from src.upload.public_upload import upload_cover_back, handle_user_upload
from src.user.authz.qrlogin import check_qr_login_back, phone_scan_back, qr_login
from src.user.entities import get_avatar
from src.user.profile.social import get_user_info
from src.user.views import confirm_email_back
from src.utils.config.theme import get_all_themes
from src.utils.filters import f2list
from src.utils.http.generate_response import send_chunk_md
from src.utils.security.safe import is_valid_iso_language_code

api_bp = Blueprint('api', __name__, url_prefix='/api')
domain = app_config.domain

logger = logging.getLogger(__name__)


@api_bp.route('/theme/upload', methods=['POST'])
@admin_required
def api_theme_upload(user_id):
    current_app.logger.info(f'{user_id} : Try Upload file')
    return admin_upload_file(current_app.config['UPLOAD_LIMIT'])


@cache.memoize(1800)
@origin_required
@api_bp.route('/blog/<int:aid>/i18n/<string:iso>', methods=['GET'])
def api_blog_i18n_content(iso, aid):
    if not is_valid_iso_language_code(iso):
        return jsonify({"error": "Invalid language code"}), 400
    content = db.session.query(ArticleI18n.content).filter(
        ArticleI18n.article_id == aid, ArticleI18n.language_code == iso).first()
    if content:
        # content是一个元组，需要取出其中的实际内容
        content_text = content[0] if isinstance(content, tuple) else content.content
        return send_chunk_md(content_text, aid, iso)
    else:
        return jsonify({"error": "Article not found"}), 404


@api_bp.route('/article/unlock', methods=['GET', 'POST'])
@csrf.exempt
def api_article_unlock():
    from src.blueprints.blog import blog_tmp_url
    return blog_tmp_url(domain=domain, cache_instance=cache)


@api_bp.route('/comment/<article_id>', methods=['POST'])
@jwt_required
def api_comment(user_id, article_id):
    return create_comment_with_anti_spam(user_id, article_id)


@api_bp.route("/comment/<article_id>", methods=['GET'])
@login_required
def comment(article_id):
    return comment_page_get(article_id)


@api_bp.route('/report', methods=['POST'])
@jwt_required
def api_report(user_id):
    return report_back(user_id)


@cache.memoize(120)
@api_bp.route('/user/avatar', methods=['GET'])
def api_user_avatar(user_identifier=None, identifier_type='id'):
    user_id = request.args.get('id')
    if user_id is not None:
        user_identifier = int(user_id)
        identifier_type = 'id'
    avatar_url = get_avatar(domain=domain, user_identifier=user_identifier,
                            identifier_type=identifier_type)
    if avatar_url:
        return avatar_url
    else:
        avatar_url = current_app.config['AVATAR_SERVER']  # 默认头像服务器地址
        return avatar_url


@api_bp.route('/tags/suggest', methods=['GET'])
def suggest_tags():
    prefix = request.args.get('q', '')
    # logger.debug(f"prefix: {prefix}")

    # 使用缓存来存储去重后的标签列表
    cache_key = 'unique_tags'  # 使用明确的缓存键名
    unique_tags = cache.get(cache_key)

    if not unique_tags:
        logger.info("缓存未命中，从数据库加载标签...")
        # 获取所有文章的标签字符串
        tags_results = db.session.execute(select(func.distinct(Article.tags))).scalars().all()

        # 处理标签数据
        all_tags = []
        for tag_string in tags_results:
            if tag_string:  # 确保不是空字符串  
                all_tags.extend(f2list(tag_string.strip()))

        # 去重并排序
        unique_tags = sorted(set(all_tags))
        logger.info(f"加载并处理完成，唯一标签数量: {len(unique_tags)}")

        # 缓存处理后的结果，避免重复处理
        cache.set(cache_key, unique_tags, timeout=1200)

    # 过滤出匹配前缀的标签
    matched_tags = [tag for tag in unique_tags if tag.startswith(prefix)]
    # logger.debug(f"匹配前缀 '{prefix}' 的标签数量: {len(matched_tags)}")

    # 返回前五个匹配的标签
    return jsonify(matched_tags[:5])


# 验证并执行换绑的路由
@api_bp.route('/change-email/confirm/<token>', methods=['GET'])
@jwt_required
def confirm_email_change(user_id, token):
    return confirm_email_back(user_id, cache, token)


@cache.memoize(timeout=300)
@api_bp.route('/theme', methods=['GET'])
def get_current_theme():
    return jsonify(get_all_themes())


@cache.cached(timeout=300, key_prefix='all_users')
def get_all_users():
    all_users = {}
    try:
        users = db.session.query(User.username, User.id).all()
        for username, user_id in users:
            all_users[username] = str(user_id)
        return all_users
    except Exception as e:
        logger.error(f"An error occurred: {e}")


@cache.cached(timeout=3600, key_prefix='all_emails')
def get_all_emails():
    all_emails = []
    try:
        # 查询所有用户邮箱
        results = db.session.query(User.email).all()
        for result in results:
            email = result[0]
            all_emails.append(email)
        return all_emails
    except Exception as e:
        logger.error(f"An error occurred: {e}")


@api_bp.route('/email-exists', methods=['GET'])
def email_exists_back():
    email = request.args.get('email')
    all_emails = cache.get('all_emails')
    if all_emails is None:
        # 如果缓存中没有所有用户的邮箱，重新获取并缓存
        all_emails = get_all_emails()
    return jsonify({"exists": bool(email in all_emails)})


@api_bp.route('/username-exists/<username>', methods=['GET'])
def username_exists(username):
    all_users = cache.get('all_users')
    if all_users is None:
        # 如果缓存中没有所有用户的信息，重新获取并缓存
        all_users = get_all_users()
    if request.referrer:
        return jsonify({"exists": bool(all_users.get(username))})
    return all_users.get(username)


@api_bp.route('/user/bio/<int:user_id>', methods=['GET'])
def api_user_bio(user_id):
    user_info = api_user_profile(user_id=user_id)
    bio = user_info[6] if len(user_info) > 6 and user_info[6] else ""
    return bio


@api_bp.route('/user/profile/<int:user_id>', methods=['GET'])
@cache.memoize(timeout=300)
def api_user_profile(user_id):
    return get_user_info(user_id)


@cache.cached(timeout=600, key_prefix='username_check')
def api_username_check(username):
    return username_exists(username)


@api_bp.route('/article/<int:article_id>/status', methods=['POST'])
@jwt_required
def update_article_status(user_id, article_id):
    """更新文章状态"""
    article = db.session.query(Article).filter_by(article_id=article_id, user_id=user_id).first()
    if not article:
        return jsonify({'success': False, 'message': '文章不存在'}), 404

    new_status = int(request.json.get('status'))
    if not isinstance(new_status, int):
        return jsonify({'success': False, 'message': '状态必须是整数类型'}), 400

    article.status = new_status
    # article.updated_at = datetime.now()
    db.session.commit()
    return jsonify({'success': True, 'message': f'文章已{new_status}'})


@api_bp.route('/upload/cover', methods=['POST'])
@jwt_required
def upload_cover(user_id):
    cover_path = Path(str(current_app.root_path)).parent / 'static' / 'cover'
    logger.debug(cover_path)
    return upload_cover_back(user_id=user_id, base_path=cover_path, domain=get_site_domain())


@api_bp.route('/article/password-form/<int:aid>', methods=['GET'])
@login_required
def get_password_form(aid):
    return get_apw_form(aid)


# 密码更改 API
@api_bp.route('/article/password/<int:aid>', methods=['POST'])
@login_required
def api_update_article_password(aid):
    return check_apw_form(aid)


@api_bp.route('/routes')
def list_all_routes():
    routes = []
    for rule in current_app.url_map.iter_rules():
        routes.append({
            "endpoint": rule.endpoint,
            "path": rule.rule,
            "methods": sorted(rule.methods)
        })
    return jsonify({"routes": routes})


@api_bp.route('/qr/generate', methods=['GET'])
def generate_qr():
    """Generate QR code for login"""
    try:
        token_json, qr_code_base64, token_expire, token = qr_login(
            sys_version="1.0", global_encoding=app_config.global_encoding,
            domain=domain
        )

        # Store token in cache
        cache.set(f"QR-token_{token}", token_json, timeout=180)

        return jsonify({
            'success': True,
            'qr_code': f"data:image/png;base64,{qr_code_base64}",
            'token': token,
            'expires_at': token_expire,
            'status': 'pending'
        })

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to generate QR code'
        }), 500


@api_bp.route('/phone/scan', methods=['GET'])
@jwt_required
def phone_scan(user_id):
    return phone_scan_back(user_id, cache)


@api_bp.route('/qr/status', methods=['GET', 'POST'])
def check_qr_status():
    """Check QR code login status"""
    return check_qr_login_back(cache)


@api_bp.route('/media/upload', methods=['POST'])
@jwt_required
def upload_media_file(user_id):
    """Upload media file for media page"""
    try:
        return handle_user_upload(user_id=user_id, allowed_size=current_app.config['UPLOAD_LIMIT'],
                                  allowed_mimes=current_app.config['ALLOWED_MIMES'], check_existing=False)
    except Exception as e:
        logger.error(e)
        return jsonify({'message': '上传失败', 'error': str(e)}), 500


from src.upload.public_upload import handle_chunked_upload_init, handle_chunked_upload_chunk, \
    handle_chunked_upload_complete, handle_chunked_upload_progress, handle_chunked_upload_cancel, \
    handle_chunked_upload_chunks

# 大文件分块上传路由
api_bp.add_url_rule('/upload/chunked/init', 'chunked_upload_init', handle_chunked_upload_init, methods=['POST'])
api_bp.add_url_rule('/upload/chunked/chunk', 'chunked_upload_chunk', handle_chunked_upload_chunk, methods=['POST'])
api_bp.add_url_rule('/upload/chunked/complete', 'chunked_upload_complete', handle_chunked_upload_complete,
                    methods=['POST'])
api_bp.add_url_rule('/upload/chunked/progress', 'chunked_upload_progress', handle_chunked_upload_progress,
                    methods=['GET'])
api_bp.add_url_rule('/upload/chunked/chunks', 'chunked_upload_chunks', handle_chunked_upload_chunks,
                    methods=['GET'])
api_bp.add_url_rule('/upload/chunked/cancel', 'chunked_upload_cancel', handle_chunked_upload_cancel,
                    methods=['POST'])


@cache.cached(timeout=300)
@api_bp.route('/check-username')
def check_username():
    username = request.args.get('username')
    exists = User.query.filter_by(username=username).first() is not None
    return jsonify({'exists': exists})


@cache.cached(timeout=300)
@api_bp.route('/check-email')
def check_email():
    email = request.args.get('email')
    exists = User.query.filter_by(email=email).first() is not None
    return jsonify({'exists': exists})


from src.security import admin_permission, role_required, permission_required, create_permission


# 点赞文章功能
@api_bp.route('/article/<int:article_id>/like', methods=['POST'])
@jwt_required
def like_article(user_id, article_id):
    """用户点赞文章"""
    try:
        # 获取文章
        from src.models.article import ArticleLike
        article = Article.query.get(article_id)
        if not article:
            return jsonify({'success': False, 'message': '文章不存在'}), 404

        # 检查用户是否已经点过赞
        existing_like = ArticleLike.query.filter_by(user_id=user_id, article_id=article_id).first()
        if existing_like:
            return jsonify({'success': False, 'message': '您已经点过赞了'}), 400

        # 增加点赞数
        article.likes += 1

        # 记录用户点赞
        new_like = ArticleLike(user_id=user_id, article_id=article_id)
        db.session.add(new_like)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '点赞成功',
            'likes': article.likes
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': '点赞失败'}), 500


@api_bp.route('/article/<int:article_id>/view', methods=['POST'])
def record_article_view(article_id):
    """记录文章浏览量（使用缓存异步更新数据库）"""
    try:
        # 检查文章是否存在
        article = db.session.query(Article).filter_by(article_id=article_id).first()
        if not article:
            return jsonify({'success': False, 'message': '文章不存在'}), 404

        # 使用缓存来记录浏览量，避免频繁写入数据库
        cache_key = f"article_views_{article_id}"
        current_views = cache.get(cache_key)

        if current_views is None:
            # 如果缓存中没有，则从数据库获取当前浏览量
            current_views = article.views

        # 增加浏览量计数
        current_views += 1

        # 将新的浏览量存回缓存
        cache.set(cache_key, current_views, timeout=300)  # 缓存5分钟

        return jsonify({'success': True, 'message': '浏览量记录成功'})

    except Exception as e:
        return jsonify({'success': False, 'message': f'记录浏览量失败: {str(e)}'}), 500


# 需要管理员角色
@api_bp.route('/admin/dashboard')
@admin_permission.require()  # 或者使用 @role_required('admin')
def admin_dashboard():
    return jsonify({'message': '管理员面板'})


# 需要经理角色
@api_bp.route('/manager/reports')
@role_required('manager')
def manager_reports():
    return jsonify({'message': '经理报告'})


# 需要特定权限
@api_bp.route('/user/create')
@permission_required(create_permission('user_create'))
def create_user():
    return jsonify({'message': '创建用户'})


# 多个权限之一
@api_bp.route('/content/edit')
def edit_content():
    edit_perm = create_permission('content_edit')
    publish_perm = create_permission('content_publish')

    if edit_perm.can() or publish_perm.can():
        return jsonify({'message': '编辑内容'})
    else:
        return jsonify({'error': '权限不足'}), 403


# 在视图函数中检查权限
@api_bp.route('/analytics')
def analytics():
    from flask_principal import Permission, RoleNeed

    # 动态检查权限
    if Permission(RoleNeed('admin')).can():
        return jsonify({'data': '完整分析数据'})
    elif Permission(RoleNeed('manager')).can():
        return jsonify({'data': '基础分析数据'})
    else:
        return jsonify({'error': '无权访问分析数据'}), 403


@api_bp.route('/user/check-login', methods=['GET'])
def check_login_status():
    """检查用户登录状态"""
    # 检查用户是否通过 Flask-Login 登录
    from flask_login import current_user
    if current_user.is_authenticated:
        user = check_user_exist(current_user.id)
        if user:
            return jsonify({
                'logged_in': True,
                'user_id': current_user.id,
            }), 200

    # 用户未登录或无效
    return jsonify({
        'logged_in': False,
        'message': 'Not logged in or invalid user'
    }), 200


@cache.memoize(timeout=300)
def check_user_exist(user_id):
    return User.query.get(user_id) is not None


@api_bp.route('/user/media', methods=['GET'])
@jwt_required
def get_user_media(user_id):
    """获取当前用户的所有媒体文件"""
    try:
        from src.models.media import Media
        media_list = Media.query.filter_by(user_id=user_id).all()
        
        media_data = []
        for media in media_list:
            media_data.append({
                'id': media.id,
                'original_filename': media.original_filename,
                'mime_type': media.file_hash.mime_type,
                'created_at': media.created_at.isoformat() if media.created_at else None
            })
        
        return jsonify({'media': media_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/media/<int:media_id>', methods=['GET'])
@jwt_required
def get_media_details(user_id, media_id):
    """获取媒体文件详情"""
    try:
        from src.models.media import Media
        media = Media.query.filter_by(id=media_id, user_id=user_id).first()
        
        if not media:
            return jsonify({'error': '媒体文件不存在或无权限访问'}), 404
        
        media_data = {
            'id': media.id,
            'original_filename': media.original_filename,
            'hash': media.hash,
            'mime_type': media.file_hash.mime_type,
            'file_size': media.file_hash.file_size,
            'storage_path': media.file_hash.storage_path,
            'created_at': media.created_at.isoformat() if media.created_at else None
        }
        
        return jsonify({'media': media_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

