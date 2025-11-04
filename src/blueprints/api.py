from pathlib import Path

from flask import Blueprint, jsonify, current_app, render_template, request, redirect, make_response
from sqlalchemy import select, func

from src.blog.article.core.content import get_i18n_content_by_aid
from src.blog.article.core.views import blog_tmp_url
from src.blog.article.security.password import check_apw_form, get_apw_form
from src.blog.comment import create_comment_with_anti_spam, comment_page_get
from src.database import get_db
from src.extensions import cache
from src.models import Article, User
from src.other.filters import f2list
from src.other.report import report_back
from src.setting import app_config
from src.upload.admin_upload import admin_upload_file
from src.upload.public_upload import upload_cover_back, handle_user_upload
from src.user.authz.decorators import jwt_required, admin_required, origin_required
from src.user.authz.qrlogin import check_qr_login_back, phone_scan_back, qr_login
from src.user.entities import get_avatar
from src.user.profile.social import get_user_info
from src.user.views import confirm_email_back
from src.utils.config.theme import get_all_themes
from src.utils.http.generate_response import send_chunk_md
from src.utils.security.jwt_handler import JWTHandler
from src.utils.security.safe import is_valid_iso_language_code

api_bp = Blueprint('api', __name__, url_prefix='/api')
domain = app_config.domain


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
    content = get_i18n_content_by_aid(iso=iso, aid=aid)
    return send_chunk_md(content, aid, iso)


@api_bp.route('/article/unlock', methods=['GET', 'POST'])
def api_article_unlock():
    return blog_tmp_url(domain=domain, cache_instance=cache)


@api_bp.route('/comment/<article_id>', methods=['POST'])
@jwt_required
def api_comment(user_id, article_id):
    return create_comment_with_anti_spam(user_id, article_id)


@api_bp.route("/comment/<article_id>", methods=['GET'])
@jwt_required
def comment(user_id, article_id):
    return comment_page_get(user_id, article_id)


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
    # print(f"prefix: {prefix}")

    # 使用缓存来存储去重后的标签列表
    cache_key = 'unique_tags'  # 使用明确的缓存键名
    unique_tags = cache.get(cache_key)

    if not unique_tags:
        print("缓存未命中，从数据库加载标签...")
        with get_db() as db:
            # 获取所有文章的标签字符串
            tags_results = db.execute(select(func.distinct(Article.tags))).scalars().all()

            # 处理标签数据
            all_tags = []
            for tag_string in tags_results:
                if tag_string:  # 确保不是空字符串
                    all_tags.extend(f2list(tag_string.strip()))

            # 去重并排序
            unique_tags = sorted(set(all_tags))
            print(f"加载并处理完成，唯一标签数量: {len(unique_tags)}")

            # 缓存处理后的结果，避免重复处理
            cache.set(cache_key, unique_tags, timeout=1200)

    # 过滤出匹配前缀的标签
    matched_tags = [tag for tag in unique_tags if tag.startswith(prefix)]
    # print(f"匹配前缀 '{prefix}' 的标签数量: {len(matched_tags)}")

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
    with get_db() as session:
        try:
            users = session.query(User.username, User.id).all()
            for username, user_id in users:
                all_users[username] = str(user_id)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            return all_users


@cache.cached(timeout=3600, key_prefix='all_emails')
def get_all_emails():
    all_emails = []
    with get_db() as session:
        try:
            # 查询所有用户邮箱
            results = session.query(User.email).all()
            for result in results:
                email = result[0]
                all_emails.append(email)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            return all_emails


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


@api_bp.route('/upload/cover', methods=['POST'])
@jwt_required
def upload_cover(user_id):
    cover_path = Path(str(current_app.root_path)).parent / 'static' / 'cover'
    print(cover_path)
    return upload_cover_back(user_id=user_id, base_path=cover_path, domain=domain)


@api_bp.route('/article/password-form/<int:aid>', methods=['GET'])
@jwt_required
def get_password_form(user_id, aid):
    return get_apw_form(aid)


# 密码更改 API
@api_bp.route('/article/password/<int:aid>', methods=['POST'])
@jwt_required
def api_update_article_password(user_id, aid):
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
        print(f"An error occurred: {e}")
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


@api_bp.route('/mobile/login', methods=['GET', 'POST'])
def mobile_login():
    """Mobile login page for QR scanning"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        email = data.get('email')
        password = data.get('password')

        from flask_bcrypt import check_password_hash
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Generate JWT tokens
            jwt_token = JWTHandler.generate_token(user.id, user.username)
            refresh_token = JWTHandler.generate_refresh_token(user.id)
            # Set cookies for mobile QR scanning
            response = make_response(jsonify({
                'success': True,
                'message': 'Login successful',
                'user': user.to_dict()
            }) if request.is_json else redirect('/profile'))

            response.set_cookie('jwt', jwt_token, httponly=True, secure=False, max_age=3600)
            response.set_cookie('refresh_token', refresh_token, httponly=True, secure=False, max_age=604800)

            return response
        else:
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': 'Invalid email or password'
                }), 401
            else:
                return render_template('mobile/login.html', error='Invalid email or password')

    return render_template('mobile/login.html')


@api_bp.route('/media/upload', methods=['POST'])
@jwt_required
def upload_user_path(user_id):
    """Upload media file"""
    try:
        return handle_user_upload(user_id=user_id, allowed_size=current_app.config['UPLOAD_LIMIT'],
                                  allowed_mimes=current_app.config['ALLOWED_MIMES'], check_existing=False)
    except Exception as e:
        print(e)
