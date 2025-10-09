from pathlib import Path

from flask import Blueprint, request, jsonify, current_app, redirect, render_template

from src.blog.article.core.views import blog_detail_i18n, blog_detail_i18n_list, contribute_back, blog_detail_aid_back, \
    new_article_back, edit_article_back
from src.blog.homepage import index_page_back, tag_page_back, featured_page_back
from src.blueprints.api import api_user_profile, username_exists, api_user_avatar, api_user_bio
from src.error import error
from src.extensions import cache
from src.models import UserSubscription, Article, db, User
from src.other.diy import diy_space_put
from src.user.authz.decorators import jwt_required, domain
from src.user.authz.password import confirm_password_back, change_password_back
from src.user.views import change_profiles_back, setting_profiles_back, diy_space_back
from update import base_dir

other_bp = Blueprint('other', __name__)


@other_bp.route('/<int:aid>.html/<string:iso>/<string:slug_name>', methods=['GET', 'POST'])
def blog_detail_i18n_route(aid, iso, slug_name):
    return blog_detail_i18n(aid=aid, blog_slug=slug_name, i18n_code=iso)


@other_bp.route('/contribute', methods=['GET', 'POST'])
def contribute():
    aid = request.args.get('aid')  # 文章ID
    if aid is None:
        # 根据请求类型返回不同的错误响应
        if request.method == 'POST':
            return jsonify({'success': False, 'message': 'Invalid request: missing article ID'}), 400
        return error(message='Invalid request: missing article ID', status_code=400)
    return contribute_back(aid)


@other_bp.route('/<int:aid>.html/<string:iso>', methods=['GET'])
def blog_detail_i18n_list_route(aid, iso):
    return blog_detail_i18n_list(aid=aid, i18n_code=iso)


@other_bp.route('/<int:aid>.html', methods=['GET', 'POST'])
def blog_detail_aid(aid):
    return blog_detail_aid_back(aid=aid)


@other_bp.route('/tmpView', methods=['GET', 'POST'])
def temp_view():
    url = request.args.get('url')
    if url is None:
        return jsonify({"message": "Missing URL parameter"}), 400

    aid = cache.get(f"temp-url_{url}")
    print(aid)

    if aid is None:
        return jsonify({"message": "Temporary URL expired or invalid"}), 404
    else:
        return blog_detail_aid_back(aid=aid, safeMode=False)


@other_bp.route('/profile')
@jwt_required
def profile(user_id):
    """当前用户的个人资料页面"""
    return redirect(f'/space/{user_id}')


@other_bp.route('/space/<int:target_user_id>')
@jwt_required
def user_space(user_id, target_user_id):
    """用户空间页面 - 显示用户资料和文章"""
    try:
        target_user = User.query.get_or_404(target_user_id)

        # 判断是否为当前用户自己的空间
        is_own_profile = user_id == target_user_id

        if target_user.profile_private and not is_own_profile:
            return render_template('inform.html', status_code=503, message='<h1>该用户未公开资料</h1><UNK>')

        # 获取用户统计数据
        stats = {
            'articles_count': Article.query.filter_by(user_id=target_user_id, status=1).count(),
            'followers_count': UserSubscription.query.filter_by(subscribed_user_id=target_user_id).count(),
            'following_count': UserSubscription.query.filter_by(subscriber_id=target_user_id).count(),
            'total_views': db.session.query(db.func.sum(Article.views)).filter_by(user_id=target_user_id,
                                                                                  status=1).scalar() or 0,
            'total_likes': db.session.query(db.func.sum(Article.likes)).filter_by(user_id=target_user_id,
                                                                                  status=1).scalar() or 0
        }

        # 获取用户最新发布的文章
        recent_articles = Article.query.filter_by(
            user_id=target_user_id,
            status=1
        ).order_by(Article.updated_at.desc()).limit(6).all()

        # 检查当前用户是否已关注目标用户
        is_following = False
        if user_id != target_user_id:
            is_following = UserSubscription.query.filter_by(
                subscriber_id=user_id,
                subscribed_user_id=target_user_id
            ).first() is not None

        return render_template('Profile.html',
                               target_user=target_user,
                               is_own_profile=is_own_profile,
                               is_following=is_following,
                               stats=stats,
                               recent_articles=recent_articles)
    except Exception as e:
        print(f"An error occurred: {e}")


@other_bp.route('/new', methods=['GET', 'POST'])
@jwt_required
def new_article(user_id):
    return new_article_back(user_id)


@other_bp.route('/', methods=['GET'])
@other_bp.route('/index.html', methods=['GET'])
@cache.cached(timeout=180, query_string=True)
def index_html():
    return index_page_back()


@other_bp.route('/tag/<tag_name>', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def tag_page(tag_name):
    return tag_page_back(tag_name, current_app.config['global_encoding'])


@other_bp.route('/featured', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def featured_page():
    return featured_page_back()


@other_bp.route('/diy/space', methods=['GET'])
@jwt_required
def diy_space(user_id):
    try:
        return diy_space_back(user_id, avatar_url=api_user_avatar(user_id), profiles=api_user_profile(user_id),
                              user_bio=api_user_bio(user_id))
    except Exception as e:
        print(f"An error occurred: {e}")


@other_bp.route('/edit/blog/<int:aid>', methods=['GET', 'POST', 'PUT'])
@jwt_required
def markdown_editor(user_id, aid):
    return edit_article_back(user_id, aid)


@other_bp.route('/setting/profiles', methods=['GET'])
@jwt_required
def setting_profiles(user_id):
    user_info = api_user_profile(user_id=user_id)
    return setting_profiles_back(user_id, user_info, cache, current_app.config['AVATAR_SERVER'])


@other_bp.route('/setting/profiles', methods=['PUT'])
@jwt_required
def change_profiles(user_id):
    return change_profiles_back(user_id, cache, domain)


@other_bp.route("/@<user_name>")
def user_diy_space(user_name):
    @cache.cached(timeout=300, key_prefix=f'current_{user_name}')
    def _user_diy_space():
        user_id = username_exists(user_name)
        user_path = Path(base_dir) / 'media' / user_id / 'index.html'
        print(user_path)
        if user_path.exists():
            with user_path.open('r', encoding=current_app.config['global_encoding']) as f:
                return f.read()
        else:
            return "用户主页未找到", 404

    return _user_diy_space()


@other_bp.route("/diy/space", methods=['PUT'])
@jwt_required
def diy_space_upload(user_id):
    print("111")
    return diy_space_put(base_dir=base_dir, user_id=user_id, encoding=current_app.config['global_encoding'])


@other_bp.route('/confirm-password', methods=['GET', 'POST'])
@jwt_required
def confirm_password(user_id):
    return confirm_password_back(user_id, cache)


@other_bp.route('/change-password', methods=['GET', 'POST'])
@jwt_required
def change_password(user_id):
    return change_password_back(user_id, cache)
