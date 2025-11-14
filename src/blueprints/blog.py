from flask import Blueprint, request, jsonify, current_app, render_template

from src.blog.article.core.views import blog_detail_i18n, blog_detail_i18n_list, contribute_back, blog_detail_aid_back, \
    new_article_back, edit_article_back
from src.blog.homepage import index_page_back, tag_page_back, featured_page_back
from src.blueprints.api import api_user_profile
from src.error import error
from src.extensions import cache
from src.models import UserSubscription, Article, db, User, Notification, Pages, SystemSettings, MenuItems, Menus
from src.user.authz.decorators import jwt_required, domain
from src.user.views import change_profiles_back, setting_profiles_back

blog_bp = Blueprint('blog', __name__)


@blog_bp.route('/<int:aid>.html/<string:iso>/<string:slug_name>', methods=['GET', 'POST'])
def blog_detail_i18n_route(aid, iso, slug_name):
    return blog_detail_i18n(aid=aid, blog_slug=slug_name, i18n_code=iso)


@blog_bp.route('/contribute', methods=['GET', 'POST'])
def contribute():
    aid = request.args.get('aid')  # 文章ID
    if aid is None:
        # 根据请求类型返回不同的错误响应
        if request.method == 'POST':
            return jsonify({'success': False, 'message': 'Invalid request: missing article ID'}), 400
        return error(message='Invalid request: missing article ID', status_code=400)
    return contribute_back(aid)


@blog_bp.route('/<int:aid>.html/<string:iso>', methods=['GET'])
def blog_detail_i18n_list_route(aid, iso):
    return blog_detail_i18n_list(aid=aid, i18n_code=iso)


@blog_bp.route('/<int:aid>.html', methods=['GET', 'POST'])
def blog_detail_aid(aid):
    return blog_detail_aid_back(aid=aid)


@blog_bp.route('/tmpView', methods=['GET', 'POST'])
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


@blog_bp.route('/new', methods=['GET', 'POST'])
@jwt_required
def new_article(user_id):
    return new_article_back(user_id)


@blog_bp.route('/', methods=['GET'])
@blog_bp.route('/index.html', methods=['GET'])
@cache.cached(timeout=180, query_string=True)
def index_html():
    return index_page_back()


@blog_bp.route('/tag/<tag_name>', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def tag_page(tag_name):
    return tag_page_back(tag_name, current_app.config['global_encoding'])


@blog_bp.route('/featured', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def featured_page():
    return featured_page_back()


@blog_bp.route('/edit/blog/<int:aid>', methods=['GET', 'POST', 'PUT'])
@jwt_required
def markdown_editor(user_id, aid):
    return edit_article_back(user_id, aid)


@blog_bp.route('/setting/profiles', methods=['GET'])
@jwt_required
def setting_profiles(user_id):
    user_info = api_user_profile(user_id=user_id)
    return setting_profiles_back(user_id, user_info, cache, current_app.config['AVATAR_SERVER'])


@blog_bp.route('/setting/profiles', methods=['PUT'])
@jwt_required
def change_profiles(user_id):
    return change_profiles_back(user_id, cache, domain)


@blog_bp.route('/space/<int:target_user_id>')
@jwt_required
def user_space(user_id, target_user_id):
    """用户空间页面 - 显示用户资料和文章"""
    try:
        target_user = User.query.get_or_404(target_user_id)

        # 判断是否为当前用户自己的空间
        is_own_profile = user_id == target_user_id

        has_unread_message = False

        if is_own_profile:
            # 获取用户未读消息数
            has_unread_message = bool(db.session.query(Notification).filter_by(user_id=target_user_id,
                                                                               is_read=False).count()) or False

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
                               has_unread_message=has_unread_message,
                               stats=stats,
                               recent_articles=recent_articles)
    except Exception as e:
        print(f"An error occurred: {e}")


def render_template_with_settings(template_content):
    """
    根据 SystemSettings 表中的所有键值对替换模板内容
    模板中的占位符格式为 {{ key_name }}
    """
    if not template_content:
        return template_content

    # 获取所有系统设置
    settings = db.session.query(SystemSettings).all()

    # 构建键值对字典
    settings_dict = {setting.key: setting.value for setting in settings}

    # 替换模板中的占位符
    for key, value in settings_dict.items():
        placeholder = '{{ ' + key + ' }}'
        if placeholder in template_content and value:
            template_content = template_content.replace(placeholder, value)

    return template_content


@cache.cached(timeout=24 * 3600, key_prefix='footer')
def get_footer():
    footer_content = db.session.query(Pages).filter_by(slug='footer001').first()

    if not footer_content:
        return '<span>-- 我是有底线的 --</span>'

    # 使用通用的模板渲染函数
    rendered_content = render_template_with_settings(footer_content.content)

    return rendered_content


@cache.cached(timeout=24 * 3600, key_prefix='banner')
def get_banner():
    banner_content = db.session.query(Pages).filter_by(slug='banner001').first()

    if not banner_content:
        return ''

    # 使用通用的模板渲染函数
    rendered_content = render_template_with_settings(banner_content.content)

    return rendered_content


def get_system_setting_value(key):
    """获取系统设置中的某个值"""
    setting = db.session.query(SystemSettings.value).filter_by(key=key).first()
    return setting.value if setting else None


@cache.cached(timeout=24 * 3600, key_prefix='site_title')
def get_site_title():
    """获取网站标题"""
    return get_system_setting_value('site_title')


@cache.cached(timeout=24 * 3600, key_prefix='site_domain')
def get_site_domain():
    """获取网站域名"""
    return get_system_setting_value('site_domain')


@cache.cached(timeout=24 * 3600, key_prefix='site_beian')
def get_site_beian():
    """获取网站备案号"""
    return get_system_setting_value('site_beian')


def get_menu_by_slug(slug):
    """根据slug获取菜单及其所有菜单项"""
    menu = Menus.query.filter_by(slug=slug, is_active=True).first()
    if not menu:
        return None

    # 获取所有顶级菜单项（parent_id为None）
    menu_items = MenuItems.query.filter_by(
        menu_id=menu.id,
        parent_id=None,
        is_active=True
    ).order_by(MenuItems.order_index).all()

    return {
        'menu': menu,
        'items': menu_items
    }


def build_menu_tree(menu_items):
    """递归构建菜单树"""
    result = []
    for item in menu_items:
        menu_item_data = {
            'id': item.id,
            'title': item.title,
            'url': item.url,
            'target': item.target,
            'order_index': item.order_index
        }

        # 递归处理子菜单
        children = MenuItems.query.filter_by(
            parent_id=item.id,
            is_active=True
        ).order_by(MenuItems.order_index).all()

        if children:
            menu_item_data['children'] = build_menu_tree(children)

        result.append(menu_item_data)

    return result


@cache.cached(timeout=3 * 3600, key_prefix='site_menu')
def get_site_menu(slug):
    """获取网站菜单"""
    menu_data = get_menu_by_slug(slug)
    if not menu_data:
        return None
    # 构建菜单树
    menu_tree = build_menu_tree(menu_data['items'])
    print(menu_tree)
    return menu_tree


@cache.cached(timeout=3600, key_prefix='site_footer')
def get_current_menu_slug():
    """获取当前菜单的slug"""
    menu_slug = SystemSettings.query.filter_by(key='menu_slug').first()
    return menu_slug.value if menu_slug else None


@cache.cached(timeout=3600, key_prefix='selfDefined_page')
@blog_bp.route('/page/<string:slug>.html', methods=['GET'])
def get_selfDefined_page(slug):
    """获取自定义页面"""
    page = Pages.query.filter_by(slug=f"{slug}.html").first()
    if not page:
        return jsonify({'success': False, 'data': '页面不存在'}), 404
    return page.content
