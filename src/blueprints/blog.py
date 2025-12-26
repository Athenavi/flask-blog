import re

from flask import Blueprint
from flask import request, render_template, jsonify, current_app
from flask import url_for, flash, redirect
from flask_jwt_extended import current_user

from src.auth_utils import jwt_required
from src.blog.article.password import get_article_password
from src.blog.homepage import index_page_back, tag_page_back, featured_page_back
from src.error import error
from src.extensions import cache, csrf, limiter
from src.models import Article, ArticleContent, ArticleI18n, User, db, Category, VIPPlan
from src.models import UserSubscription, Notification, Pages, SystemSettings, MenuItems, Menus
from src.user.entities import auth_by_uid
from src.user.views import change_profiles_back, setting_profiles_back
from src.utils.security.safe import is_valid_iso_language_code, valid_language_codes
from src.utils.security.safe import random_string

blog_bp = Blueprint('blog', __name__)


def edit_article_back(user_id, article_id):
    auth = auth_by_uid(article_id, user_id)
    if auth is None:
        return jsonify({"message": "Authentication failed"}), 401

    article = Article.query.filter_by(article_id=article_id).first()
    content_obj = ArticleContent.query.filter_by(aid=article_id).first()
    content = content_obj.content if content_obj else ""
    categories = Category.query.all()
    vip_plans = VIPPlan.query.all()

    if request.method == 'POST':

        try:
            # 更新文章基本信息
            # print(request.form)
            article.title = request.form.get('title')
            article.slug = request.form.get('slug')
            article.excerpt = request.form.get('excerpt')
            article.tags = request.form.get('tags')
            article.hidden = 1 if request.form.get('hidden') == 'on' else 0
            article.status = request.form.get('status')
            article.category_id = request.form.get('category')
            article.cover_image = request.form.get('cover_image')
            article.article_ad = request.form.get('article_ad')
            # 将 'on' 或 None 转换为布尔值
            article.is_vip_only = True if request.form.get('vipRequired') == 'on' else False
            article.required_vip_level = request.form.get('vipRequiredLevel') or 0

            # 如果文章被隐藏，则vipRequired自动关闭
            if article.hidden == 1:
                article.is_vip_only = False

            # 处理slug，允许包含 -
            article.slug = re.sub(r'[^\w\s-]', '', article.slug)
            article.slug = re.sub(r'\s+', '_', article.slug)

            # 更新或创建文章内容
            content_value = request.form.get('content')
            if content_obj:
                content_obj.content = content_value
            else:
                content_obj = ArticleContent(
                    aid=article_id,
                    content=content_value,
                    language_code='zh-CN'
                )
                db.session.add(content_obj)

            # 提交所有更改到数据库
            db.session.commit()
            flash('更新成功!', 'success')

        except Exception as e:
            db.session.rollback()
            print(f"保存失败: {str(e)}")
            flash(f'保存失败: {str(e)}', 'error')
            return render_template('blog/edit.html',
                                   article=article,
                                   content=content,
                                   categories=categories,
                                   status_options=['Draft', 'Published', 'Deleted'])

        return redirect(url_for('blog.markdown_editor', aid=article_id))

    return render_template('blog/edit.html',
                           article=article,
                           content=content,
                           categories=categories,
                           vip_plans=vip_plans,
                           status_options=['Draft', 'Published', 'Deleted'])


def new_article_back(user_id):
    article = None
    content = ""
    if request.method == 'POST':
        # 处理表单提交
        title = request.form.get('title')
        slug = request.form.get('slug')
        excerpt = request.form.get('excerpt')
        content = request.form.get('content')
        tags = request.form.get('tags')
        is_featured = True if request.form.get('is_featured') else False
        # status = request.form.get('status', 0)
        article_ad = request.form.get('article_ad')
        cover_image = request.form.get('cover_image')
        # 创建新文章
        new_article = Article(
            title=title,
            slug=slug,
            excerpt=excerpt,
            tags=tags,
            is_featured=is_featured,
            status=0,
            article_ad=article_ad,
            cover_image=cover_image,
            user_id=user_id
        )

        db.session.add(new_article)
        db.session.commit()
        article_content = ArticleContent(
            aid=new_article.article_id,
            content=content,
            language_code='zh-CN'
        )
        db.session.add(article_content)
        db.session.commit()
        flash('文章创建成功!', 'success')
        return redirect('/my/posts')

    return render_template('blog/edit.html',
                           article=article,
                           content=content,
                           status_options=['Draft', 'Published'])


def contribute_back(aid):
    if request.method == 'GET':
        # 获取现有翻译信息用于展示
        existing_translations = db.session.query(ArticleI18n.language_code).filter(
            ArticleI18n.article_id == aid
        ).all()
        existing_languages = [t.language_code for t in existing_translations]

        return render_template('blog/contribute.html',
                               aid=aid,
                               existing_languages=existing_languages,
                               valid_language_codes=sorted(valid_language_codes))

    if request.method == 'POST':
        # 确保请求是JSON格式
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Request must be JSON'}), 400

        data = request.get_json()

        # 处理表单提交
        contribute_type = data.get('contribute_type')
        contribute_content = data.get('contribute_content')
        contribute_language = data.get('contribute_language')
        contribute_title = data.get('contribute_title')
        contribute_slug = data.get('contribute_slug')

        # 验证必填字段
        if not all([contribute_type, contribute_content, contribute_language,
                    contribute_title, contribute_slug]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        # 处理slug
        contribute_slug = re.sub(r'[^\w\s-]', '', contribute_slug)  # 移除非字母数字和下划线的字符
        contribute_slug = re.sub(r'\s+', '_', contribute_slug)

        # 验证语言代码
        if not is_valid_iso_language_code(contribute_language):
            return jsonify({'success': False, 'message': 'Invalid language code'}), 400

        # 验证文章是否存在
        article = db.session.query(Article).filter(
            Article.article_id == aid,
            Article.status == 1
        ).first()
        if not article:
            return jsonify({'success': False, 'message': 'Article not found'}), 404

        # 检查是否已存在相同语言版本的翻译
        existing_i18n = ArticleI18n.query.filter_by(
            article_id=aid,
            language_code=contribute_language
        ).first()

        try:
            if existing_i18n:
                # 更新现有翻译
                existing_i18n.title = contribute_title
                existing_i18n.slug = contribute_slug
                existing_i18n.content = contribute_content
                existing_i18n.excerpt = contribute_content[:200]  # 简单截取作为摘要
                db.session.commit()
                return jsonify({
                    'success': True,
                    'message': 'Translation updated successfully',
                    'i18n_id': existing_i18n.i18n_id
                })
            else:
                # 创建新翻译
                new_i18n = ArticleI18n(
                    article_id=aid,
                    language_code=contribute_language,
                    title=contribute_title,
                    slug=contribute_slug,
                    content=contribute_content,
                    excerpt=contribute_content[:200]  # 简单截取作为摘要
                )
                db.session.add(new_i18n)
                db.session.commit()
                return jsonify({
                    'success': True,
                    'message': 'Translation submitted successfully',
                    'i18n_id': new_i18n.i18n_id
                })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

    return jsonify({'success': False, 'message': 'Invalid request method'}), 400


def blog_detail_aid_back(aid, safe_mode=True):
    try:
        article = db.session.query(Article).filter(
            Article.article_id == aid,
            Article.status == 1
        ).first()

        # print(article)

        if article:
            if safe_mode:
                # 仅在安全模式下检查是否隐藏
                if article.hidden:
                    return render_template('inform.html', aid=article.article_id)
            # 获取文章内容
            content = db.session.query(ArticleContent).filter_by(aid=article.article_id).first()
            print(content)

            # 获取多语言版本
            i18n_versions = db.session.query(ArticleI18n).filter_by(article_id=article.article_id).all()

            # 获取作者信息
            author = db.session.query(User).get(article.user_id)
            print(f'1. author: {author}')
            print(f'2. content: {content}')
            print(f'3. i18n: {i18n_versions}')

            return render_template('blog/detail.html',
                                   article=article,
                                   content=content,
                                   author=author,
                                   i18n_versions=i18n_versions,
                                   )
        return error(message='Article not found', status_code=404)
    except Exception as e:
        print(f"Template error: {str(e)}")
        return error(message=f'Internal server error: {str(e)}', status_code=500)


@blog_bp.route('/<int:aid>.html/<string:iso>/<string:slug_name>', methods=['GET', 'POST'])
def blog_detail_i18n_route(aid, iso, slug_name):
    if request.method == 'GET':
        return render_template('blog/i18n_detail.html', articleName=slug_name, url_for=url_for,
                               i18n_code=iso, aid=aid)
    return error(message='Invalid request', status_code=400)


def blog_detail_i18n_list(aid, i18n_code):
    if not is_valid_iso_language_code(i18n_code):
        return error(message='Invalid request', status_code=400)
    article = Article.query.filter_by(article_id=aid).first()
    if not article:
        return error(message='Article not found', status_code=404)
    if article.status != 1:
        return error(message='Article not published', status_code=403)
    article_i18n = ArticleI18n.query.filter_by(article_id=aid, language_code=i18n_code).all()
    if not article_i18n:
        return error(message=f'Article not found for language {i18n_code}', status_code=404)

    # 生成包含链接的HTML代码
    html_links = "<ul>"
    for i in article_i18n:
        link = f"/{aid}.html/{i18n_code}/{i.slug}"
        html_links += f"<li><a href='{link}'>{i.language_code}: {i.title}-{i.slug}</a></li>"
    html_links += "</ul>"

    return render_template('inform.html',
                           status_code=f"This article contains {len(article_i18n)} international translations.（{i18n_code}）",
                           message=html_links)


@blog_bp.route('/contribute', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
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
        return blog_detail_aid_back(aid=aid, safe_mode=False)


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
    from src.blueprints.api import api_user_profile
    user_info = api_user_profile(user_id=user_id)
    return setting_profiles_back(user_id, user_info, cache, current_app.config['AVATAR_SERVER'])


@blog_bp.route('/setting/profiles', methods=['PUT'])
@csrf.exempt
@jwt_required
@limiter.limit("10 per minute")
def change_profiles(user_id):
    # 使用 get_site_domain 函数获取域名
    domain = get_site_domain()
    return change_profiles_back(user_id, cache, domain)


@blog_bp.route('/space/<int:target_user_id>')
@jwt_required
def user_space(user_id, target_user_id):
    """用户空间页面 - 显示用户资料和文章"""
    # 检查会话是否有效
    from src.auth_utils import check_access_token
    access_token = request.cookies.get('access_token')
    if access_token and not check_access_token(access_token):
        from flask import flash
        flash("会话已过期，请重新登录", 'error')
        from flask import url_for
        return redirect(url_for('auth.logout'))
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

        return render_template('my/profile.html',
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


@jwt_required
@cache.cached(timeout=24 * 3600, key_prefix='site_slug')
def get_username(user_id):
    if user_id:
        return User.query.filter_by(id=user_id).first().username
    else:
        return '未登录'


def get_username_no_check():
    from flask_login import current_user
    if current_user.is_authenticated:
        return current_user.username
    else:
        return '未登录'


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
def get_self_defined_page(slug):
    """获取自定义页面"""
    page = Pages.query.filter_by(slug=f"{slug}.html").first()
    if not page:
        return jsonify({'success': False, 'data': '页面不存在'}), 404
    return page.content


def is_owner_or_vip(user_id, article):
    # 首先检查用户ID是否存在
    if user_id is None:
        return False, '此文为VIP专享，需要完成登录认证'

    # 验证是否为作者
    if auth_by_uid(article.article_id, user_id):
        return True, '您是作者，可以继续阅读'

    # 验证VIP权限
    try:
        user = db.session.query(User).get(user_id)
        if user is None:
            return False, '用户信息不存在，请重新登录'

        if user.vip_level >= article.required_vip_level:
            return True, f'您是尊贵的VIP{user.vip_level}，可以继续阅读'
        else:
            return False, f'此文需要VIP{article.required_vip_level}及以上等级才能阅读，您当前是VIP{user.vip_level}'
    except Exception as e:
        # 记录错误日志
        print(f"VIP权限验证失败: {e}")
        return False, '权限验证失败，请稍后重试'


def blog_detail_back(blog_slug, safe_mode=True):
    try:
        # 尝试作为文章slug查找
        article = db.session.query(Article).filter(
            Article.slug == blog_slug,
            Article.status == 1,
        ).first()

        print(f'0. {article}')

        if not article:
            return error(message='Article not found', status_code=404)

        if safe_mode:
            # 仅在安全模式下检查是否隐藏
            if article.hidden:
                return render_template('inform.html', aid=article.article_id)

            if article.is_vip_only:
                user_id = current_user.id
                result, message = is_owner_or_vip(article=article, user_id=user_id)
                if not result:
                    return render_template('inform.html', status_code=403, message=message)

        # 获取文章内容
        content = db.session.query(ArticleContent).filter_by(aid=article.article_id).first()
        if not content:
            return error(message='Content not found', status_code=404)

        # 获取多语言版本
        i18n_versions = db.session.query(ArticleI18n).filter_by(article_id=article.article_id).all()

        # 获取作者信息
        author = db.session.query(User).get(article.user_id)
        if not author:
            return render_template('inform.html', status_code=404, message='作者信息不存在')

        # print(f'1. author: {author}')
        # print(f'2. content: {content}')
        # print(f'3. i18n: {i18n_versions}')

        return render_template('blog/detail.html',
                               article=article,
                               content=content,
                               author=author,
                               i18n_versions=i18n_versions
                               )

    except Exception as e:
        print(f"博客详情页错误: {e}")


def blog_tmp_url(domain, cache_instance):
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
    if len(entered_password) < 4 or len(entered_password) > 128:
        return jsonify({"message": "Invalid Password"}), 400

    passwd = get_article_password(aid)
    if passwd is None:
        return jsonify({"message": "Authentication failed"}), 401

    if entered_password == passwd:
        cache_instance.set(f"temp-url_{view_uuid}", aid, timeout=900)
        temp_url = f'{domain}tmpView?url={view_uuid}'
        response_data['temp_url'] = temp_url
        return jsonify(response_data), 200
    else:
        referrer = request.referrer
        current_app.logger.error(f"{referrer} Failed access attempt {view_uuid}")
        return jsonify({"message": "Authentication failed"}), 401
