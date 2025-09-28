import re

from flask import request, render_template, url_for, jsonify, current_app, flash, redirect

from src.blog.article.security.password import get_article_password
from src.database import get_db
from src.error import error
from src.models import Article, ArticleContent, ArticleI18n, User, db, Category, VIPPlan
from src.user.authz.decorators import get_current_user_id
from src.user.entities import auth_by_uid
from src.utils.security.safe import random_string, is_valid_iso_language_code, valid_language_codes


def is_owner_or_vip(user_id, article):
    # 首先检查用户ID是否存在
    if user_id is None:
        return False, '此文为VIP专享，需要完成登录认证'

    # 验证是否为作者
    if auth_by_uid(article.article_id, user_id):
        return True, '您是作者，可以继续阅读'

    # 验证VIP权限
    try:
        with get_db() as db:
            user = db.query(User).get(user_id)
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


def blog_detail_back(blog_slug, safeMode=True):
    try:
        with get_db() as db:
            # 尝试作为文章slug查找
            article = db.query(Article).filter(
                Article.slug == blog_slug,
                Article.status == 'Published',
            ).first()

            print(f'0. {article}')

            if not article:
                return error(message='Article not found', status_code=404)

            if safeMode:
                # 仅在安全模式下检查是否隐藏
                if article.hidden:
                    return render_template('inform.html', aid=article.article_id)

                if article.is_vip_only:
                    user_id = get_current_user_id()
                    result, message = is_owner_or_vip(article=article, user_id=user_id)
                    if not result:
                        return render_template('inform.html', status_code=403, message=message)

            # 获取文章内容
            content = db.query(ArticleContent).filter_by(aid=article.article_id).first()
            if not content:
                return error(message='Content not found', status_code=404)

            # 获取多语言版本
            i18n_versions = db.query(ArticleI18n).filter_by(article_id=article.article_id).all()

            # 获取作者信息
            author = db.query(User).get(article.user_id)
            if not author:
                return render_template('inform.html', status_code=404, message='作者信息不存在')

            print(f'1. author: {author}')
            print(f'2. content: {content}')
            print(f'3. i18n: {i18n_versions}')

            return render_template('blog_detail.html',
                                   article=article,
                                   content=content,
                                   author=author,
                                   i18n_versions=i18n_versions
                                   )

    except Exception as e:
        print(f"博客详情页错误: {e}")


def blog_detail_i18n(aid, blog_slug, i18n_code):
    if request.method == 'GET':
        return render_template('zyDetail.html', articleName=blog_slug, url_for=url_for,
                               i18n_code=i18n_code, aid=aid)
    return error(message='Invalid request', status_code=400)


def blog_detail_i18n_list(aid, i18n_code):
    if not is_valid_iso_language_code(i18n_code):
        return error(message='Invalid request', status_code=400)
    article = Article.query.filter_by(article_id=aid).first()
    if not article:
        return error(message='Article not found', status_code=404)
    if article.status != 'Published':
        return error(message='Article not published', status_code=403)
    articleI18n = ArticleI18n.query.filter_by(article_id=aid, language_code=i18n_code).all()
    if not articleI18n:
        return error(message=f'Article not found for language {i18n_code}', status_code=404)

    # 生成包含链接的HTML代码
    html_links = "<ul>"
    for i in articleI18n:
        link = f"/{aid}.html/{i18n_code}/{i.slug}"
        html_links += f"<li><a href='{link}'>{i.language_code}: {i.title}-{i.slug}</a></li>"
    html_links += "</ul>"

    return render_template('inform.html',
                           status_code=f"This article contains {len(articleI18n)} international translations.（{i18n_code}）",
                           message=html_links)


def contribute_back(aid):
    with get_db() as db:
        if request.method == 'GET':
            # 获取现有翻译信息用于展示
            existing_translations = db.query(ArticleI18n.language_code).filter(
                ArticleI18n.article_id == aid
            ).all()
            existing_languages = [t.language_code for t in existing_translations]

            return render_template('contribute.html',
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
            contribute_slug = re.sub(r'[^\w\s]', '', contribute_slug)  # 移除非字母数字和下划线的字符
            contribute_slug = re.sub(r'\s+', '_', contribute_slug)

            # 验证语言代码
            if not is_valid_iso_language_code(contribute_language):
                return jsonify({'success': False, 'message': 'Invalid language code'}), 400

            # 验证文章是否存在
            article = db.query(Article).filter(
                Article.article_id == aid,
                Article.status == 'Published'
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
                    db.add(new_i18n)
                    return jsonify({
                        'success': True,
                        'message': 'Translation submitted successfully',
                        'i18n_id': new_i18n.i18n_id
                    })
            except Exception as e:
                db.rollback()
                return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

        return jsonify({'success': False, 'message': 'Invalid request method'}), 400


def blog_detail_aid_back(aid, safeMode=True):
    with get_db() as db:
        try:
            article = db.query(Article).filter(
                Article.article_id == aid,
                Article.status == 'Published'
            ).first()

            print(article)

            if article:
                if safeMode:
                    # 仅在安全模式下检查是否隐藏
                    if article.hidden:
                        return render_template('inform.html', aid=article.article_id)
                # 获取文章内容
                content = db.query(ArticleContent).filter_by(aid=article.article_id).first()
                print(content)

                # 获取多语言版本
                i18n_versions = db.query(ArticleI18n).filter_by(article_id=article.article_id).all()

                # 获取作者信息
                author = db.query(User).get(article.user_id)
                print(f'1. author: {author}')
                print(f'2. content: {content}')
                print(f'3. i18n: {i18n_versions}')

                return render_template('blog_detail.html',
                                       article=article,
                                       content=content,
                                       author=author,
                                       i18n_versions=i18n_versions,
                                       )
            return None
        except Exception as e:
            print(f"Template error: {str(e)}")
            return str(e), 500


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


def edit_article_back(user_id, article_id):
    auth = auth_by_uid(article_id, user_id)
    if not auth:
        return jsonify({"message": "Authentication failed"}), 401

    article = Article.query.get_or_404(article_id)
    content_obj = ArticleContent.query.filter_by(aid=article_id).first()
    content = content_obj.content if content_obj else ""
    categories = Category.query.all()
    vip_plans = VIPPlan.query.all()

    if request.method == 'POST':

        try:
            # 更新文章基本信息
            print(request.form)
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
            return render_template('article_edit.html',
                                   article=article,
                                   content=content,
                                   categories=categories,
                                   status_options=['Draft', 'Published', 'Deleted'])

        return redirect(url_for('other.markdown_editor', aid=article_id))

    return render_template('article_edit.html',
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
        status = request.form.get('status', 'Draft')
        article_ad = request.form.get('article_ad')
        cover_image = request.form.get('cover_image')
        # 创建新文章
        new_article = Article(
            title=title,
            slug=slug,
            excerpt=excerpt,
            tags=tags,
            is_featured=is_featured,
            status=status,
            article_ad=article_ad,
            cover_image=cover_image,
            user_id=user_id
        )
        with get_db() as db:
            db.add(new_article)
            db.commit()
            article_content = ArticleContent(
                aid=new_article.article_id,
                content=content,
                language_code='zh-CN'
            )
            db.add(article_content)
            db.commit()
            flash('文章创建成功!', 'success')
            return redirect('/my/posts')

    return render_template('article_edit.html',
                           article=article,
                           content=content,
                           status_options=['Draft', 'Published'])
