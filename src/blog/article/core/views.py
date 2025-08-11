import os
from datetime import datetime, timezone

from flask import request, render_template, url_for, jsonify, current_app, flash, redirect

from src.blog.article.core.crud import get_blog_name
from src.blog.article.security.password import get_article_password
from src.blog.tag import query_article_tags
from src.error import error
from src.user.entities import auth_by_uid
from src.utils.security.safe import random_string


def blog_preview_back(base_dir, domain):
    user = request.args.get('user')
    file_name = request.args.get('file_name')
    prev_file_path = os.path.join(base_dir, 'media', str(user), file_name)
    if not os.path.exists(prev_file_path):
        return error(message=f'{file_name}不存在', status_code=404)
    else:
        # app.logger.info(f'{user_id} preview: {file_name}')
        return render_template('zyDetail.html', article_content=1,
                               articleName=f"prev_{file_name}", domain=domain,
                               url_for=url_for, article_Surl='-')


def blog_list_back(blog_name, aid):
    if request.method == 'GET':
        aid, article_tags = query_article_tags(blog_name)
        i18n_code = request.args.get('i18n') or None
        i18n_name = get_blog_name(aid=aid, i18n_code=i18n_code)
        if i18n_name:
            blog_name = i18n_name
        return render_template('zyDetail.html', articleName=blog_name, url_for=url_for,
                               article_tags=article_tags, i18n_code=i18n_code, aid=aid)
    return error(message='Invalid request', status_code=400)


from src.models import db, Article, ArticleContent, ArticleI18n, User


def blog_detail_back(blog_slug):
    # 尝试作为文章slug查找
    article = db.session.query(Article).filter(
        Article.slug == blog_slug,
        Article.status == 'Published'
    ).first()

    print(article)

    if article:
        # 获取文章内容
        content = db.session.query(ArticleContent).filter_by(aid=article.article_id).first()

        # 获取多语言版本
        i18n_versions = db.session.query(ArticleI18n).filter_by(article_id=article.article_id).all()

        # 获取作者信息
        author = db.session.query(User).get(article.user_id)
        print(author)
        return render_template('blog_detail.html',
                               article=article,
                               content=content,
                               author=author,
                               i18n_versions=i18n_versions
                               )
    return None


def blog_detail_i18n(aid, blog_slug, i18n_code):
    if request.method == 'GET':
        return render_template('zyDetail.html', articleName=blog_slug, url_for=url_for,
                               i18n_code=i18n_code, aid=aid)
    return error(message='Invalid request', status_code=400)


def blog_detail_aid_back(aid):
    # 尝试作为 文章id 查找
    article = db.session.query(Article).filter(
        Article.article_id == aid,
        Article.status == 'Published'
    ).first()

    print(article)

    if article:
        # 获取文章内容
        content = db.session.query(ArticleContent).filter_by(aid=article.article_id).first()
        print(content)

        # 获取多语言版本
        i18n_versions = db.session.query(ArticleI18n).filter_by(article_id=article.article_id).all()

        # 获取作者信息
        author = db.session.query(User).get(article.user_id)
        print(author)
        return render_template('blog_detail.html',
                               article=article,
                               content=content,
                               author=author,
                               i18n_versions=i18n_versions
                               )
    return None


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
    if len(entered_password) != 4:
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

    if request.method == 'POST':
        # 更新文章信息
        article.title = request.form.get('title')
        article.slug = request.form.get('slug')
        article.excerpt = request.form.get('excerpt')
        article.tags = request.form.get('tags')
        article.hidden = 1 if request.form.get('hidden') else 0
        article.status = request.form.get('status')
        article.article_type = request.form.get('article_type')
        article.cover_image = request.form.get('cover_image')

        # 更新内容
        if content_obj:
            content_obj.content = request.form.get('content')
        else:
            content_obj = ArticleContent(
                aid=article_id,
                content=request.form.get('content'),
                language_code='zh-CN'
            )
            db.session.add(content_obj)

        db.session.commit()
        # flash('update success!', 'success')
        return redirect(url_for('edit_article', article_id=article_id))

    return render_template('article_edit.html',
                           article=article,
                           content=content,
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
        article_type = request.form.get('article_type')
        cover_image = request.form.get('cover_image')

        # 创建新文章
        new_article = Article(
            title=title,
            slug=slug,
            excerpt=excerpt,
            tags=tags,
            is_featured=is_featured,
            status=status,
            article_type=article_type,
            cover_image=cover_image,
            user_id=user_id
        )

        db.session.add(new_article)
        db.session.commit()

        # 创建内容
        article_content = ArticleContent(
            aid=new_article.article_id,
            content=content,
            language_code='zh-CN'
        )
        db.session.add(article_content)
        db.session.commit()

        flash('文章创建成功!', 'success')
        return redirect(url_for('edit_article', article_id=new_article.article_id))

    return render_template('article_edit.html',
                           article=article,
                           content=content,
                           status_options=['Draft', 'Published'])
