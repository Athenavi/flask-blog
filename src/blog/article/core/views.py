import os

import markdown
from flask import request, render_template, url_for, jsonify, current_app

from src.blog.article.core.crud import get_blog_name
from src.blog.article.security.password import get_article_password
from src.blog.tag import query_article_tags
from src.error import error
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
