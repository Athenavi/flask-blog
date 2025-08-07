import os

from flask import request, render_template, url_for

from src.blog.article.core.crud import post_blog_detail, get_blog_name
from src.blog.tag import query_article_tags
from src.error import error


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


def blog_detail_back(blog_name):
    if request.method == 'POST':
        return post_blog_detail(blog_name)
    if request.method == 'GET':
        aid, article_tags = query_article_tags(blog_name)
        i18n_code = request.args.get('i18n') or None
        i18n_name = get_blog_name(aid=aid, i18n_code=i18n_code)
        if i18n_name:
            blog_name = i18n_name
        return render_template('zyDetail.html', articleName=blog_name, url_for=url_for,
                               article_tags=article_tags, i18n_code=i18n_code, aid=aid)
    return error(message='Invalid request', status_code=400)