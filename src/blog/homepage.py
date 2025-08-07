from flask import request, make_response, current_app, render_template
from jinja2 import TemplateNotFound

from src.blog.article.core.crud import fetch_articles
from src.config.theme import db_get_theme
from src.error import error
from src.utils.http.etag import generate_etag


def proces_page_data(total_articles, article_info, page, total_pages):
    current_theme = db_get_theme()
    template_rel_path = f'theme/{current_theme}/index.html' if current_theme != 'default' else 'index.html'

    try:
        loader = current_app.jinja_loader
        loader.get_source(current_app.jinja_env, template_rel_path)
    except TemplateNotFound:
        # cache_instance.set('display_theme', 'default')
        template_rel_path = 'index.html'

    # 使用 current_app 的渲染能力（通过 flask.render_template）
    html_content = render_template(template_rel_path,
                                   article_info=article_info,
                                   page=page,
                                   total_pages=total_pages)
    etag = generate_etag(total_articles, article_info, page, current_theme)
    return html_content, etag


def index_page_back():
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


def tag_page_back(tag_name, encoding):
    if len(tag_name.encode(encoding)) > 10:
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
        current_app.logger.error(f"值错误: {e}")
        return error("参数传递错误。", status_code=400)
    except Exception as e:
        current_app.logger.error(f"未知错误: {e}")
        return error("获取文章时发生未知错误。", status_code=500)

    html_content, etag = proces_page_data(total_articles, article_info, page, total_pages)

    # 设置响应头
    response = make_response(html_content)
    response.set_etag(etag)
    response.headers['Cache-Control'] = 'public, max-age=180'
    return response


def featured_page_back():
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
        current_app.logger.error(f"值错误: {e}")
        return error("参数传递错误。", status_code=400)
    except Exception as e:
        current_app.logger.error(f"未知错误: {e}")
        return error("获取文章时发生未知错误。", status_code=500)
    html_content, etag = proces_page_data(total_articles, article_info, page, total_pages)
    response = make_response(html_content)
    response.set_etag(etag)
    response.headers['Cache-Control'] = 'public, max-age=180'
    return response
