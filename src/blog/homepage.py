import hashlib
from datetime import datetime

from flask import render_template, request, make_response, current_app

from src.database import get_db
from src.error import error
from src.models import Article, Category
from src.utils.config.theme import get_all_themes


def proces_page_data(total_articles, article_info, current_page, page_size, theme='default'):
    """
    处理分页数据并生成HTML内容和ETag
    """
    try:
        # 计算总页数
        total_pages = (total_articles + page_size - 1) // page_size

        # 准备分页数据
        pagination_data = {
            'current_page': current_page,
            'total_pages': total_pages,
            'has_prev': current_page > 1,
            'has_next': current_page < total_pages,
            'prev_page': current_page - 1 if current_page > 1 else None,
            'next_page': current_page + 1 if current_page < total_pages else None,
        }

        # 处理文章数据
        articles = [{
            'article_id': article[0],
            'title': article[1],
            'user_id': article[2],
            'views': article[3],
            'likes': article[4],
            'cover_image': article[5],
            'category_id': article[6],
            'excerpt': article[7],
            'is_featured': article[8],
            'tags': article[9].split(',') if article[9] else [],
            'slug': article[10]
        } for article in article_info]

        all_appearance = get_all_themes()
        if theme in all_appearance:
            html_content = render_template(
                f'theme/{theme}/index.html',
                articles=articles,
                pagination=pagination_data,
            )
        else:
            # 渲染模板
            html_content = render_template(
                'index.html',
                articles=articles,
                pagination=pagination_data,
                total_articles=total_articles
            )

        # 生成ETag
        content_hash = hashlib.md5(html_content.encode()).hexdigest()
        etag = f"{content_hash}-{int(datetime.now().timestamp())}"

        return html_content, etag

    except Exception as e:
        current_app.logger.error(f"Error processing page data: {e}")
        return error("获取文章时发生错误。", status_code=500)


def get_articles_with_filters(filters, page, page_size):
    """
    通用函数：根据提供的过滤器获取文章
    """
    try:
        with get_db() as session:
            # 基本查询
            query = session.query(
                Article.article_id,
                Article.title,
                Article.user_id,
                Article.views,
                Article.likes,
                Article.cover_image,
                Article.category_id,
                Article.excerpt,
                Article.is_featured,
                Article.tags,
                Article.slug,
            ).outerjoin(Category, Article.category_id == Category.id).filter(
                Article.hidden == False,
                Article.status == 'Published',
                Article.is_vip_only == False,
            )

            # 添加额外过滤器
            for filter_cond in filters:
                query = query.filter(filter_cond)

            # 获取当前页的文章
            articles = query.order_by(
                Article.article_id.desc()
            ).limit(page_size).offset((page - 1) * page_size).all()

            # 获取总文章数
            count_query = session.query(Article).filter(
                Article.hidden == False,
                Article.status == 'Published'
            )
            for filter_cond in filters:
                count_query = count_query.filter(filter_cond)

            total_articles = count_query.count()

            return [tuple(article) for article in articles], total_articles

    except Exception as e:
        current_app.logger.error(f"Database error: {e}")
        raise


def create_response(html_content, etag):
    """创建带有ETag和缓存头的响应"""
    response = make_response(html_content)
    response.set_etag(etag)
    response.headers['Cache-Control'] = 'public, max-age=180'
    return response


def index_page_back():
    page = max(request.args.get('page', 1, type=int), 1)
    page_size = 45
    theme = request.cookies.get('site-theme') or 'default'
    try:
        article_info, total_articles = get_articles_with_filters([], page, page_size)
        html_content, etag = proces_page_data(total_articles, article_info, page, page_size, theme)
        return create_response(html_content, etag)
    except Exception as e:
        return error(str(e), 500)


def tag_page_back(tag_name, encoding):
    if len(tag_name.encode(encoding)) > 10:
        return error("Tag 名称不能超过 10 字节。", status_code=400)

    page = max(request.args.get('page', 1, type=int), 1)
    page_size = 45

    try:
        article_info, total_articles = get_articles_with_filters(
            [Article.tags.like(f'%{tag_name}%')], page, page_size
        )
        html_content, etag = proces_page_data(total_articles, article_info, page, page_size)
        return create_response(html_content, etag)
    except Exception as e:
        current_app.logger.error(f"Error in tag_page_back: {e}")
        return error("获取文章时发生错误。", status_code=500)


def featured_page_back():
    page = max(request.args.get('page', 1, type=int), 1)
    page_size = 45

    try:
        article_info, total_articles = get_articles_with_filters(
            [Article.is_featured == True], page, page_size
        )
        html_content, etag = proces_page_data(total_articles, article_info, page, page_size)
        return create_response(html_content, etag)
    except Exception as e:
        current_app.logger.error(f"Error in featured_page_back: {e}")
        return error("获取文章时发生错误。", status_code=500)
