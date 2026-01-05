"""
SEO相关路由处理
包含sitemap.xml和robots.txt等
"""
from flask import Blueprint, Response, request

from src.models import SystemSettings
from src.utils.seo import generate_sitemap

seo_bp = Blueprint('seo', __name__, url_prefix='')


@seo_bp.route('/sitemap.xml')
def sitemap():
    """生成sitemap.xml"""
    sitemap_content = generate_sitemap()
    return Response(sitemap_content, mimetype='application/xml')


@seo_bp.route('/robots.txt')
def robots_txt():
    """生成robots.txt"""
    # 获取网站域名
    domain_setting = SystemSettings.query.filter_by(key='site_domain').first()
    domain = domain_setting.value if domain_setting else request.host_url.rstrip('/')
    
    robots_content = f"""User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/
Disallow: /debug/
Disallow: /user/
Disallow: /tmpView

Sitemap: {domain}/sitemap.xml"""
    
    return Response(robots_content, mimetype='text/plain')


def get_optimized_article_url(article):
    """
    生成优化的URL
    """
    if article.slug:
        return f"/p/{article.slug}"
    else:
        return f"/{article.article_id}.html"


def get_optimized_category_url(category):
    """
    生成优化的分类URL
    """
    return f"/category/{category.name}"


def get_optimized_tag_url(tag):
    """
    生成优化的标签URL
    """
    return f"/tag/{tag}"