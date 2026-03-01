"""
SEO优化工具模块
包含sitemap生成、meta标签优化等功能
"""
from datetime import datetime

from flask import request

from src.models import Article, Category, User


def generate_sitemap():
    """
    生成sitemap.xml内容
    """
    from src.models import SystemSettings
    
    # 获取网站域名
    domain_setting = SystemSettings.query.filter_by(key='site_domain').first()
    domain = domain_setting.value if domain_setting else request.host_url.rstrip('/')
    
    # 开始构建sitemap
    sitemap = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
        'xmlns:xhtml="http://www.w3.org/1999/xhtml">',
        f'  <url><loc>{domain}/</loc><lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod><priority>1.00</priority></url>'
    ]
    
    # 添加主页
    sitemap.append(f'  <url><loc>{domain}/</loc><lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod><priority>1.00</priority></url>')
    
    # 添加分类页面
    categories = Category.query.all()
    for category in categories:
        sitemap.append(f'  <url><loc>{domain}/category/{category.name}</loc><lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod><priority>0.80</priority></url>')
    
    # 添加标签页面
    # 获取所有唯一标签
    all_articles = Article.query.filter_by(status=1, hidden=0).all()
    tags_set = set()
    for article in all_articles:
        if article.tags:
            for tag in article.tags.split(','):
                tag = tag.strip()
                if tag:
                    tags_set.add(tag)
    
    for tag in tags_set:
        sitemap.append(f'  <url><loc>{domain}/tag/{tag}</loc><lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod><priority>0.70</priority></url>')
    
    # 添加文章页面
    articles = Article.query.filter_by(status=1, hidden=0).all()
    for article in articles:
        sitemap.append(f'  <url><loc>{domain}/p/{article.slug}</loc><lastmod>{article.updated_at.strftime("%Y-%m-%d") if article.updated_at else article.created_at.strftime("%Y-%m-%d")}</lastmod><priority>0.90</priority></url>')
    
    # 添加用户空间页面
    users = User.query.all()
    for user in users:
        sitemap.append(f'  <url><loc>{domain}/space/{user.id}</loc><lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod><priority>0.60</priority></url>')
    
    # 添加其他重要页面
    other_pages = [
        ('/login', '0.50'),
        ('/register', '0.50'),
        ('/search', '0.70'),
        ('/featured', '0.70'),
    ]
    
    for page_url, priority in other_pages:
        sitemap.append(f'  <url><loc>{domain}{page_url}</loc><lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod><priority>{priority}</priority></url>')
    
    sitemap.append('</urlset>')
    
    return '\n'.join(sitemap)


def get_article_meta_tags(article, content=None, author=None):
    """
    为文章页面生成meta标签
    """
    title = article.title
    description = article.excerpt if article.excerpt else (content.content[:150] if content and content.content else f"阅读关于{article.title}的文章")
    author_name = author.username if author else "未知作者"
    cover_image = article.cover_image if article.cover_image else ""
    
    meta_tags = {
        'title': f"{title} - {request.endpoint.split('.')[0] if request.endpoint and '.' in request.endpoint else '博客'}",
        'description': description,
        'keywords': article.tags.replace(',', ', ') if article.tags else title,
        'author': author_name,
        'og:title': title,
        'og:description': description,
        'og:type': 'article',
        'og:url': f"{request.host_url}p/{article.slug}",
        'og:image': cover_image if cover_image else f"{request.host_url}static/images/default-cover.jpg",
        'article:author': author_name,
        'article:published_time': article.created_at.isoformat() if article.created_at else datetime.now().isoformat(),
        'article:modified_time': article.updated_at.isoformat() if article.updated_at else article.created_at.isoformat(),
        'article:section': article.category.name if article.category else '未分类',
        'twitter:card': 'summary_large_image',
        'twitter:title': title,
        'twitter:description': description,
        'twitter:image': cover_image if cover_image else f"{request.host_url}static/images/default-cover.jpg",
    }
    
    return meta_tags


def get_page_meta_tags(title, description="", keywords="", page_type="website"):
    """
    为普通页面生成meta标签
    """
    meta_tags = {
        'title': title,
        'description': description,
        'keywords': keywords,
        'og:title': title,
        'og:description': description,
        'og:type': page_type,
        'og:url': request.url,
        'og:site_name': request.endpoint.split('.')[0] if request.endpoint and '.' in request.endpoint else '博客',
        'twitter:card': 'summary',
        'twitter:title': title,
        'twitter:description': description,
    }
    
    return meta_tags


def slugify(text):
    """
    将文本转换为URL友好的slug格式
    """
    import re
    # 转换为小写
    text = text.lower()
    # 替换空格和特殊字符为连字符
    text = re.sub(r'[^a-z0-9\u4e00-\u9fa5\-\s]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text.strip('-')


def generate_seo_friendly_url(title, model_type='article', id_value=None):
    """
    生成SEO友好的URL
    """
    slug = slugify(title)
    if model_type == 'article':
        return f"/p/{slug}" if slug else f"/{id_value}.html" if id_value else f"/article.html"
    elif model_type == 'category':
        return f"/category/{slug}" if slug else f"/category/{id_value}" if id_value else "/category" 
    elif model_type == 'tag':
        return f"/tag/{slug}" if slug else f"/tag/{id_value}" if id_value else "/tag"
    else:
        return f"/{slug}"