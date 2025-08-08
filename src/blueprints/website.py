from datetime import datetime

from flask import Blueprint, Response, request, render_template, redirect

from src.blog.article.core.content import get_article_titles, get_content
from src.utils.shortener.links import create_special_url, redirect_to_long_url

website_bp = Blueprint('website', __name__, template_folder='templates')


# 通过参数传递 Cache 实例
def create_website_blueprint(cache_instance, domain, sitename):
    @website_bp.route('/robots.txt')
    @cache_instance.cached(7200)
    def static_from_root():
        content = "User-agent: *\nDisallow: /admin"
        modified_content = content + '\nSitemap: ' + domain + 'sitemap.xml'

        response = Response(modified_content, mimetype='text/plain')
        return response

    @website_bp.route('/sitemap.xml')
    @website_bp.route('/sitemap')
    @cache_instance.memoize(7200)
    def generate_sitemap():
        articles, *_ = get_article_titles()
        xml_data = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'

        for title in articles:
            article_url = domain + 'blog/' + title
            article_surl = api_shortlink(article_url)
            *_, date = get_content(identifier=title, is_title=True)

            xml_data += '<url>\n'
            xml_data += f'\t<loc>{article_surl}</loc>\n'
            xml_data += f'\t<lastmod>{date}</lastmod>\n'
            xml_data += '\t<changefreq>Monthly</changefreq>\n'
            xml_data += '\t<priority>0.8</priority>\n'
            xml_data += '</url>\n'

        xml_data += '</urlset>\n'

        response = Response(xml_data, mimetype='text/xml')
        return response

    @website_bp.route('/feed')
    @website_bp.route('/rss')
    @cache_instance.memoize(7200)
    def generate_rss():
        markdown_files, *_ = get_article_titles()
        xml_data = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_data += '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
        xml_data += '<channel>\n'
        xml_data += f'<title>{domain} RSS Feed </title>\n'
        xml_data += f'<link>{domain}rss</link>\n'
        xml_data += f'<description>{sitename} RSS Feed</description>\n'
        xml_data += '<language>en-us</language>\n'
        xml_data += f'<lastBuildDate>{datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")}</lastBuildDate>\n'
        xml_data += f'<atom:link href="{domain}rss" rel="self" type="application/rss+xml" />\n'

        for title in markdown_files:
            article_url = domain + 'blog/' + title
            article_surl = api_shortlink(article_url)
            content, date = get_content(identifier=title, is_title=True)
            describe = title
            xml_data += '<item>\n'
            xml_data += f'\t<title>{title}</title>\n'
            xml_data += f'\t<link>{article_surl}</link>\n'
            xml_data += f'\t<guid>{article_url}</guid>\n'
            xml_data += f'\t<pubDate>{date}</pubDate>\n'
            xml_data += f'\t<description>{describe}</description>\n'
            xml_data += f'\t<content:encoded><![CDATA[{content}]]></content:encoded>'
            xml_data += '</item>\n'

        xml_data += '</channel>\n'
        xml_data += '</rss>\n'

        response = Response(xml_data, mimetype='application/rss+xml')
        return response

    @website_bp.route('/jump', methods=['GET', 'POST'])
    def jump():
        url = request.args.get('url', default=domain)
        return render_template('inform.html', url=url, domain=domain)

    @website_bp.route('/api/shortlink')
    def api_shortlink(long_url):
        if not long_url.startswith('https://') and not long_url.startswith('http://'):
            return 'error'
        short_url = create_special_url(long_url, user_id=1)
        article_surl = domain + 's/' + short_url
        return article_surl

    @cache_instance.cached(timeout=24 * 3600, key_prefix='short_link')
    @website_bp.route('/s/<short_url>', methods=['GET', 'POST'])
    def redirect_to_long_url_route(short_url):
        if len(short_url) != 6:
            return 'error'
        long_url = redirect_to_long_url(short_url)
        if long_url:
            return redirect(long_url, code=302)
        else:
            return "短网址无效"

    @website_bp.route('/guestbook', methods=['GET', 'POST'])
    def guestbook():
        return '当前功能暂未开放！'

    @website_bp.route('/message')
    def message_page():
        return render_template('message.html')

    @website_bp.route('/links')
    def get_friends_link():
        return "区域还在建设中，敬请期待"

    return website_bp
