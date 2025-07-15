import urllib
from datetime import datetime

from flask import Blueprint, Response, request, render_template, redirect

from src.blog.article.core.content import get_article_content, get_article_last_modified, get_a_list
from src.blog.article.core.crud import read_hidden_articles
from src.database import get_db_connection
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
        db = None
        try:
            db = get_db_connection()
            with db.cursor() as cursor:
                query = """SELECT Title
                           FROM `articles`
                           WHERE `Hidden` = 0
                             AND `Status` = 'Published'
                           ORDER BY `article_id` DESC
                           LIMIT 40"""
                cursor.execute(query)
                results = cursor.fetchall()
                article_titles = [item[0] for item in results]

                xml_data = '<?xml version="1.0" encoding="UTF-8"?>\n'
                xml_data += '<urlset xmlns="https://www.sitemaps.org/schemas/sitemap/0.9">\n'

                for title in article_titles:
                    article_url = domain + 'blog/' + title
                    article_surl = api_shortlink(article_url)
                    date = get_article_last_modified(title)

                    xml_data += '<url>\n'
                    xml_data += f'\t<loc>{article_surl}</loc>\n'
                    xml_data += f'\t<lastmod>{date}</lastmod>\n'
                    xml_data += '\t<changefreq>Monthly</changefreq>\n'
                    xml_data += '\t<priority>0.8</priority>\n'
                    xml_data += '</url>\n'

                xml_data += '</urlset>\n'

                response = Response(xml_data, mimetype='text/xml')
                return response
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            if db is not None:
                db.close()

    @website_bp.route('/feed')
    @website_bp.route('/rss')
    @cache_instance.memoize(7200)
    def generate_rss():
        markdown_files = get_a_list(chanel=3, page=1)
        hidden_articles = read_hidden_articles()
        markdown_files = [file for file in markdown_files if file not in hidden_articles]

        xml_data = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_data += '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
        xml_data += '<channel>\n'
        xml_data += f'<title>{domain} RSS Feed </title>\n'
        xml_data += f'<link>{domain}rss</link>\n'
        xml_data += f'<description>{sitename} RSS Feed</description>\n'
        xml_data += '<language>en-us</language>\n'
        xml_data += f'<lastBuildDate>{datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")}</lastBuildDate>\n'
        xml_data += f'<atom:link href="{domain}rss" rel="self" type="application/rss+xml" />\n'

        for file in markdown_files:
            encoded_article_name = urllib.parse.quote(file)
            article_url = domain + 'blog/' + encoded_article_name
            article_surl = api_shortlink(article_url)
            date = get_article_last_modified(encoded_article_name)
            content, *_ = get_article_content(file, 10)
            describe = encoded_article_name

            xml_data += '<item>\n'
            xml_data += f'\t<title>{file}</title>\n'
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

    @website_bp.route('/changelog')
    def changelog():
        return redirect('https://athenavi.cn/blog/changelog')

    @website_bp.route('/links')
    def get_friends_link():
        return "区域还在建设中，敬请期待"

    return website_bp
