import os
import re
import time
from xml.etree import ElementTree as ET

from flask import request, render_template

from src.database import get_db
from src.models import Article, ArticleContent


def search_handler(user_id, domain, global_encoding, max_cache_timestamp):
    matched_content = []

    def strip_html_tags(text):
        """去除HTML标签"""
        if text is None:
            return ''
        return re.sub('<[^<]+?>', '', text)

    if request.method == 'POST':
        with get_db() as db:
            keyword = request.form.get('keyword')  # 获取搜索关键词
            cache_dir = os.path.join('temp', 'search')
            os.makedirs(cache_dir, exist_ok=True)
            cache_path = os.path.join(cache_dir, keyword + '.xml')

            # 检查缓存是否失效
            if os.path.isfile(cache_path) and (
                    time.time() - os.path.getmtime(cache_path) < max_cache_timestamp):
                # 读取缓存并继续处理
                with open(cache_path, 'r', encoding=global_encoding) as cache_file:
                    match_data = cache_file.read()
            else:
                # 查询公开的文章（只索引已发布、非隐藏的文章）
                articles = db.query(Article, ArticleContent).join(
                    ArticleContent, Article.article_id == ArticleContent.aid
                ).filter(
                    Article.status == 1,
                    Article.hidden == False
                ).all()

                # 创建XML根元素
                root = ET.Element('rss')
                root.set('version', '2.0')

                # 为每个匹配的文章创建XML条目
                for article, content in articles:
                    # 检查文章是否包含关键词（在标题或内容中）
                    if (keyword.lower() in article.title.lower() or
                            keyword.lower() in strip_html_tags(content.content).lower()):
                        item = ET.SubElement(root, 'item')

                        title_elem = ET.SubElement(item, 'title')
                        title_elem.text = article.title

                        link_elem = ET.SubElement(item, 'link')
                        link_elem.text = f"{domain}p/{article.slug}"

                        pubDate_elem = ET.SubElement(item, 'pubDate')
                        pubDate_elem.text = article.created_at.strftime('%a, %d %b %Y %H:%M:%S GMT')

                        description_elem = ET.SubElement(item, 'description')
                        # 使用摘要或截取的内容前200字符
                        desc_text = article.excerpt if article.excerpt else strip_html_tags(content.content)[
                                                                                :200] + '...'
                        description_elem.text = desc_text

                # 创建XML树并写入缓存
                tree = ET.ElementTree(root)
                match_data = ET.tostring(tree.getroot(), encoding="unicode", method='xml')

                with open(cache_path, 'w', encoding=global_encoding) as cache_file:
                    cache_file.write(match_data)

        # 解析XML数据
        parsed_data = ET.fromstring(match_data)
        for item in parsed_data.findall('item'):
            content = {
                'title': item.find('title').text,
                'link': item.find('link').text,
                'pubDate': item.find('pubDate').text,
                'description': item.find('description').text
            }
            matched_content.append(content)

    return render_template('search.html', results=matched_content)
