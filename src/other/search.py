import os
import time
import xml.etree.ElementTree as ElementTree

from flask import request, render_template

from src.blog.article.core.content import get_article_titles, get_content
from src.utils.security.safe import clean_html_format

from datetime import datetime


def search_handler(user_id, domain, global_encoding, max_cache_timestamp):
    matched_content = []

    if request.method == 'POST':
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
            markdown_files, *_ = get_article_titles()
            root = ElementTree.Element('root')

            for title in markdown_files:
                article_url = domain + 'blog/' + title
                describe, date = get_content(identifier=title, is_title=True, limit=50)
                describe = clean_html_format(describe)

                # 将 datetime 对象转换为字符串
                if isinstance(date, datetime):
                    date = date.strftime('%Y-%m-%dT%H:%M:%SZ')

                if keyword.lower() in title.lower() or keyword.lower() in describe.lower():
                    item = ElementTree.SubElement(root, 'item')
                    ElementTree.SubElement(item, 'title').text = title
                    ElementTree.SubElement(item, 'link').text = article_url
                    ElementTree.SubElement(item, 'pubDate').text = date
                    ElementTree.SubElement(item, 'description').text = describe

            # 创建XML树并写入缓存
            tree = ElementTree.ElementTree(root)
            match_data = ElementTree.tostring(tree.getroot(), encoding="unicode", method='xml')

            with open(cache_path, 'w', encoding=global_encoding) as cache_file:
                cache_file.write(match_data)

        # 解析XML数据
        parsed_data = ElementTree.fromstring(match_data)
        for item in parsed_data.findall('item'):
            content = {
                'title': item.find('title').text,
                'link': item.find('link').text,
                'pubDate': item.find('pubDate').text,
                'description': item.find('description').text
            }
            matched_content.append(content)

    return render_template('search.html', results=matched_content)
