import os
import re
import time
from xml.etree import ElementTree as ET

from flask import request, render_template

from src.database import get_db
from src.models import Article, ArticleContent, SearchHistory, db


def saveSearchHistory(user_id, keyword, results_count):
    """保存搜索历史"""
    new_search_history = SearchHistory(user_id=user_id, keyword=keyword, results_count=results_count)
    db.session.add(new_search_history)
    db.session.commit()


def getUserSearchHisotry(user_id):
    history_keywords = db.session.query(SearchHistory.keyword).filter(SearchHistory.user_id == user_id).order_by(
        SearchHistory.created_at.desc()).all()
    # 使用集合去重
    unique_keywords = set(keyword[0] for keyword in history_keywords)
    # 将集合转换为列表
    return list(unique_keywords)


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
            # 对关键词进行转义，替换特殊字符
            safe_keyword = re.sub(r'[\\/*?:"<>|]', '', keyword)
            cache_dir = os.path.join('temp', 'search')
            os.makedirs(cache_dir, exist_ok=True)
            cache_path = os.path.join(cache_dir, safe_keyword + '.xml')

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
            if item:
                saveSearchHistory(user_id, keyword, len(matched_content) or 0)
    history_list = getUserSearchHisotry(user_id)
    return render_template('search.html', historyList=history_list, results=matched_content)
