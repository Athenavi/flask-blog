import codecs
import datetime
import html
import os
import re
import urllib
from pathlib import Path

import markdown

from src.database import get_db_connection
from src.error import error
from src.utils.security.safe import clean_html_format


def get_a_list(chanel=1, page=1):
    if chanel == 1:
        articles, has_next_page, has_previous_page = get_article_titles(page=1, per_page=99999)
        return articles
    if chanel == 2:
        articles, has_next_page, has_previous_page = get_article_titles(page=page, per_page=12)
        return articles, has_next_page, has_previous_page
    if chanel == 3:
        # rss页面
        articles, has_next_page, has_previous_page = get_article_titles(page=1, per_page=30)
        return articles


def delete_article(article_name, temp_folder):
    # 确保 temp_folder 是 Path 对象
    temp_folder = Path(temp_folder)

    # 构建文件路径
    draft_file_path = temp_folder / f"{article_name}.md"
    published_file_path = Path('articles') / f"{article_name}.md"

    # 删除草稿文件
    if draft_file_path.is_file():
        os.remove(draft_file_path)

    # 删除已发布文件
    if published_file_path.exists():
        os.remove(published_file_path)

    return True


def get_article_titles(per_page, page=1):
    articles = []
    files = os.listdir('articles')
    markdown_files = [file for file in files if file.endswith('.md')]

    # 根据修改日期对markdown_files进行逆序排序
    markdown_files = sorted(markdown_files, key=lambda f: datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(
        'articles', f))), reverse=True)

    start_index = (page - 1) * per_page
    end_index = start_index + per_page

    for file in markdown_files[start_index:end_index]:
        article_name = file[:-3]  # 去除文件扩展名(.md)
        articles.append(article_name)

    # 检查每篇文章是否在hidden.txt中，并在必要时将其移除
    # hidden_articles = read_hidden_articles()
    # articles = [article for article in articles if article not in hidden_articles]

    # 移除文章名称列表中以下划线开头的文章
    articles = [article for article in articles if not article.startswith('_')]

    has_next_page = end_index < len(markdown_files)
    has_previous_page = start_index > 0

    return articles, has_next_page, has_previous_page


def get_article_content(article, limit):
    global code_lang
    try:
        with codecs.open(f'articles/{article}.md', 'r', encoding='utf-8') as f:
            content = f.read()

        lines = content.split('\n')
        lines_limit = min(limit, len(lines))
        line_counter = 0
        html_content = ''
        read_nav = []
        in_code_block = False
        in_math_block = False
        code_block_content = ''
        math_content = ''

        for line in lines:
            if line_counter >= lines_limit:
                break

            if line.startswith('```'):
                if in_code_block:
                    in_code_block = False
                    # code_lang = line.split('```')[1].strip()
                    escaped_code_block_content = html.escape(code_block_content.strip())
                    html_content += f'<div class="highlight"><pre><code class="language-{code_lang}">{escaped_code_block_content}</code></pre></div>'
                    code_block_content = ''
                else:
                    in_code_block = True
                    code_lang = line.split('```')[1].strip()
            elif in_code_block:
                code_block_content += line + '\n'
            elif line.startswith('$$'):
                if not in_math_block:
                    in_math_block = True
                else:
                    in_math_block = False
                    html_content += f'<div class="math">{math_content.strip()}</div>'
                    math_content = ''
            elif in_math_block:
                math_content += line.strip() + ' '
            else:
                if re.search(r'^\s*<.*?>', line):
                    # Skip HTML tags and their content in non-code block lines
                    continue

                if line.startswith('#'):
                    header_level = len(line.split()[0]) + 2
                    header_title = line.strip('#').strip()
                    anchor = header_title.lower().replace(" ", "-")
                    read_nav.append(
                        f'<a href="#{anchor}">{header_title}</a><br>'
                    )
                    line = f'<h{header_level} id="{anchor}">{header_title}</h{header_level}>'

                html_content += zy_show_article(line)

            line_counter += 1

        return html_content, '\n'.join(read_nav)

    except FileNotFoundError:
        # Return a 404 error page if the file does not exist
        return error('No file', 404)


def zy_show_article(content):
    try:
        markdown_text = content
        article_content = markdown.markdown(markdown_text)
        return article_content
    except Exception as e:
        # 发生任何异常时返回一个错误页面，可以根据需要自定义错误消息
        return error(f'Error in displaying the article :{e}', 404)


def edit_article_content(article, max_line):
    limit = max_line
    try:
        with codecs.open(f'articles/{article}.md', 'r', encoding='utf-8-sig', errors='replace') as f:
            lines = []
            for line in f:
                try:
                    lines.append(line)
                except UnicodeDecodeError:
                    # 在遇到解码错误时跳过当前行
                    pass

                if len(lines) >= limit:
                    break

        return ''.join(lines)
    except FileNotFoundError:
        # 文件不存在时返回 404 错误页面
        return error('No file', 404)


def get_article_last_modified(file_path):
    try:
        decoded_name = urllib.parse.unquote(file_path)  # 对文件名进行解码处理
        file_path = os.path.join('articles', decoded_name + '.md')
        # 获取文件的创建时间
        # create_time = os.path.getctime(file_path)
        # 获取文件的修改时间
        modify_time = os.path.getmtime(file_path)
        # 获取文件的访问时间
        # access_time = os.path.getatime(file_path)

        formatted_modify_time = datetime.datetime.fromtimestamp(modify_time).strftime("%Y-%m-%d %H:%M")

        return formatted_modify_time

    except FileNotFoundError:
        # 处理文件不存在的情况
        return None


def get_file_summary(a_title):
    articles_dir = os.path.join('articles', a_title + ".md")
    try:
        with open(articles_dir, 'r', encoding='utf-8') as file:
            content = file.read()
    except FileNotFoundError:
        return "未找到文件"
    html_content = markdown.markdown(content)
    text_content = clean_html_format(html_content)
    summary = (text_content[:75] + "...") if len(text_content) > 75 else text_content
    return summary


def save_article_changes(aid, hidden, status, cover_image_path, excerpt):
    db = None
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            # 根据cover_image_path是否为None构建不同的查询
            if cover_image_path is None:
                query = "UPDATE `articles` SET `Hidden` = %s, `Status` = %s, `excerpt` = %s WHERE `article_id` = %s"
                cursor.execute(query, (int(hidden), status, excerpt, aid))
            else:
                query = "UPDATE `articles` SET hidden = %s, `Status` = %s, `cover_image` = %s, `excerpt` = %s WHERE `article_id` = %s"
                cursor.execute(query, (int(hidden), status, cover_image_path, excerpt, aid))
            db.commit()
            return {'show_edit_code': 'success'}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {'show_edit_code': 'failure', 'error': str(e)}
    finally:
        if db is not None:
            db.close()


def zy_delete_article(filename):
    # 指定目录的路径
    directory = 'articles/'
    db = None
    cursor = None
    try:
        db = get_db_connection()
        with db.cursor() as cursor:
            query = "UPDATE `articles` SET `Status` = 'Deleted' WHERE `articles`.`Title` = %s;"
            cursor.execute(query, (filename,))  # 确保 filename 与数据库中存储的格式一致
            db.commit()
            filename = filename + '.md'
            # 构建文件的完整路径
            file_path = os.path.join(directory, filename)
            # 删除文件
            os.remove(file_path)
            return 'success'
    except Exception as e:
        return 'failed: ' + str(e)
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()
