import codecs
import os
from pathlib import Path

import markdown

from src.database import get_db_connection
from src.error import error
from src.utils.security.safe import clean_html_format


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


def get_article_titles(per_page=30, page=1):
    # 连接到MySQL数据库
    conn = get_db_connection()
    cursor = conn.cursor()

    # 计算查询的起始和结束索引
    start_index = (page - 1) * per_page

    # 执行查询，获取仅公开且未隐藏的文章标题
    query = """
            SELECT title
            FROM articles
            WHERE status = 'Published'
              AND hidden = 0
            ORDER BY updated_at DESC
            LIMIT %s OFFSET %s \
            """
    cursor.execute(query, (per_page, start_index))
    articles = [row[0] for row in cursor.fetchall()]

    # 关闭数据库连接
    cursor.close()
    conn.close()

    # 计算是否有下一页和上一页
    # 这里我们再次查询总的公开且未隐藏的文章数量，以确定是否有下一页和上一页
    count_query = """
                  SELECT COUNT(*)
                  FROM articles
                  WHERE status = 'Published'
                    AND hidden = 0 \
                  """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(count_query)
    total_articles = cursor.fetchone()[0]

    has_next_page = (start_index + per_page) < total_articles
    has_previous_page = start_index > 0

    # 关闭数据库连接
    cursor.close()
    conn.close()

    return articles, has_next_page, has_previous_page


import html


def get_article_content_by_title_or_id(identifier, is_title=True, limit=10):
    try:
        db = get_db_connection()
        cursor = db.cursor()

        if is_title:
            query = """
                    SELECT ac.content, ac.updated_at
                    FROM articles a
                             JOIN article_content ac ON a.article_id = ac.aid
                    WHERE a.title = %s
                    """
            cursor.execute(query, (identifier,))
        else:
            query = """
                    SELECT ac.content, ac.updated_at
                    FROM article_content ac
                    WHERE ac.aid = %s
                    """
            cursor.execute(query, (identifier,))

        result = cursor.fetchone()
        cursor.close()
        db.close()

        if not result:
            print(f"No article found with {'title' if is_title else 'article_id'}:", identifier)
            return None, None

        content, date = result
        unescaped_content = html.unescape(content)

        # 按行分割Markdown内容
        lines = unescaped_content.splitlines()

        # 处理空内容的情况
        if not lines:
            return "", date

        # 截取指定行数并保留行结构
        truncated_lines = lines[:limit]
        truncated_content = "\n".join(truncated_lines)

        # 添加省略号指示截断（如果实际行数超过限制）
        if len(lines) > limit:
            truncated_content += "\n..."

        return truncated_content, date

    except Exception as e:
        print(f"Error fetching content: {str(e)}")
        return None, None


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
