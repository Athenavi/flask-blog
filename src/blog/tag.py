from src.database import get_db_connection
#from pymysql import DatabaseError

def get_unique_article_tags():
    unique_tags = []

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = "SELECT Tags FROM articles"
                cursor.execute(query)
                results = cursor.fetchall()
                for result in results:
                    tags_str = result[0]
                    if tags_str:
                        tags_list = tags_str.split(';')
                        unique_tags.extend(tag for tag in tags_list if tag)
                unique_tags = list(set(unique_tags))

    except Exception as e:
        return f"未知错误: {e}"

    return unique_tags



def get_articles_by_tag(tag_name):
    tag_articles = []

    try:
        with get_db_connection() as db:
            with db.cursor() as cursor:
                query = "SELECT Title FROM articles WHERE hidden = 0 AND `Status` = 'Published' AND `Tags` LIKE %s"
                cursor.execute(query, ('%' + tag_name + '%',))
                results = cursor.fetchall()
                for result in results:
                    tag_articles.append(result[0])

    except Exception as e:
        return f"未知错误: {e}"

    return tag_articles



def query_article_tags(article_name):
    db = get_db_connection()
    cursor = db.cursor()
    unique_tags = []
    aid = 0

    try:
        query = "SELECT article_id, Tags FROM articles WHERE Title = %s"
        cursor.execute(query, (article_name,))

        result = cursor.fetchone()
        if result:
            aid = result[0] or 0
            tags_str = result[1]
            if tags_str:
                tags_list = tags_str.split(';')
                unique_tags = list(set(tags_list))
    except Exception as e:  # 捕获其他异常
        # 记录其他错误
        print(f"发生了一个错误: {e}")
        return aid, []
    finally:
        cursor.close()
        db.close()
        return aid, unique_tags



def update_article_tags(aid, tags_list):
    tags_str = ';'.join(tags_list)

    db = get_db_connection()
    cursor = db.cursor()

    try:
        # 检查文章是否存在
        query = "SELECT * FROM articles WHERE article_id = %s"
        cursor.execute(query, (int(aid),))
        result = cursor.fetchone()

        if result:
            # 如果文章存在，则更新标签
            update_query = "UPDATE articles SET Tags = %s WHERE article_id = %s"
            cursor.execute(update_query, (tags_str, int(aid)))
            db.commit()

    except Exception as e:
        print(f"An error occurred during database operation: {e}")
        pass

    finally:
        cursor.close()
        db.close()
