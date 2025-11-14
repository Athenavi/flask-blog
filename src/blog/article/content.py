from src.models import Article, db


def get_article_slugs():
    # 使用ORM查询
    results = db.session.query(Article.article_id, Article.slug).filter(
        Article.status == 1,
        Article.hidden == False
    ).all()
    # 组合成字典返回
    article_dict = {row[0]: row[1] for row in results}
    return article_dict
