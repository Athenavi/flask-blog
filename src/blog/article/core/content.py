from src.database import get_db
from src.models import ArticleI18n, Article


def get_article_slugs():
    with get_db() as session:
        # 使用ORM查询
        results = session.query(Article.article_id, Article.slug).filter(
            Article.status == 'Published',
            Article.hidden == False
        ).all()
        # 组合成字典返回
        article_dict = {row[0]: row[1] for row in results}
        return article_dict


def get_i18n_content_by_aid(iso, aid):
    with get_db() as session:
        # 使用ORM查询
        i18n_content = session.query(ArticleI18n.content).filter(
            ArticleI18n.article_id == aid, ArticleI18n.language_code == iso).first()
        if i18n_content:
            return i18n_content[0]
        else:
            return None
