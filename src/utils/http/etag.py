import hashlib
import json


def generate_etag(total_articles: int, article_info: list, page: int, current_theme: str) -> str:
    """生成 ETag（包含分页参数和数据版本）"""
    etag_data = f"{json.dumps(article_info)}-{total_articles}-page-{page}-current_theme-{current_theme}"
    return hashlib.md5(etag_data.encode()).hexdigest()
