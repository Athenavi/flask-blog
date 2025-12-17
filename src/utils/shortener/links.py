import os
import random
import string

from sqlalchemy.exc import SQLAlchemyError

from src.blueprints.blog import get_site_domain
# from src.database import get_db
from src.models import Url, db


def generate_short_url():
    characters = string.ascii_letters + string.digits
    short_url = ''.join(random.choice(characters) for _ in range(6))
    return short_url


def create_special_url(long_url, user_id):
    try:
        # print(f"[DEBUG] create_special_url called with long_url={long_url}, user_id={user_id}")
        domain = get_site_domain() or os.getenv('DOMAIN')
        # print(f"[DEBUG] Domain from settings: {domain}")

        # 如果domain末尾没有斜杠，则添加一个
        if domain and not domain.endswith('/'):
            domain += '/'

        # 如果long_url已经是完整URL，则检查是否以domain开头
        if long_url.startswith(('http://', 'https://')):
            print(f"[DEBUG] long_url is absolute URL")
            if domain and not long_url.startswith(domain):
                # 如果不是以当前domain开头，我们需要将其转换为相对路径
                print(f"[DEBUG] long_url doesn't start with domain, converting to relative path")
                from urllib.parse import urlparse
                parsed = urlparse(long_url)
                long_url = long_url[len(f"{parsed.scheme}://{parsed.netloc}"):]
        elif domain:
            # 如果long_url是相对路径且domain存在，构建完整URL用于检查
            print(f"[DEBUG] Processing relative URL with domain")
            full_url = domain.rstrip('/') + '/' + long_url.lstrip('/')
            if not long_url.startswith('/'):
                long_url = '/' + long_url

        # 查询是否存在该长链接和用户ID对应的短链接
        existing_url = db.session.query(Url).filter_by(long_url=long_url, user_id=user_id).first()
        # print(f"[DEBUG] Existing URL query result: {existing_url}")

        if existing_url:
            short_url = existing_url.short_url
            # print(f"[DEBUG] Using existing short URL: {short_url}")
        else:
            # 生成新的短链接
            short_url = generate_short_url()
            # print(f"[DEBUG] Generated new short URL: {short_url}")
            new_url = Url(long_url=long_url, short_url=short_url, user_id=user_id)
            db.session.add(new_url)
            db.session.commit()
            # print(f"[DEBUG] New URL committed to database")

        return short_url
    except Exception as e:
        # print(f"[ERROR] Exception in create_special_url: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def redirect_to_long_url(short_url):
    try:
        domain = get_site_domain() or os.getenv('DOMAIN')
        # 查询短链接对应的长链接
        url_entry = db.session.query(Url).filter_by(short_url=short_url).first()
        if url_entry:
            # 如果长链接已经以http://或https://开头，则不添加域名
            if url_entry.long_url.startswith(('http://', 'https://')):
                return url_entry.long_url
            long_url = domain + url_entry.long_url.lstrip('/') if url_entry.long_url.startswith(
                '/') else domain + '/' + url_entry.long_url
            return long_url
        else:
            return None
    except SQLAlchemyError as e:
        print(f"Not Found {e}")
        return None


def delete_link(short_url):
    try:
        # 查询并删除短链接对应的记录
        url_entry = db.session.query(Url).filter_by(short_url=short_url).first()
        if url_entry:
            db.session.delete(url_entry)
            db.session.commit()
            return True
        else:
            return False
    except Exception as e:
        return f"Not Found {e}"
