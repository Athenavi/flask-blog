import json
from datetime import datetime, timezone, timedelta
from functools import lru_cache

import markdown
from flask import current_app as app

from src.database import get_db
from src.models import Category
from src.user.profile.social import get_user_name_by_id


def json_filter(value):
    """将 JSON 字符串解析为 Python 对象"""
    # 如果已经是字典直接返回
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        # print(f"Unexpected type for value: {type(value)}. Expected a string.")
        return None

    try:
        result = json.loads(value)
        return result
    except (ValueError, TypeError) as e:
        app.logger.error(f"Error parsing JSON: {e}, Value: {value}")
        return None


def string_split(value, delimiter=','):
    """
    在模板中对字符串进行分割
    :param value: 要分割的字符串
    :param delimiter: 分割符，默认为逗号
    :return: 分割后的列表
    """
    if not isinstance(value, str):
        app.logger.error(f"Unexpected type for value: {type(value)}. Expected a string.")
        return []

    try:
        result = value.split(delimiter)
        return result
    except Exception as e:
        app.logger.error(f"Error splitting string: {e}, Value: {value}")
        return []


@lru_cache(maxsize=128)  # 设置缓存大小为128
def article_author(user_id):
    """通过 user_id 搜索作者名称"""
    return get_user_name_by_id(user_id)


def md2html(content):
    return markdown.markdown(content, extensions=['markdown.extensions.fenced_code', 'toc'])


def relative_time_filter(dt):
    # 确保传入的时间是UTC时区
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)

    now = datetime.now(timezone.utc)
    diff = now - dt

    if diff < timedelta(minutes=1):
        return "刚刚"
    elif diff < timedelta(hours=1):
        return f"{int(diff.seconds / 60)}分钟前"
    elif diff < timedelta(days=1):
        return f"{int(diff.seconds / 3600)}小时前"
    elif diff < timedelta(days=30):
        return f"{diff.days}天前"
    else:
        return dt.strftime('%Y-%m-%d')


@lru_cache(maxsize=128)
def category_filter(category_id):
    with get_db() as db:
        category = db.query(Category).filter(Category.id == category_id).first()
        if category:
            return category.name
        return None


def f2list(input_value, delimiter=';'):
    """
    将分隔符分隔的字符串转换为列表
    """
    try:
        if input_value is None:
            return []

        # 如果已经是列表且不为空，直接返回
        if isinstance(input_value, list):
            if input_value and isinstance(input_value[0], str) and delimiter in input_value[0]:
                # 如果列表中的字符串包含分隔符，进行分割
                result = []
                for item in input_value:
                    if isinstance(item, str):
                        result.extend([tag.strip() for tag in item.split(delimiter) if tag.strip()])
                    else:
                        result.append(str(item).strip())
                return result
            return input_value

        # 处理字符串输入
        if isinstance(input_value, str):
            return [tag.strip() for tag in input_value.split(delimiter) if tag.strip()]

        # 处理其他类型
        return [str(input_value).strip()]

    except Exception as e:
        return [str(input_value)] if input_value else []
