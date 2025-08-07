import json
from functools import lru_cache
from flask import current_app as app

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
