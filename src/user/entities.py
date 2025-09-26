from sqlalchemy.exc import SQLAlchemyError

from src.database import get_db
from src.models import Article, User


def auth_by_uid(article_id, user_id):
    try:
        with get_db() as session:
            print(type(session))
            article = session.query(Article).filter_by(article_id=article_id, user_id=user_id).first()
            print(article)
            return article is not None
    except SQLAlchemyError as e:
        print(f"An error occurred: {e}")
        return False


def check_user_conflict(zone, value):
    try:
        with get_db() as session:
            if zone == 'username':
                user = session.query(User).filter_by(username=value).first()
            elif zone == 'email':
                user = session.query(User).filter_by(email=value).first()
            else:
                return False
            return user is not None
    except SQLAlchemyError as e:
        print(f"Error getting user list: {e}")
        return False


def db_save_avatar(user_id, avatar_uuid):
    try:
        with get_db() as session:
            print(type(session))
            user = session.query(User).filter_by(id=user_id).first()
            if user:
                user.profile_picture = avatar_uuid
                session.commit()
    except SQLAlchemyError as e:
        print(f"Error saving avatar: {e} by user {user_id} avatar uuid: {avatar_uuid}")
        session.rollback()


def db_save_bio(user_id, bio):
    try:
        with get_db() as session:
            user = session.query(User).filter_by(id=user_id).first()
            if user:
                user.bio = bio
                session.commit()
    except SQLAlchemyError as e:
        print(f"Error saving bio: {e} by user {user_id} bio: {bio}")
        session.rollback()


def change_username(user_id, new_username):
    # 修改用户名将可能导致资料被意外删除,建议先导出您的资料再进行下一步操作
    # 导出资料: 点击右上角头像 -> 点击设置 -> 点击导出资料
    try:
        with get_db() as session:
            user = session.query(User).filter_by(id=user_id).first()
            if user:
                user.username = new_username
                session.commit()
    except SQLAlchemyError as e:
        print(f"Error changing username: {e} by user {user_id} new username: {new_username}")
        session.rollback()


def bind_email(user_id, param):
    if check_user_conflict('email', param):
        return False
    try:
        with get_db() as session:
            user = session.query(User).filter_by(id=user_id).first()
            if user:
                user.email = param
                session.commit()
    except SQLAlchemyError as e:
        print(f"Error binding email: {e} by user {user_id} email: {param}")
        session.rollback()


def get_avatar(domain, user_identifier=None, identifier_type='id'):
    avatar_url = None
    if not user_identifier:
        return avatar_url

    try:
        with get_db() as session:
            if identifier_type == 'id':
                user = session.query(User).filter_by(id=user_identifier).first()
            elif identifier_type == 'username':
                user = session.query(User).filter_by(username=user_identifier).first()
            else:
                raise ValueError("identifier_type must be 'id' or 'username'")
            if user and user.profile_picture:
                avatar_url = f"{domain}static/avatar/{user.profile_picture}.webp"
    except SQLAlchemyError as e:
        print(f"Error fetching avatar: {e}")

    return avatar_url
