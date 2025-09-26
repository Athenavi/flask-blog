from src.database import get_db
from src.models import User


def get_user_info(user_id):
    if not user_id:
        return []
    with get_db() as session:
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if user:
                info_list = [user.id, user.username, user.email, user.is_2fa_enabled, user.register_ip,
                             user.profile_picture,
                             user.bio, user.profile_private]
                return info_list
            else:
                return []
        except Exception as e:
            print(f"An error occurred: {e}")


def get_user_name_by_id(user_id):
    author_name = '未知'
    with get_db() as session:
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if user:
                author_name = user.username
        except (ValueError, TypeError) as e:
            pass
        finally:
            return author_name
