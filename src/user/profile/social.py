from src.models import User, db


def get_user_info(user_id):
    if not user_id:
        return []
    try:
        user = db.session.query(User).filter(User.id == user_id).first()
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
    try:
        user = db.session.query(User).filter(User.id == user_id).first()
        if user:
            author_name = user.username
            return author_name

    except (ValueError, TypeError) as e:
        pass
