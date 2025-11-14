from flask import request

from src.models import User, Notification, db


def update_password(user_id, new_password, confirm_password, ip):
    user = db.session.query(User).filter_by(id=user_id).first()

    if user:
        # 验证新密码和确认密码是否一致，并且长度是否符合要求
        if new_password == confirm_password and len(new_password) >= 6:
            try:
                user.set_password(new_password)
                # 创建通知
                notice = Notification(
                    user_id=user_id,
                    type='safe',
                    message=f"{ip} changed password"
                )
                db.session.add(notice)
                return True
            except Exception as e:
                print(e)
                return False
            finally:
                db.session.commit()
        else:
            return False

    return False


def validate_password(user_id):
    password = request.form.get('password')
    # 查询用户
    user = db.session.query(User).filter_by(id=user_id).first()
    if user:
        return user.check_password(password=password)
    return False
