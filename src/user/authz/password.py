import bcrypt
from flask import redirect, render_template
from flask import request

from src.database import get_db
from src.models import User, Notification
from src.utils.security.ip_utils import get_client_ip


def update_password(user_id, new_password, confirm_password, ip):
    # 查询用户
    with get_db() as db:
        user = db.query(User).filter_by(id=user_id).first()

        if user:
            # 验证新密码和确认密码是否一致，并且长度是否符合要求
            if new_password == confirm_password and len(new_password) >= 6:
                # 哈希新密码
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

                # 更新密码
                user.password = hashed_password.decode('utf-8')

                # 创建通知
                notice = Notification(
                    user_id=user_id,
                    type='safe',
                    message=f"{ip} changed password"
                )

                # 添加通知到会话
                db.add(notice)
                return True

        return False


def validate_password(user_id):
    password = request.form.get('password')
    with get_db() as db:
        # 查询用户
        user = db.query(User).filter_by(id=user_id).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return True
        else:
            return False


def confirm_password_back(user_id, cache_instance):
    if request.method == 'POST':
        if validate_password(user_id):
            cache_instance.set(f"tmp-change-key_{user_id}", True, timeout=300)
            return redirect("/change-password")
    return render_template('Authentication.html', form='confirm')


def change_password_back(user_id, cache_instance):
    if not cache_instance.get(f"tmp-change-key_{user_id}"):
        return redirect('/confirm-password')
    if request.method == 'POST':
        ip = get_client_ip(request)
        new_pass = request.form.get('new_password')
        repeat_pass = request.form.get('confirm_password')
        if update_password(user_id, new_password=new_pass, confirm_password=repeat_pass, ip=ip):
            return render_template('inform.html', status_code='200', message='密码修改成功！')
        else:
            return render_template('Authentication.html', form='change')
    return render_template('Authentication.html', form='change')
