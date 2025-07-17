import logging
import random
from datetime import timedelta, datetime

import bcrypt
import bleach
from flask import request, redirect, url_for, render_template, make_response

from src.error import error
from src.user.authz.core import generate_jwt, generate_refresh_token
from src.database import get_db_connection


def user_login(callback_route, site_key):
    input_value = bleach.clean(request.form['username'])  # 用户输入的用户名或邮箱
    password = bleach.clean(request.form['password'])
    db = get_db_connection()
    cursor = db.cursor()
    try:
        query = "SELECT * FROM users WHERE (username = %s OR email = %s) AND username <> 'guest@7trees.cn'"
        cursor.execute(query, (input_value, input_value))
        result = cursor.fetchone()

        if result is not None and bcrypt.checkpw(password.encode('utf-8'), result[2].encode('utf-8')):
            # 登录成功，生成 JWT 和刷新令牌
            user_id = result[0]  # 假设 result[0] 是用户ID
            user_name = result[1]
            token = generate_jwt(user_id, user_name)  # 生成 JWT
            refresh_token = generate_refresh_token(user_id, user_name)  # 生成刷新令牌

            response = make_response(redirect(url_for(callback_route)))

            # 设置 Cookie 的过期时间为 7 天
            expires = datetime.now() + timedelta(seconds=21600)
            refresh_expires = datetime.now() + timedelta(days=7)

            response.set_cookie('jwt', token, httponly=True, expires=expires)
            response.set_cookie('refresh_token', refresh_token, httponly=True, expires=refresh_expires)
            return response
        else:
            return render_template('LoginRegister.html', error="Invalid username or password", site_key=site_key)

    except Exception as e:
        logging.error(f"Error logging in: {e}")
        return "登录失败"

    finally:
        cursor.close()
        db.close()


def create_user(ip, site_key):
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        invite_code = request.form.get('invite_code', '').strip()
        email_address = username + str(random.randint(1000, 9999)) + "@7trees.cn"
        db = get_db_connection()
        cursor = db.cursor()

        try:
            # 判断用户名是否已存在
            query_invite_code = "SELECT * FROM permissions WHERE code = %s and description LIKE 'invite_code%%';"
            cursor.execute(query_invite_code, (invite_code,))
            existing_invite_code = cursor.fetchone()
            if existing_invite_code is None:
                return render_template('LoginRegister.html', title="注册",
                                       msg='无效的邀请码!', type="register", site_key=site_key)
            # 判断用户名是否已存在
            query_username = "SELECT * FROM users WHERE username = %s"
            cursor.execute(query_username, (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                return render_template('LoginRegister.html', title="注册",
                                       msg='该用户名已被注册，请选择其他用户名!', type="register", site_key=site_key)

            # 执行用户注册的逻辑
            hashed_password = '$2b$12$kF4nZn6kESHtj0cjNeaoZugUlWXSgXp27iKAXHepyzSwUxrrhVTz2'
            insert_query = "INSERT INTO users (username, password, register_ip,email) VALUES (%s, %s, %s,%s)"
            cursor.execute(insert_query, (username, hashed_password, ip, email_address))
            db.commit()

            # 标记邀请码
            update_invite_code_query = ("INSERT INTO events (title, description, event_date) VALUES (%s, %s, "
                                        "CURRENT_TIMESTAMP)")
            cursor.execute(update_invite_code_query, (
                'new user registered', f'username: {username}, register_ip: {ip}, invite_code: {invite_code}'))
            db.commit()
            message = f"{username}注册成功！已经为您分配默认密码 ‘123456’，请尽快修改！！避免个人信息泄露！"
            return render_template('inform.html', status_code='200', message=message)

        except Exception as e:
            return error(message=f"注册失败, {e}", status_code=500)

        finally:
            cursor.close()
            db.close()

    return render_template('LoginRegister.html', title="注册", type="register", site_key=site_key)


def tp_mail_login(user_email, ip):
    username = 'qks' + format(random.randint(1000, 9999))
    password = '123456'
    db = get_db_connection()
    cursor = db.cursor()

    try:
        # 判断用户是否已存在
        query = "SELECT * FROM users WHERE (username = %s OR email = %s) AND username <> 'guest@7trees.cn'"
        cursor.execute(query, (user_email, user_email))
        result = cursor.fetchone()

        if result is not None:
            # 登录成功，生成 JWT 和刷新令牌
            user_id = result[0]  # 假设 result[0] 是用户ID
            user_name = result[1]
            token = generate_jwt(user_id, user_name)  # 生成 JWT
            refresh_token = generate_refresh_token(user_id, user_name)  # 生成刷新令牌
            response = make_response(
                render_template('inform.html', status_code='200', message="授权通过!你可以关闭此页面"))
            # 设置 Cookie 的过期时间为 7 天
            expires = datetime.now() + timedelta(days=7)
            response.set_cookie('jwt', token, httponly=True, expires=expires)
            response.set_cookie('refresh_token', refresh_token, httponly=True, expires=expires)

            return response

        else:
            # 执行用户注册的逻辑
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            insert_query = "INSERT INTO users (username, password, email,register_ip) VALUES (%s, %s, %s,%s)"
            cursor.execute(insert_query, (username, hashed_password, user_email, ip))
            db.commit()
            message = '已经为您自动注册账号\n' + '账号' + username + '默认密码：123456 请尽快修改'
            return render_template('inform.html', status_code='200', message=message)

    except Exception as e:
        logging.error(f"Error registering user: {e}")
        return "注册失败,如遇到其他问题，请尽快反馈"

    finally:
        cursor.close()
        db.close()