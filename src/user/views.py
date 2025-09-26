import re

from flask import render_template, request, jsonify, current_app

from src.models import User
from src.other.sendEmail import request_email_change
from src.user.entities import check_user_conflict, change_username, bind_email
from src.user.profile.edit import edit_profile


def setting_profiles_back(user_id, user_info, cache_instance, avatar_url_api):
    try:
        if user_info is None:
            # 处理未找到用户信息的情况
            return "用户信息未找到", 404
        avatar_url = user_info[5] if len(user_info) > 5 and user_info[5] else avatar_url_api
        bio = user_info[6] if len(user_info) > 6 and user_info[6] else "这人很懒，什么也没留下"
        user_name = user_info[1] if len(user_info) > 1 else "匿名用户"
        user_email = user_info[2] if len(user_info) > 2 else "未绑定邮箱"
        profile_private = User.query.filter(User.id == user_id).first().profile_private
        print(profile_private)

        return render_template(
            'setting.html',
            avatar_url=avatar_url,
            username=user_name,
            limit_username_lock=cache_instance.get(f'limit_username_lock_{user_id}'),
            Bio=bio,
            userEmail=user_email,
            ProfilePrivate=profile_private,
        )
    except Exception as e:
        print(e)



def change_profiles_back(user_id, cache_instance, domain):
    change_type = request.args.get('change_type')
    if not change_type:
        return jsonify({'error': 'Change type is required'}), 400
    if change_type not in ['avatar', 'username', 'email', 'password', 'bio']:
        return jsonify({'error': 'Invalid change type'}), 400
    cache_instance.delete_memoized(current_app.view_functions['api_user_profile'], user_id=user_id)
    if change_type == 'username':
        limit_username_lock = cache_instance.get(f'limit_username_lock_{user_id}')
        if limit_username_lock:
            return jsonify({'error': 'Cannot change username more than once a week'}), 400
        username = request.json.get('username')
        if not username:
            return jsonify({'error': 'Username is required'}), 400
        if not re.match(r'^[a-zA-Z0-9_]{4,16}$', username):
            return jsonify({'error': 'Username should be 4-16 characters, letters, numbers or underscores'}), 400
        if check_user_conflict(zone='username', value=username):
            return jsonify({'error': 'Username already exists'}), 400
        change_username(user_id, new_username=username)
        cache_instance.set(f'limit_username_lock_{user_id}', True, timeout=604800)
        return jsonify({'message': 'Username updated successfully'}), 200
    if change_type == 'email':
        email = request.json.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'error': 'Invalid email format'}), 400
        if check_user_conflict(zone='email', value=email):
            return jsonify({'error': 'Email already exists'}), 400
        request_email_change(user_id, cache_instance, domain, email)
        return jsonify({'message': 'Email updated successfully'}), 200
    else:
        return edit_profile(request, change_type, user_id)


def diy_space_back(user_id, avatar_url, profiles, user_bio):
    return render_template('diy_space.html', user_id=user_id, avatar_url=avatar_url,
                           profiles=profiles, userBio=user_bio)


def confirm_email_back(user_id, cache_instance, token):
    new_email = cache_instance.get(f"temp_email_{user_id}").get('new_email')
    token_value = cache_instance.get(f"temp_email_{user_id}").get('token')

    # 验证令牌匹配
    if token != token_value:
        return jsonify({"error": "Invalid verification data"}), 400

    bind_email(user_id, new_email)
    cache_instance.delete_memoized(current_app.view_functions['api_user_profile'], user_id=user_id)

    return render_template('inform.html', status_code=200, message='Email updated successfully')
