import re

from flask import url_for, render_template, request, jsonify, current_app

from src.blog.article.core.content import get_e_content
from src.blog.article.core.crud import get_articles_by_uid
from src.blog.article.metadata.handlers import get_article_metadata
from src.error import error
from src.other.sendEmail import request_email_change
from src.user.entities import auth_by_uid, check_user_conflict, change_username
from src.user.profile.edit import edit_profile
from src.user.profile.social import can_follow_user, get_follower_count, get_following_count


def user_space_back(user_id, target_id, user_bio, target_username, avatar_url):
    can_followed = 1
    if user_id != 0 and target_id != 0:
        can_followed = can_follow_user(user_id, target_id)
    owner_articles = get_articles_by_uid(user_id=target_id) or []
    return render_template('Profile.html', url_for=url_for, avatar_url=avatar_url,
                           target_username=target_username,
                           userBio=user_bio, follower=get_follower_count(user_id=target_id, subscribe_type='User'),
                           following=get_following_count(user_id=target_id, subscribe_type='User'),
                           target_id=target_id, user_id=user_id,
                           Articles=owner_articles, canFollowed=can_followed)


def setting_profiles_back(user_id, user_info, cache_instance, avatar_url_api):
    if user_info is None:
        # 处理未找到用户信息的情况
        return "用户信息未找到", 404
    avatar_url = user_info[5] if len(user_info) > 5 and user_info[5] else avatar_url_api
    bio = user_info[6] if len(user_info) > 6 and user_info[6] else "这人很懒，什么也没留下"
    user_name = user_info[1] if len(user_info) > 1 else "匿名用户"
    user_email = user_info[2] if len(user_info) > 2 else "未绑定邮箱"

    return render_template(
        'setting.html',
        avatar_url=avatar_url,
        username=user_name,
        limit_username_lock=cache_instance.get(f'limit_username_lock_{user_id}'),
        Bio=bio,
        userEmail=user_email,
    )


def markdown_editor_back(user_id, aid):
    auth = auth_by_uid(aid, user_id)
    if auth:
        all_info = get_article_metadata(aid)
        if request.method == 'GET':
            edit_html = get_e_content(identifier=aid, is_title=False, limit=9999)
            # print(edit_html)
            return render_template('editor.html', edit_html=edit_html, aid=aid,
                                   user_id=user_id, coverImage=f"/api/cover/{aid}.png",
                                   all_info=all_info)
        else:
            return render_template('editor.html')

    else:
        return error(message='您没有权限', status_code=503)


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


def render_profile(user_id, articles, avatar_url, user_bio, recycle_bin_flag=False):
    user_follow = get_following_count(user_id=user_id) or 0
    follower = get_follower_count(user_id=user_id) or 0
    return render_template('Profile.html',
                           avatar_url=avatar_url,
                           userBio=user_bio,
                           following=user_follow,
                           follower=follower,
                           target_id=user_id,
                           user_id=user_id,
                           Articles=articles,
                           recycle_bin=recycle_bin_flag)


def diy_space_back(user_id, avatar_url, profiles, user_bio):
    return render_template('diy_space.html', user_id=user_id, avatar_url=avatar_url,
                           profiles=profiles, userBio=user_bio)
