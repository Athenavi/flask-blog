from flask import url_for, render_template

from src.blog.article.core.crud import get_articles_by_uid
from src.user.profile.social import can_follow_user, get_follower_count, get_following_count


def user_space_back(user_id, target_id, user_bio,target_username,avatar_url):
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