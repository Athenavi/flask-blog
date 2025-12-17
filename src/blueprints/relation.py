from flask import Blueprint, render_template
from flask import jsonify

from src.auth_utils import jwt_required
from src.models import User, UserSubscription, db

relation_bp = Blueprint('relation', __name__, template_folder='templates')


@relation_bp.route('/fans/follow')
@jwt_required
def following_list(user_id):
    """显示当前用户关注的人列表"""
    following_query = db.session.query(User, UserSubscription.created_at).join(
        UserSubscription, User.id == UserSubscription.subscribed_user_id
    ).filter(UserSubscription.subscriber_id == user_id).order_by(
        UserSubscription.created_at.desc()
    )

    following_list = following_query.all()
    following_count = following_query.count()

    return render_template('fans/following.html',
                           following_list=following_list,
                           following_count=following_count,
                           current_user=user_id)


@relation_bp.route('/fans/fans')
@jwt_required
def fans_list(user_id):
    """显示当前用户的粉丝列表"""
    try:
        # 获取关注当前用户的所有用户（粉丝）
        fans_query = db.session.query(User, UserSubscription.created_at).join(
            UserSubscription, User.id == UserSubscription.subscriber_id
        ).filter(UserSubscription.subscribed_user_id == user_id).order_by(
            UserSubscription.created_at.desc()
        )
        current_user = User.query.get(user_id)

        fans_list = fans_query.all()
        fans_count = fans_query.count()

        return render_template('fans/fans.html',
                               fans_list=fans_list,
                               fans_count=fans_count,
                               current_user=current_user)
    except Exception as e:
        print(e)


@relation_bp.route('/api/follow/<int:target_user_id>', methods=['POST'])
@jwt_required
def follow_user(user_id, target_user_id):
    """关注用户"""
    if user_id == target_user_id:
        return jsonify({'success': False, 'message': '不能关注自己'}), 400

        # 检查是否已经关注
    existing = UserSubscription.query.filter_by(
        subscriber_id=user_id,
        subscribed_user_id=target_user_id
    ).first()

    if existing:
        return jsonify({'success': False, 'message': '已经关注了该用户'}), 400

    # 创建关注关系
    subscription = UserSubscription(
        subscriber_id=user_id,
        subscribed_user_id=target_user_id,
    )
    db.session.add(subscription)
    db.session.commit()

    return jsonify({'success': True, 'message': '关注成功'})


@relation_bp.route('/api/unfollow/<int:target_user_id>', methods=['POST'])
@jwt_required
def unfollow_user(user_id, target_user_id):
    """取消关  注用户"""
    subscription = UserSubscription.query.filter_by(
        subscriber_id=user_id,
        subscribed_user_id=target_user_id
    ).first()

    if not subscription:
        return jsonify({'success': False, 'message': '未关注该用户'}), 400
    db.session.delete(subscription)
    db.session.commit()
    return jsonify({'success': True, 'message': '取消关注成功'})


@relation_bp.route('/users')
@jwt_required
def users_list(user_id):
    """用户列表页面，用于发现和关注新用户"""
    # 获取所有用户（除了当前用户）
    users = User.query.filter(User.id != user_id, User.profile_private != True).all()

    # 获取当前用户已关注的用户ID列表

    following_ids = [sub.subscribed_user_id for sub in
                     UserSubscription.query.filter_by(subscriber_id=user_id).all()]

    return render_template('fans/users.html',
                           users=users,
                           following_ids=following_ids)
