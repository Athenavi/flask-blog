from datetime import datetime

from flask import Blueprint, session as flask_session
from flask import render_template, request, jsonify
from flask_login import current_user
from flask_login import login_required

from src.auth_utils import admin_required
from src.models import UserSession, User, db, Role

session_bp = Blueprint('session', __name__)


@session_bp.route('/api/sessions/<session_id>', methods=['DELETE'])
@login_required
def logout_session(session_id):
    """退出特定会话"""
    # 查找会话
    user_session = UserSession.get_by_session_id(session_id)

    # 检查会话是否存在且属于当前用户
    if user_session and user_session.user_id == current_user.id:
        # 直接从数据库中删除记录
        db.session.delete(user_session)
        db.session.commit()
        success = True
    else:
        success = False

    if success:
        return jsonify({'message': '会话已退出'})
    else:
        return jsonify({'error': '会话不存在或无权操作'}), 404


@session_bp.route('/api/sessions/others', methods=['DELETE'])
@login_required
def logout_other_sessions():
    """退出除当前会话外的所有其他会话"""
    current_session_id = flask_session.get('internal_sid')
    count = current_user.logout_all_other_sessions(current_session_id)

    return jsonify({
        'message': f'已退出 {count} 个其他会话',
        'logged_out_count': count
    })


@session_bp.route('/sessions')
@login_required
def user_sessions():
    """用户查看自己的会话"""
    sessions = UserSession.get_active_sessions(current_user.id)
    return render_template('session/user.html', sessions=sessions)


@session_bp.route('/admin/sessions')
@admin_required
def admin_sessions(user_id):
    """管理员查看所有用户会话"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    device_type = request.args.get('device_type', '')
    status = request.args.get('status', '')

    # 构建查询
    query = UserSession.query.join(User)

    if search:
        query = query.filter(
            (User.username.ilike(f'%{search}%')) |
            (User.email.ilike(f'%{search}%'))
        )

    if device_type:
        query = query.filter(UserSession.device_type == device_type)

    if status == 'active':
        query = query.filter(UserSession.is_active == True)
    elif status == 'inactive':
        query = query.filter(UserSession.is_active == False)

    # 分页 - 按用户名排序，然后按最后活动时间排序，以便前端可以正确分组
    pagination = query.order_by(
        User.username,
        UserSession.last_activity.desc()
    ).paginate(
        page=page, per_page=20, error_out=False
    )

    # 统计数据
    total_sessions = UserSession.query.count()
    active_sessions = UserSession.query.filter_by(is_active=True).count()
    online_users = db.session.query(db.func.count(db.distinct(UserSession.user_id))).filter_by(is_active=True).scalar()
    mobile_sessions = UserSession.query.filter_by(device_type='mobile').count()
    today_sessions = UserSession.query.filter(
        UserSession.last_activity >= datetime.now().date()
    ).count()
    total_users = User.query.count()

    return render_template(
        'session/admin.html',
        sessions=pagination.items,
        pagination=pagination,
        total_sessions=total_sessions,
        active_sessions=active_sessions,
        online_users=online_users,
        mobile_sessions=mobile_sessions,
        today_sessions=today_sessions,
        total_users=total_users
    )


@session_bp.route('/admin/user/<int:user_id>/ban', methods=['POST'])
@admin_required
def ban_user(user_id):
    """管理员封禁用户"""
    try:
        # 获取要封禁的用户
        user_to_ban = User.query.get(user_id)

        if not user_to_ban:
            return jsonify({
                'success': False,
                'message': '用户不存在'
            }), 404

        # 检查是否试图封禁自己
        if user_to_ban.id == user_id:
            return jsonify({
                'success': False,
                'message': '不能封禁自己'
            }), 400

        # 检查用户是否已经是管理员
        if user_to_ban.has_role('admin'):
            return jsonify({
                'success': False,
                'message': '不能封禁管理员用户'
            }), 403

        # 封禁用户 - 这里我们通过设置一个特殊角色来实现
        # 在这个系统中，我们通过添加一个"banned"角色来实现封禁功能
        banned_role = db.session.query(Role).filter_by(name='banned').first()
        if not banned_role:
            # 如果banned角色不存在，创建它
            banned_role = Role(name='banned', description='封禁用户')
            db.session.add(banned_role)
            db.session.flush()

        # 检查用户是否已经被封禁
        if user_to_ban.has_role('banned'):
            return jsonify({
                'success': False,
                'message': '用户已被封禁'
            }), 400

        # 添加封禁角色
        user_to_ban.roles.append(banned_role)

        # 使用户的所有会话失效
        active_sessions = UserSession.query.filter_by(
            user_id=user_id,
            is_active=True
        ).all()

        for session in active_sessions:
            session.deactivate()

        # 清除该用户的缓存
        from src.extensions import cache
        cache_key = f"user_banned_status_{user_id}"
        cache.delete(cache_key)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'用户 {user_to_ban.username} 已被封禁'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'封禁用户失败: {str(e)}'
        }), 500
