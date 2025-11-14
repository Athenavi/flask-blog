from datetime import datetime

from flask import Blueprint, session as flask_session
from flask_login import login_required

from src.models import UserSession, User, db

session_bp = Blueprint('session', __name__)


@session_bp.route('/api/sessions/<session_id>', methods=['DELETE'])
@login_required
def logout_session(session_id):
    """退出特定会话"""
    success = current_user.logout_session(session_id)

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


from flask import render_template, request, jsonify
from flask_login import login_required, current_user


# 管理员权限
# admin_permission = Permission(RoleNeed('admin'))


@session_bp.route('/sessions')
@login_required
def user_sessions():
    """用户查看自己的会话"""
    sessions = UserSession.get_active_sessions(current_user.id)
    return render_template('session/user.html', sessions=sessions)


@session_bp.route('/admin/sessions')
@login_required
# @admin_permission.require()
def admin_sessions():
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
