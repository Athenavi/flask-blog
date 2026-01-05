"""
分析和统计蓝图
提供访问统计、用户行为分析等API端点
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required
from sqlalchemy import func

from src.auth_utils import admin_required
from src.extensions import db
from src.models.misc import PageView, UserActivity
from src.models.user import User
from src.utils.analytics import (
    get_page_views_stats,
    get_user_activity_stats,
    get_top_pages,
    get_user_engagement_stats,
    analyze_user_behavior,
    get_behavior_insights
)

analytics_bp = Blueprint('analytics', __name__, url_prefix='/api/analytics')


@analytics_bp.route('/dashboard', methods=['GET'])
@admin_required
def dashboard_stats(user_id):
    """
    获取分析仪表板数据
    """
    try:
        # 获取总体统计数据
        total_page_views = PageView.query.count()
        total_user_activities = UserActivity.query.count()
        total_unique_users = db.session.query(PageView.user_id).distinct(PageView.user_id).count()

        # 获取最近7天的数据
        from datetime import datetime, timedelta
        start_date = datetime.utcnow() - timedelta(days=7)

        recent_page_views = PageView.query.filter(PageView.created_at >= start_date).count()
        recent_user_activities = UserActivity.query.filter(UserActivity.created_at >= start_date).count()

        # 获取最活跃的用户
        active_users = db.session.query(
            UserActivity.user_id,
            func.count(UserActivity.id).label('activity_count')
        ).filter(
            UserActivity.created_at >= start_date
        ).group_by(UserActivity.user_id).order_by(
            func.count(UserActivity.id).desc()
        ).limit(5).all()

        # 获取最活跃的页面
        popular_pages = get_top_pages(limit=5, start_date=start_date)

        return jsonify({
            'success': True,
            'data': {
                'total_page_views': total_page_views,
                'total_user_activities': total_user_activities,
                'total_unique_users': total_unique_users,
                'recent_page_views': recent_page_views,
                'recent_user_activities': recent_user_activities,
                'active_users': [
                    {
                        'user_id': user.user_id,
                        'activity_count': user.activity_count,
                        'username': User.query.get(user.user_id).username if User.query.get(user.user_id) else 'Unknown'
                    } for user in active_users
                ],
                'popular_pages': popular_pages
            }
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取分析数据时出错: {str(e)}'
        }), 500


@analytics_bp.route('/page-views', methods=['GET'])
@admin_required
def page_views_stats(user_id):
    """
    获取页面访问统计
    """
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        page_url = request.args.get('page_url')

        stats = get_page_views_stats(
            start_date=start_date,
            end_date=end_date,
            page_url=page_url
        )

        return jsonify({
            'success': True,
            'data': stats
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取页面访问统计时出错: {str(e)}'
        }), 500


@analytics_bp.route('/user-activity/<int:user_id>', methods=['GET'])
@login_required
def user_activity_stats(current_user_id, user_id):
    """
    获取特定用户活动统计
    管理员可以查看任何用户，普通用户只能查看自己的
    """
    try:
        # 检查权限
        from src.models import User
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404

        # 检查权限：用户只能查看自己的数据，除非是管理员
        is_admin = user.has_role('admin') or user.has_permission('admin_access')
        if current_user_id != user_id and not is_admin:
            return jsonify({'success': False, 'message': '权限不足'}), 403

        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        stats = get_user_activity_stats(
            user_id=user_id,
            start_date=start_date,
            end_date=end_date
        )

        return jsonify({
            'success': True,
            'data': stats
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取用户活动统计时出错: {str(e)}'
        }), 500


@analytics_bp.route('/user-activities', methods=['GET'])
@admin_required
def user_activities_stats(user_id):
    """
    获取所有用户活动统计
    """
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))

        # 计算分页偏移量
        offset = (page - 1) * per_page

        # 查询所有用户活动，支持分页和日期筛选
        query = db.session.query(UserActivity)

        if start_date:
            query = query.filter(UserActivity.created_at >= start_date)
        if end_date:
            query = query.filter(UserActivity.created_at <= end_date)

        # 获取总数
        total_activities = query.count()

        # 获取分页数据
        activities = query.offset(offset).limit(per_page).all()

        # 按用户分组统计活动
        user_activity_stats = {}
        for activity in activities:
            user_id = activity.user_id
            if user_id not in user_activity_stats:
                user_activity_stats[user_id] = {
                    'user_id': user_id,
                    'activity_count': 0,
                    'activity_types': {}
                }

            user_activity_stats[user_id]['activity_count'] += 1
            activity_type = activity.activity_type
            user_activity_stats[user_id]['activity_types'][activity_type] = \
                user_activity_stats[user_id]['activity_types'].get(activity_type, 0) + 1

        # 获取用户名（如果可能）
        for user_data in user_activity_stats.values():
            user = User.query.get(user_data['user_id'])
            user_data['username'] = user.username if user else 'Unknown'

        # 转换为列表格式
        stats_list = list(user_activity_stats.values())

        return jsonify({
            'success': True,
            'data': {
                'activities': stats_list,
                'total': total_activities,
                'page': page,
                'per_page': per_page,
                'pages': (total_activities + per_page - 1) // per_page
            }
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取用户活动统计时出错: {str(e)}'
        }), 500


@analytics_bp.route('/user-engagement/<int:user_id>', methods=['GET'])
@login_required
def user_engagement(current_user_id, user_id):
    """
    获取用户参与度统计
    """
    try:
        # 检查权限
        from src.models import User
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404

        # 检查权限：用户只能查看自己的数据，除非是管理员
        is_admin = user.has_role('admin') or user.has_permission('admin_access')
        if current_user_id != user_id and not is_admin:
            return jsonify({'success': False, 'message': '权限不足'}), 403

        stats = get_user_engagement_stats(user_id=user_id)

        return jsonify({
            'success': True,
            'data': stats
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取用户参与度统计时出错: {str(e)}'
        }), 500


@analytics_bp.route('/top-pages', methods=['GET'])
@admin_required
def top_pages(current_user_id):
    """
    获取访问量最高的页面
    """
    try:
        limit = int(request.args.get('limit', 10))
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        top_pages_list = get_top_pages(
            limit=limit,
            start_date=start_date,
            end_date=end_date
        )

        return jsonify({
            'success': True,
            'data': top_pages_list
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取热门页面时出错: {str(e)}'
        }), 500


@analytics_bp.route('/user-behavior/<int:user_id>', methods=['GET'])
@login_required
def user_behavior_analysis(current_user_id, user_id):
    """
    分析特定用户的行为模式
    """
    try:
        # 检查权限
        from src.models import User
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404

        # 检查权限：用户只能查看自己的数据，除非是管理员
        is_admin = user.has_role('admin') or user.has_permission('admin_access')
        if current_user_id != user_id and not is_admin:
            return jsonify({'success': False, 'message': '权限不足'}), 403

        days = int(request.args.get('days', 30))

        analysis = analyze_user_behavior(user_id=user_id, days=days)

        return jsonify({
            'success': True,
            'data': analysis
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'分析用户行为时出错: {str(e)}'
        }), 500


@analytics_bp.route('/system-insights', methods=['GET'])
@admin_required
def system_behavior_insights(current_user_id):
    """
    获取系统用户行为洞察
    """
    try:
        insights = get_behavior_insights()

        return jsonify({
            'success': True,
            'data': insights
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取系统洞察时出错: {str(e)}'
        }), 500
