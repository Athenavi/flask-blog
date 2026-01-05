"""
Dashboard 杂项管理模块
包含事件、举报、短链接、搜索历史等功能
"""
import inspect
from datetime import datetime

from flask import request, render_template, jsonify
from sqlalchemy import func

from src.auth_utils import admin_required
from src.extensions import limiter
from src.models import User, db, Event, Report, Url, SearchHistory
from . import admin_bp


def get_db_session_and_user(user_id):
    """获取数据库会话和当前用户"""
    db_session = db.session()
    current_user = db_session.query(User).filter_by(id=user_id).first()
    return db_session, current_user


def handle_pagination(page, per_page, query):
    """处理分页的通用函数"""
    return query.paginate(page=page, per_page=per_page, error_out=False)


def get_pagination_params():
    """获取分页参数"""
    return {
        'page_events': request.args.get('page_events', 1, type=int),
        'page_reports': request.args.get('page_reports', 1, type=int),
        'page_urls': request.args.get('page_urls', 1, type=int),
        'page_search': request.args.get('page_search', 1, type=int),
        'per_page': 10
    }


def handle_event_action_internal(db_session, form_data):
    """内部事件处理函数（供兼容接口使用）"""
    action = form_data.get('event_action')

    if action == 'create_event':
        title = form_data.get('title')
        description = form_data.get('description', '')
        event_date = form_data.get('event_date')

        if not title or not event_date:
            return jsonify({'success': False, 'message': '事件标题和日期不能为空'})

        try:
            event_date_obj = datetime.strptime(event_date, '%Y-%m-%dT%H:%M')
        except ValueError:
            return jsonify({'success': False, 'message': '日期格式错误'})

        event = Event(
            title=title,
            description=description,
            event_date=event_date_obj,
            created_at=datetime.now()
        )
        db_session.add(event)
        db_session.commit()
        return jsonify({'success': True, 'message': '事件创建成功'})

    elif action == 'update_event':
        event_id = form_data.get('event_id')
        title = form_data.get('title')
        description = form_data.get('description', '')
        event_date = form_data.get('event_date')

        event = db_session.query(Event).filter_by(id=event_id).first()
        if not event:
            return jsonify({'success': False, 'message': '事件不存在'})

        try:
            event_date_obj = datetime.strptime(event_date, '%Y-%m-%dT%H:%M')
        except ValueError:
            return jsonify({'success': False, 'message': '日期格式错误'})

        event.title = title
        event.description = description
        event.event_date = event_date_obj
        db_session.commit()
        return jsonify({'success': True, 'message': '事件更新成功'})

    elif action == 'delete_event':
        event_id = form_data.get('event_id')
        event = db_session.query(Event).filter_by(id=event_id).first()
        if event:
            db_session.delete(event)
            db_session.commit()
            return jsonify({'success': True, 'message': '事件已删除'})
        return jsonify({'success': False, 'message': '事件不存在'})

    return jsonify({'success': False, 'message': '未知的事件操作'})


def handle_report_action_internal(db_session, form_data):
    """内部举报处理函数（供兼容接口使用）"""
    action = form_data.get('report_action')

    if action == 'delete_report':
        report_id = form_data.get('report_id')
        report = db_session.query(Report).filter_by(id=report_id).first()
        if report:
            db_session.delete(report)
            db_session.commit()
            return jsonify({'success': True, 'message': '举报记录已删除'})
        return jsonify({'success': False, 'message': '举报记录不存在'})

    elif action == 'process_report':
        report_id = form_data.get('report_id')
        report = db_session.query(Report).filter_by(id=report_id).first()
        if report:
            report.status = 'processed'
            report.processed_at = datetime.now()
            db_session.commit()
            return jsonify({'success': True, 'message': '举报已处理'})
        return jsonify({'success': False, 'message': '举报记录不存在'})

    return jsonify({'success': False, 'message': '未知的举报操作'})


def handle_url_action_internal(db_session, form_data):
    """内部短链接处理函数（供兼容接口使用）"""
    action = form_data.get('url_action')

    if action == 'create_url':
        long_url = form_data.get('long_url')
        short_url = form_data.get('short_url')
        user_id_url = form_data.get('user_id')

        if not long_url or not short_url:
            return jsonify({'success': False, 'message': '长链接和短链接不能为空'})

        # 检查短链接是否已存在
        existing_url = db_session.query(Url).filter_by(short_url=short_url).first()
        if existing_url:
            return jsonify({'success': False, 'message': '短链接已存在'})

        url = Url(
            long_url=long_url,
            short_url=short_url,
            user_id=user_id_url,
            created_at=datetime.now()
        )
        db_session.add(url)
        db_session.commit()
        return jsonify({'success': True, 'message': '短链接创建成功'})

    elif action == 'delete_url':
        url_id = form_data.get('url_id')
        url = db_session.query(Url).filter_by(id=url_id).first()
        if url:
            db_session.delete(url)
            db_session.commit()
            return jsonify({'success': True, 'message': '短链接已删除'})
        return jsonify({'success': False, 'message': '短链接不存在'})

    return jsonify({'success': False, 'message': '未知的短链接操作'})


def handle_search_history_action_internal(db_session, form_data):
    """内部搜索历史处理函数（供兼容接口使用）"""
    action = form_data.get('search_history_action')

    if action == 'delete_history':
        history_id = form_data.get('history_id')
        history = db_session.query(SearchHistory).filter_by(id=history_id).first()
        if history:
            db_session.delete(history)
            db_session.commit()
            return jsonify({'success': True, 'message': '搜索记录已删除'})
        return jsonify({'success': False, 'message': '搜索记录不存在'})

    elif action == 'clear_user_history':
        user_id_history = form_data.get('user_id')
        db_session.query(SearchHistory).filter_by(user_id=user_id_history).delete()
        db_session.commit()
        return jsonify({'success': True, 'message': '用户搜索记录已清空'})

    elif action == 'clear_all_history':
        db_session.query(SearchHistory).delete()
        db_session.commit()
        return jsonify({'success': True, 'message': '所有搜索记录已清空'})

    return jsonify({'success': False, 'message': '未知的搜索历史操作'})


# ===================== 事件相关操作（专用接口） =====================

@admin_bp.route('/misc/events', methods=['GET', 'POST'])
@admin_required
@limiter.limit("10 per minute")
def admin_misc_events(user_id):
    """处理事件相关操作 - 专用接口"""
    try:
        db_session, current_user = get_db_session_and_user(user_id)

        if request.method == 'POST':
            return handle_event_action_internal(db_session, request.form)

        # GET请求 - 获取事件列表
        pagination_params = get_pagination_params()
        events_query = db_session.query(Event).order_by(Event.event_date.desc())
        events_pagination = handle_pagination(
            pagination_params['page_events'],
            pagination_params['per_page'],
            events_query
        )

        return jsonify({
            'events_pagination': {
                'items': [event.to_dict() for event in events_pagination.items],
                'page': events_pagination.page,
                'pages': events_pagination.pages,
                'total': events_pagination.total,
                'has_next': events_pagination.has_next,
                'has_prev': events_pagination.has_prev
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        print(f"==>{current_func_name}, User ID: {user_id}")


# ===================== 举报相关操作（专用接口） =====================

@admin_bp.route('/misc/reports', methods=['GET', 'POST'])
@admin_required
@limiter.limit("10 per minute")
def admin_misc_reports(user_id):
    """处理举报相关操作 - 专用接口"""
    try:
        db_session, current_user = get_db_session_and_user(user_id)

        if request.method == 'POST':
            return handle_report_action_internal(db_session, request.form)

        # GET请求 - 获取举报列表
        pagination_params = get_pagination_params()
        reports_query = db_session.query(Report).join(User, Report.reported_by == User.id) \
            .order_by(Report.created_at.desc())
        reports_pagination = handle_pagination(
            pagination_params['page_reports'],
            pagination_params['per_page'],
            reports_query
        )

        return jsonify({
            'reports_pagination': {
                'items': [report.to_dict() for report in reports_pagination.items],
                'page': reports_pagination.page,
                'pages': reports_pagination.pages,
                'total': reports_pagination.total,
                'has_next': reports_pagination.has_next,
                'has_prev': reports_pagination.has_prev
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        print(f"==>{current_func_name}, User ID: {user_id}")


# ===================== 短链接相关操作（专用接口） =====================

@admin_bp.route('/misc/urls', methods=['GET', 'POST'])
@admin_required
@limiter.limit("10 per minute")
def admin_misc_urls(user_id):
    """处理短链接相关操作 - 专用接口"""
    try:
        db_session, current_user = get_db_session_and_user(user_id)

        if request.method == 'POST':
            return handle_url_action_internal(db_session, request.form)

        # GET请求 - 获取短链接列表
        pagination_params = get_pagination_params()
        urls_query = db_session.query(Url).join(User, Url.user_id == User.id) \
            .order_by(Url.created_at.desc())
        urls_pagination = handle_pagination(
            pagination_params['page_urls'],
            pagination_params['per_page'],
            urls_query
        )

        return jsonify({
            'urls_pagination': {
                'items': [url.to_dict() for url in urls_pagination.items],
                'page': urls_pagination.page,
                'pages': urls_pagination.pages,
                'total': urls_pagination.total,
                'has_next': urls_pagination.has_next,
                'has_prev': urls_pagination.has_prev
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        print(f"==>{current_func_name}, User ID: {user_id}")


# ===================== 搜索历史相关操作（专用接口） =====================

@admin_bp.route('/misc/search-history', methods=['GET', 'POST'])
@admin_required
@limiter.limit("10 per minute")
def admin_misc_search_history(user_id):
    """处理搜索历史相关操作 - 专用接口"""
    try:
        db_session, current_user = get_db_session_and_user(user_id)

        if request.method == 'POST':
            return handle_search_history_action_internal(db_session, request.form)

        # GET请求 - 获取搜索历史列表和统计信息
        pagination_params = get_pagination_params()
        search_history_query = db_session.query(SearchHistory).order_by(SearchHistory.created_at.desc())
        search_history_pagination = handle_pagination(
            pagination_params['page_search'],
            pagination_params['per_page'],
            search_history_query
        )

        # 获取搜索统计（前10个热门关键词）
        search_stats = db_session.query(
            SearchHistory.keyword,
            func.count(SearchHistory.id).label('search_count')
        ).group_by(SearchHistory.keyword) \
            .order_by(func.count(SearchHistory.id).desc()) \
            .limit(10).all()

        return jsonify({
            'search_history_pagination': {
                'items': [history.to_dict() for history in search_history_pagination.items],
                'page': search_history_pagination.page,
                'pages': search_history_pagination.pages,
                'total': search_history_pagination.total,
                'has_next': search_history_pagination.has_next,
                'has_prev': search_history_pagination.has_prev
            },
            'search_stats': [
                {'keyword': stat.keyword, 'count': stat.search_count}
                for stat in search_stats
            ]
        })

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        print(f"==>{current_func_name}, User ID: {user_id}")


# ===================== 兼容层接口 =====================

@admin_bp.route('/misc', methods=['GET', 'POST', 'PUT', 'DELETE'])
@admin_required
def admin_misc(user_id):
    """兼容层接口 - 完全独立实现，不调用其他视图函数"""
    try:
        db_session, current_user = get_db_session_and_user(user_id)

        # 处理POST请求（各种action）
        if request.method == 'POST':
            # 检查事件相关的action
            if 'event_action' in request.form:
                return handle_event_action_internal(db_session, request.form)

            # 检查举报相关的action
            elif 'report_action' in request.form:
                return handle_report_action_internal(db_session, request.form)

            # 检查短链接相关的action
            elif 'url_action' in request.form:
                return handle_url_action_internal(db_session, request.form)

            # 检查搜索历史相关的action
            elif 'search_history_action' in request.form:
                return handle_search_history_action_internal(db_session, request.form)

            return jsonify({'success': False, 'message': '未知的操作类型'})

        # GET请求 - 合并所有数据并渲染模板
        pagination_params = get_pagination_params()

        try:
            # 1. 获取事件数据
            events_query = db_session.query(Event).order_by(Event.event_date.desc())
            events_pagination = handle_pagination(
                pagination_params['page_events'],
                pagination_params['per_page'],
                events_query
            )

            # 2. 获取举报数据
            reports_query = db_session.query(Report).join(User, Report.reported_by == User.id) \
                .order_by(Report.created_at.desc())
            reports_pagination = handle_pagination(
                pagination_params['page_reports'],
                pagination_params['per_page'],
                reports_query
            )

            # 3. 获取短链接数据
            urls_query = db_session.query(Url).join(User, Url.user_id == User.id) \
                .order_by(Url.created_at.desc())
            urls_pagination = handle_pagination(
                pagination_params['page_urls'],
                pagination_params['per_page'],
                urls_query
            )

            # 4. 获取搜索历史数据
            search_history_query = db_session.query(SearchHistory).order_by(SearchHistory.created_at.desc())
            search_history_pagination = handle_pagination(
                pagination_params['page_search'],
                pagination_params['per_page'],
                search_history_query
            )

            # 5. 获取搜索统计
            search_stats = db_session.query(
                SearchHistory.keyword,
                func.count(SearchHistory.id).label('search_count')
            ).group_by(SearchHistory.keyword) \
                .order_by(func.count(SearchHistory.id).desc()) \
                .limit(10).all()

        except Exception as e:
            # 如果获取数据失败，尝试渲染空页面
            events_pagination = reports_pagination = urls_pagination = search_history_pagination = None
            search_stats = []
            print(f"获取数据失败: {str(e)}")

        return render_template('dashboard/misc.html',
                               events_pagination=events_pagination,
                               reports_pagination=reports_pagination,
                               urls_pagination=urls_pagination,
                               search_history_pagination=search_history_pagination,
                               search_stats=search_stats,
                               current_user=current_user,
                               page_events=pagination_params['page_events'],
                               page_reports=pagination_params['page_reports'],
                               page_urls=pagination_params['page_urls'],
                               page_search=pagination_params['page_search'])

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        print(f"==>{current_func_name}, User ID: {user_id}")
