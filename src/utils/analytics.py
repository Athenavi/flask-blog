"""
访问统计和用户行为分析工具模块
实现页面访问统计、用户行为跟踪和数据分析功能
"""

from flask import request
from sqlalchemy import func

from src.extensions import db
from src.models.misc import PageView, UserActivity
from src.models.user import User


def record_page_view(user_id=None, page_url=None, page_title=None, referrer=None):
    """
    记录页面访问
    
    :param user_id: 用户ID，可选
    :param page_url: 页面URL
    :param page_title: 页面标题
    :param referrer: 来源页面
    """
    try:
        # 获取当前请求信息，如果没有提供参数
        if not page_url:
            page_url = request.url if request else ''
        if not referrer and request:
            referrer = request.referrer or ''
        if not page_title and request:
            page_title = request.endpoint or ''
        
        # 解析用户代理信息
        user_agent_str = request.headers.get('User-Agent', '') if request else ''
        device_type, browser, platform = parse_user_agent(user_agent_str)
        
        # 获取IP地址
        ip_address = get_client_ip()
        
        # 创建页面访问记录
        page_view = PageView(
            user_id=user_id,
            session_id=get_session_id(),  # 需要根据实际会话系统实现
            page_url=page_url,
            page_title=page_title,
            referrer=referrer,
            user_agent=user_agent_str,
            ip_address=ip_address,
            device_type=device_type,
            browser=browser,
            platform=platform
        )
        
        db.session.add(page_view)
        db.session.commit()
        
        return page_view
    except Exception as e:
        # 记录错误但不中断请求处理
        print(f"记录页面访问时出错: {str(e)}")
        db.session.rollback()
        return None


def record_user_activity(user_id, activity_type, target_type, target_id, details=None):
    """
    记录用户活动
    
    :param user_id: 用户ID
    :param activity_type: 活动类型 (e.g., 'view', 'like', 'comment', 'share')
    :param target_type: 目标类型 (e.g., 'article', 'comment')
    :param target_id: 目标ID
    :param details: 活动详细信息
    """
    try:
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', '') if request else ''
        
        activity = UserActivity(
            user_id=user_id,
            activity_type=activity_type,
            target_type=target_type,
            target_id=target_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.session.add(activity)
        db.session.commit()
        
        return activity
    except Exception as e:
        print(f"记录用户活动时出错: {str(e)}")
        db.session.rollback()
        return None


def get_session_id():
    """
    获取当前会话ID
    这里需要根据实际的会话管理实现来获取
    """
    # 这是一个示例实现，实际应用中需要根据具体的会话系统获取session_id
    if request:
        # 例如，从cookie中获取session id
        from flask import session
        return session.get('session_id') or request.cookies.get('session')
    return None


def get_client_ip():
    """
    获取客户端IP地址
    """
    if not request:
        return None
    
    # 优先获取真实的客户端IP地址
    ip = (request.headers.get('X-Forwarded-For') or
          request.headers.get('X-Real-IP') or
          request.headers.get('X-Client-IP') or
          request.environ.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() or
          request.remote_addr)
    
    # 如果X-Forwarded-For包含多个IP，取第一个（最原始的客户端IP）
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    
    return ip


def parse_user_agent(user_agent):
    """
    解析用户代理字符串，提取设备类型、浏览器和平台信息
    """
    if not user_agent:
        return None, None, None
    
    user_agent_lower = user_agent.lower()
    
    # 设备类型检测
    device_type = 'desktop'
    if any(device in user_agent_lower for device in ['mobile', 'android', 'iphone', 'ipod', 'ipad']):
        device_type = 'mobile'
    elif any(device in user_agent_lower for device in ['tablet', 'ipad']):
        device_type = 'tablet'
    
    # 浏览器检测
    browser = 'Unknown'
    if 'chrome' in user_agent_lower and 'edge' not in user_agent_lower and 'opr' not in user_agent_lower:
        browser = 'Chrome'
    elif 'firefox' in user_agent_lower:
        browser = 'Firefox'
    elif 'safari' in user_agent_lower and 'chrome' not in user_agent_lower:
        browser = 'Safari'
    elif 'edge' in user_agent_lower:
        browser = 'Edge'
    elif 'opera' in user_agent_lower or 'opr' in user_agent_lower:
        browser = 'Opera'
    elif 'msie' in user_agent_lower or 'trident' in user_agent_lower:
        browser = 'Internet Explorer'
    
    # 平台检测
    platform = 'Unknown'
    if 'windows' in user_agent_lower:
        platform = 'Windows'
    elif 'mac' in user_agent_lower or 'darwin' in user_agent_lower:
        platform = 'macOS'
    elif 'linux' in user_agent_lower:
        platform = 'Linux'
    elif 'android' in user_agent_lower:
        platform = 'Android'
    elif 'iphone' in user_agent_lower or 'ipad' in user_agent_lower or 'ipod' in user_agent_lower:
        platform = 'iOS'
    
    return device_type, browser, platform


def get_page_views_stats(start_date=None, end_date=None, page_url=None):
    """
    获取页面访问统计信息
    
    :param start_date: 开始日期
    :param end_date: 结束日期
    :param page_url: 特定页面URL
    :return: 统计信息字典
    """
    query = db.session.query(PageView)
    
    if start_date:
        query = query.filter(PageView.created_at >= start_date)
    if end_date:
        query = query.filter(PageView.created_at <= end_date)
    if page_url:
        query = query.filter(PageView.page_url == page_url)
    
    total_views = query.count()
    unique_visitors = query.distinct(PageView.user_id, PageView.session_id).count()
    
    # 获取按日期分组的访问量
    daily_stats = db.session.query(
        func.date(PageView.created_at).label('date'),
        func.count(PageView.id).label('count')
    ).filter(PageView.created_at.isnot(None))
    
    if start_date:
        daily_stats = daily_stats.filter(PageView.created_at >= start_date)
    if end_date:
        daily_stats = daily_stats.filter(PageView.created_at <= end_date)
    if page_url:
        daily_stats = daily_stats.filter(PageView.page_url == page_url)
    
    daily_stats = daily_stats.group_by(func.date(PageView.created_at)).all()
    
    return {
        'total_views': total_views,
        'unique_visitors': unique_visitors,
        'daily_stats': [{'date': str(row.date), 'count': row.count} for row in daily_stats]
    }


def get_user_activity_stats(user_id, start_date=None, end_date=None):
    """
    获取用户活动统计信息
    
    :param user_id: 用户ID
    :param start_date: 开始日期
    :param end_date: 结束日期
    :return: 统计信息字典
    """
    query = db.session.query(UserActivity).filter(UserActivity.user_id == user_id)
    
    if start_date:
        query = query.filter(UserActivity.created_at >= start_date)
    if end_date:
        query = query.filter(UserActivity.created_at <= end_date)
    
    activities = query.all()
    
    # 按活动类型统计
    activity_counts = {}
    for activity in activities:
        activity_type = activity.activity_type
        if activity_type in activity_counts:
            activity_counts[activity_type] += 1
        else:
            activity_counts[activity_type] = 1
    
    return {
        'total_activities': len(activities),
        'activity_counts': activity_counts,
        'activities': [activity.to_dict() for activity in activities]
    }


def get_top_pages(limit=10, start_date=None, end_date=None):
    """
    获取访问量最高的页面
    
    :param limit: 返回结果数量限制
    :param start_date: 开始日期
    :param end_date: 结束日期
    :return: 页面访问统计列表
    """
    query = db.session.query(
        PageView.page_url,
        PageView.page_title,
        func.count(PageView.id).label('view_count'),
        func.count(PageView.user_id.distinct()).label('unique_visitors')
    ).group_by(PageView.page_url, PageView.page_title)
    
    if start_date:
        query = query.filter(PageView.created_at >= start_date)
    if end_date:
        query = query.filter(PageView.created_at <= end_date)
    
    top_pages = query.order_by(func.count(PageView.id).desc()).limit(limit).all()
    
    return [{
        'page_url': page.page_url,
        'page_title': page.page_title,
        'view_count': page.view_count,
        'unique_visitors': page.unique_visitors
    } for page in top_pages]


def get_user_engagement_stats(user_id):
    """
    获取用户参与度统计
    
    :param user_id: 用户ID
    :return: 参与度统计信息
    """
    user = User.query.get(user_id)
    if not user:
        return None
    
    # 计算用户的各种活动
    total_activities = UserActivity.query.filter_by(user_id=user_id).count()
    page_views = PageView.query.filter_by(user_id=user_id).count()
    
    # 计算文章相关活动
    article_activities = UserActivity.query.filter_by(
        user_id=user_id,
        target_type='article'
    ).count()
    
    return {
        'user_id': user_id,
        'username': user.username,
        'total_activities': total_activities,
        'page_views': page_views,
        'article_activities': article_activities,
        'engagement_score': (total_activities + page_views + article_activities) / 3
    }


def analyze_user_behavior(user_id, days=30):
    """
    分析用户行为模式
    
    :param user_id: 用户ID
    :param days: 分析的天数
    :return: 用户行为分析结果
    """
    from datetime import datetime, timedelta
    
    start_date = datetime.now() - timedelta(days=days)
    
    # 获取用户活动
    user_activities = UserActivity.query.filter(
        UserActivity.user_id == user_id,
        UserActivity.created_at >= start_date
    ).order_by(UserActivity.created_at.desc()).all()
    
    # 获取用户页面访问
    page_views = PageView.query.filter(
        PageView.user_id == user_id,
        PageView.created_at >= start_date
    ).order_by(PageView.created_at.desc()).all()
    
    # 按活动类型统计
    activity_types = {}
    for activity in user_activities:
        activity_type = activity.activity_type
        activity_types[activity_type] = activity_types.get(activity_type, 0) + 1
    
    # 按时间分析活动模式
    hourly_activity = {}
    for activity in user_activities:
        hour = activity.created_at.hour
        hourly_activity[hour] = hourly_activity.get(hour, 0) + 1
    
    # 按天分析活动模式
    daily_activity = {}
    for activity in user_activities:
        day = activity.created_at.strftime('%Y-%m-%d')
        daily_activity[day] = daily_activity.get(day, 0) + 1
    
    # 获取最活跃的页面
    popular_pages = {}
    for view in page_views:
        page_url = view.page_url
        popular_pages[page_url] = popular_pages.get(page_url, 0) + 1
    
    # 获取最活跃的时间段
    most_active_hour = max(hourly_activity, key=hourly_activity.get) if hourly_activity else None
    most_active_day = max(daily_activity, key=daily_activity.get) if daily_activity else None
    
    return {
        'user_id': user_id,
        'analysis_period': f'Last {days} days',
        'total_activities': len(user_activities),
        'total_page_views': len(page_views),
        'activity_types': activity_types,
        'hourly_activity': hourly_activity,
        'daily_activity': daily_activity,
        'popular_pages': dict(sorted(popular_pages.items(), key=lambda item: item[1], reverse=True)[:10]),
        'most_active_hour': most_active_hour,
        'most_active_day': most_active_day,
        'activity_timeline': [
            {
                'date': activity.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'type': activity.activity_type,
                'target': f"{activity.target_type}:{activity.target_id}",
                'details': activity.details
            } for activity in user_activities[:20]  # 只返回最近20条活动
        ]
    }


def get_behavior_insights():
    """
    获取系统用户行为洞察
    """
    from datetime import datetime, timedelta
    
    # 获取最近7天的数据
    start_date = datetime.now() - timedelta(days=7)
    
    # 获取最活跃的用户
    active_users = db.session.query(
        UserActivity.user_id,
        func.count(UserActivity.id).label('activity_count')
    ).filter(
        UserActivity.created_at >= start_date
    ).group_by(UserActivity.user_id).order_by(
        func.count(UserActivity.id).desc()
    ).limit(10).all()
    
    # 获取最活跃的页面
    popular_pages = db.session.query(
        PageView.page_url,
        PageView.page_title,
        func.count(PageView.id).label('view_count')
    ).filter(
        PageView.created_at >= start_date
    ).group_by(PageView.page_url, PageView.page_title).order_by(
        func.count(PageView.id).desc()
    ).limit(10).all()
    
    # 获取最常见的活动类型
    common_activities = db.session.query(
        UserActivity.activity_type,
        func.count(UserActivity.id).label('count')
    ).filter(
        UserActivity.created_at >= start_date
    ).group_by(UserActivity.activity_type).order_by(
        func.count(UserActivity.id).desc()
    ).all()
    
    # 按小时分析系统活动
    hourly_activity = db.session.query(
        func.hour(UserActivity.created_at).label('hour'),
        func.count(UserActivity.id).label('count')
    ).filter(
        UserActivity.created_at >= start_date
    ).group_by(func.hour(UserActivity.created_at)).order_by('hour').all()
    
    return {
        'most_active_users': [
            {
                'user_id': user.user_id,
                'activity_count': user.activity_count,
                'username': User.query.get(user.user_id).username if User.query.get(user.user_id) else 'Unknown'
            } for user in active_users
        ],
        'popular_pages': [
            {
                'page_url': page.page_url,
                'page_title': page.page_title,
                'view_count': page.view_count
            } for page in popular_pages
        ],
        'common_activities': [
            {
                'activity_type': activity.activity_type,
                'count': activity.count
            } for activity in common_activities
        ],
        'hourly_activity': [
            {
                'hour': activity.hour,
                'count': activity.count
            } for activity in hourly_activity
        ]
    }