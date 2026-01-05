"""
Dashboard 主要管理功能模块
包含用户管理、文章管理、分类管理等核心功能
"""
import inspect
from datetime import datetime, timedelta

import bcrypt
from flask import request, render_template, jsonify
from sqlalchemy import func

from src.auth_utils import admin_required
from src.extensions import limiter
from src.models import User, Article, ArticleContent, ArticleI18n, Category, db, CategorySubscription, PageView, \
    UserActivity
from src.utils.security.safe import validate_email_base
from . import admin_bp


@admin_bp.route('/index', methods=['GET'])
@admin_required
def admin_index(user_id):
    try:
        # 获取用户信息
        users_count = db.session.query(User).count()
        # 获取文章数量
        articles_count = db.session.query(Article).count()
        # 获取评论数量
        comments_count = 0

        # 获取最近活动数据
        recent_activities = db.session.query(UserActivity).order_by(UserActivity.created_at.desc()).limit(5).all()

        # 准备活动数据
        activities = []
        for activity in recent_activities:
            user = User.query.get(activity.user_id)
            activity_data = {
                'user_name': user.username if user else 'Unknown User',
                'activity_type': activity.activity_type,
                'target_type': activity.target_type,
                'target_id': activity.target_id,
                'details': activity.details,
                'created_at': activity.created_at,
                'icon': 'fas fa-chart-bar' if activity.activity_type == 'view' else \
                    'fas fa-user-plus' if activity.activity_type == 'register' else \
                        'fas fa-file-alt' if activity.activity_type == 'create_article' else \
                            'fas fa-heart' if activity.activity_type == 'like' else \
                                'fas fa-comment' if activity.activity_type == 'comment' else \
                                    'fas fa-share-alt' if activity.activity_type == 'share' else \
                                        'fas fa-chart-line'
            }
            activities.append(activity_data)

        current_user = db.session.query(User).filter_by(id=user_id).first()
        return render_template('dashboard/index.html', users_count=users_count, articles_count=articles_count,
                               comments_count=comments_count, current_user=current_user, activities=activities)
    except Exception as e:
        return jsonify({'error': str(e)})


@admin_bp.route('/recent-activities', methods=['GET'])
@admin_required
def get_recent_activities(user_id):
    """获取最近活动数据API"""
    try:
        # 获取最近活动数据
        recent_activities = db.session.query(UserActivity).order_by(UserActivity.created_at.desc()).limit(10).all()

        # 准备活动数据
        activities = []
        for activity in recent_activities:
            user = User.query.get(activity.user_id)
            activity_data = {
                'id': activity.id,
                'user_name': user.username if user else 'Unknown User',
                'activity_type': activity.activity_type,
                'target_type': activity.target_type,
                'target_id': activity.target_id,
                'details': activity.details,
                'created_at': activity.created_at.isoformat() if activity.created_at else None,
                'icon': 'fas fa-chart-bar' if activity.activity_type == 'view' else \
                    'fas fa-user-plus' if activity.activity_type == 'register' else \
                        'fas fa-file-alt' if activity.activity_type == 'create_article' else \
                            'fas fa-heart' if activity.activity_type == 'like' else \
                                'fas fa-comment' if activity.activity_type == 'comment' else \
                                    'fas fa-share-alt' if activity.activity_type == 'share' else \
                                        'fas fa-chart-line'
            }
            activities.append(activity_data)

        return jsonify({
            'success': True,
            'data': activities
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取最近活动失败: {str(e)}'
        }), 500


@admin_bp.route('/', methods=['GET'])
@admin_required
def admin_user(user_id):
    try:
        current_user = db.session.query(User).filter_by(id=user_id).first()
        return render_template('dashboard/user.html', current_user=current_user)
    except Exception as e:
        return jsonify({'error': str(e)})


@admin_bp.route('/blog', methods=['GET'])
@admin_required
def admin_blog(user_id):
    current_user = db.session.query(User).filter_by(id=user_id).first()
    return render_template('dashboard/blog.html', current_user=current_user)


@admin_bp.route('/analytics', methods=['GET'])
@admin_required
def admin_analytics(user_id):
    """分析仪表板页面"""
    current_user = db.session.query(User).filter_by(id=user_id).first()
    return render_template('dashboard/analytics.html', current_user=current_user)


@admin_bp.route('/analytics/data', methods=['GET'])
@admin_required
def admin_analytics_data(user_id):
    """获取分析数据API"""
    try:
        # 获取总体统计数据
        total_page_views = PageView.query.count()
        total_user_activities = UserActivity.query.count()
        total_unique_users = db.session.query(PageView.user_id).distinct(PageView.user_id).count()

        # 获取最近7天的数据
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
        from src.utils.analytics import get_top_pages
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


@admin_bp.route('/user', methods=['GET'])
@admin_required
@limiter.limit("20 per minute")
def get_users(user_id):
    """获取用户列表 - 支持分页和搜索"""
    try:
        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search = request.args.get('search', '', type=str)

        # 构建查询
        query = User.query

        # 搜索功能
        if search:
            query = query.filter(
                db.session.or_(
                    User.username.contains(search),
                    User.email.contains(search),
                    User.bio.contains(search)
                )
            )

        # 分页
        users = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

        # 序列化用户数据
        users_data = []
        for user in users.items:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'profile_picture': user.profile_picture,
                'bio': user.bio,
                'register_ip': user.register_ip,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'updated_at': user.updated_at.isoformat() if user.updated_at else None,
                'media_count': len(user.media),
                'comment_count': 0
            })

        return jsonify({
            'success': True,
            'data': users_data,
            'pagination': {
                'page': users.page,
                'pages': users.pages,
                'per_page': users.per_page,
                'total': users.total,
                'has_next': users.has_next,
                'has_prev': users.has_prev
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取用户列表失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/user', methods=['POST'])
@admin_required
@limiter.limit("5 per minute")
def create_user(user_id):
    """创建新用户"""
    try:
        data = request.get_json()

        # 验证必填字段
        required_fields = ['username', 'password', 'email']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'缺少必填字段: {field}'
                }), 400

        # 验证邮箱格式
        if not validate_email_base(data['email']):
            return jsonify({
                'success': False,
                'message': '邮箱格式不正确'
            }), 400

        # 验证用户名长度
        if len(data['username']) < 3 or len(data['username']) > 255:
            return jsonify({
                'success': False,
                'message': '用户名长度必须在3-255个字符之间'
            }), 400

        # 验证密码强度
        if len(data['password']) < 8:
            return jsonify({
                'success': False,
                'message': '密码长度至少8个字符'
            }), 400

        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

        # 创建新用户
        new_user = User(
            username=data['username'],
            password=hashed_password.decode('utf-8'),
            email=data['email'],
            bio=data.get('bio'),
            register_ip="（系统维护）",
            locale="zh_CN",
            profile_private=False,
        )

        db.session.add(new_user)
        db.session.commit()
        db.session.flush()  # 确保 new_user.id 和 created_at 已经被设置

        return jsonify({
            'success': True,
            'message': '用户创建成功',
            'data': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email,
                'created_at': new_user.created_at.isoformat(),
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'创建用户失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/user/<int:user_id2>', methods=['PUT'])
@admin_required
def update_user(user_id, user_id2):
    """更新用户信息"""
    user = db.session.query(User).filter_by(id=user_id2).first()
    data = request.get_json()

    # 更新用户名
    if 'username' in data:
        if len(data['username']) < 3 or len(data['username']) > 255:
            return jsonify({
                'success': False,
                'message': '用户名长度必须在3-255个字符之间'
            }), 400
        user.username = data['username']

    # 更新邮箱
    if 'email' in data:
        if not validate_email_base(data['email']):
            return jsonify({
                'success': False,
                'message': '邮箱格式不正确'
            }), 400
        user.email = data['email']

    # 更新密码
    if 'password' in data:
        if len(data['password']) < 6:
            return jsonify({
                'success': False,
                'message': '密码长度至少6个字符'
            }), 400
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        user.password = hashed_password.decode('utf-8')

    # 更新其他字段
    if 'profile_picture' in data:
        user.profile_picture = data['profile_picture']

    if 'bio' in data:
        user.bio = data['bio']

    user.updated_at = datetime.today()
    db.session.commit()
    return jsonify({
        'success': True,
        'message': '用户更新成功',
        'data': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'profile_picture': user.profile_picture,
            'bio': user.bio,
            'updated_at': user.updated_at.isoformat()
        }
    }), 200


@admin_bp.route('/user/<int:user_id2>', methods=['DELETE'])
@admin_required
def delete_user(user_id, user_id2):
    """删除用户"""
    try:
        user = db.session.query(User).filter_by(id=user_id2).first()

        # 检查用户是否有关联数据
        media_count = len(user.media)
        comment_count = 0

        if media_count > 0:
            return jsonify({
                'success': False,
                'message': f'无法删除用户，该用户有 {media_count} 个媒体文件',
                'details': {
                    'media_count': media_count,

                }
            }), 409

        username = user.username
        db.session.delete(user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'用户 {username} 删除成功'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'删除用户失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/user/<int:user_id2>', methods=['GET'])
@admin_required
def get_user(user_id, user_id2):
    """获取单个用户详情"""
    try:
        user = User.query.get_or_404(user_id2)

        return jsonify({
            'success': True,
            'data': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'profile_picture': user.profile_picture,
                'bio': user.bio,
                'register_ip': user.register_ip,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'updated_at': user.updated_at.isoformat() if user.updated_at else None,
                'media_count': len(user.media),
                'comment_count': 0
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取用户详情失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_stats(user_id):
    """获取统计数据"""
    try:
        total_users = User.query.count()
        recent_users = User.query.filter(
            User.created_at >= datetime.today()
        ).count()

        return jsonify({
            'success': True,
            'data': {
                'total_users': total_users,
                'recent_users': recent_users,
                'active_users': total_users  # 简化统计
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取统计数据失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/article', methods=['GET'])
@admin_required
@limiter.limit("20 per minute")
def get_articles(user_id):
    """获取文章列表 - 支持分页和搜索"""

    try:
        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search = request.args.get('search', '', type=str)
        status = request.args.get('status', '', type=str)

        # 构建查询
        query = Article.query

        # 搜索功能
        if search:
            query = query.filter(
                db.session.or_(
                    Article.title.contains(search),
                    Article.excerpt.contains(search)
                )
            )

        # 状态筛选
        if status:
            # 将字符串状态转换为整数状态
            status_mapping = {
                'Draft': 0,
                'Published': 1,
                'Deleted': -1,
                '0': 0,
                '1': 1,
                '-1': -1
            }
            if status in status_mapping:
                query = query.filter(Article.status == status_mapping[status])
            else:
                # 如果状态值不在映射中，返回错误
                return jsonify({
                    'success': False,
                    'message': f'无效的状态值: {status}. 有效值为: Draft, Published, Deleted, 0, 1, -1'
                }), 400

        # 按创建时间倒序排列
        query = query.order_by(Article.created_at.desc())

        # 分页
        articles = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

        # 序列化文章数据
        articles_data = []
        for article in articles.items:
            # 获取文章内容
            # content = ArticleContent.query.filter_by(aid=article.article_id).first()

            articles_data.append({
                'id': article.article_id,
                'title': article.title,
                'excerpt': article.excerpt,
                'status': article.status,
                'cover_image': article.cover_image,
                'views': article.views,
                'likes': article.likes,
                'comment_count': 0,
                'created_at': article.created_at.isoformat() if article.created_at else None,
                'updated_at': article.updated_at.isoformat() if article.updated_at else None,
                'author': {
                    'id': article.author.id,
                    'username': article.author.username
                } if article.author else None,
                # 'content_preview': content.content[:200] + '...' if content and content.content else '',
                'tags': article.tags.split(',') if article.tags else [],
                'category_id': article.category_id if article.category_id else None,
                'category': {
                    'id': article.category_id if article.category_id else None,
                    'name': article.category.name if article.category_id else None,
                }
            })

        return jsonify({
            'success': True,
            'data': articles_data,
            'pagination': {
                'page': articles.page,
                'pages': articles.pages,
                'per_page': articles.per_page,
                'total': articles.total,
                'has_next': articles.has_next,
                'has_prev': articles.has_prev
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取文章列表失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/article', methods=['POST'])
@admin_required
@limiter.limit("10 per minute")
def create_article(user_id):
    """创建新文章"""
    try:
        print("[1] 开始处理请求，获取JSON数据...")
        data = request.get_json()
        print(f"[1] 接收数据：{data}")

        # 验证必填字段
        print("[2] 验证必填字段...")
        required_fields = ['title', 'author_id']
        for field in required_fields:
            if not data.get(field):
                print(f"[2] 缺失字段：{field}")
                return jsonify({'success': False, 'message': f'缺少必填字段: {field}'}), 400
        print("[2] 必填字段验证通过")

        # 验证作者是否存在
        print(f"[3] 验证作者ID {data['author_id']} 是否存在...")
        author = User.query.get(data['author_id'])
        if not author:
            print("[3] 作者不存在")
            return jsonify({'success': False, 'message': '作者不存在'}), 404
        print(f"[3] 作者验证通过：{author.username}")

        # 生成slug
        print("[4] 生成slug...")
        import re
        raw_slug = re.sub(r'[^\w\s-]', '', data['title']).strip().lower()
        slug = re.sub(r'[-\s]+', '-', raw_slug)
        print(f"[4] 原始slug：{slug}")

        # 确保slug唯一
        print("[5] 检查slug唯一性...")
        base_slug = slug
        counter = 1
        while Article.query.filter_by(slug=slug).first():
            print(f"[5] slug冲突：{slug}")
            slug = f"{base_slug}-{counter}"
            counter += 1
        print(f"[5] 最终slug：{slug}")

        # 创建新文章
        print("[6] 创建文章对象...")
        new_article = Article(
            title=data['title'],
            slug=slug,
            user_id=data['author_id'] or user_id,
            excerpt=data.get('summary', '-'),
            cover_image=data.get('featured_image'),
            tags=data.get('tags', '-'),
            status=0 if data.get('status') == 'Draft' else 1,
            is_featured=data.get('is_featured', False),
            category_id=data.get('category_id', None)
        )
        db.session.add(new_article)
        db.session.flush()
        print(f"[6] 文章ID已生成：{new_article.article_id}")

        # 创建文章内容（带安全校验）
        print("[7] 添加文章内容...")
        content = data.get('content') or '此文章由系统生成，请编辑后发布。'
        if not content.strip():
            print("[7] 警告：文章内容为空，使用默认提示")
            content = '此文章由系统生成，请编辑后发布。'

        article_content = ArticleContent(
            aid=new_article.article_id,
            content=content,
            language_code=data.get('language_code', 'zh-CN')
        )
        db.session.add(article_content)

        # 统一提交
        print("[8] 执行数据库写入...")
        db.session.commit()  # 关键点3：单次提交
        print(f"[8] 文章创建成功，ID：{new_article.article_id}")

        return jsonify({
            'success': True,
            'message': '文章创建成功',
            'data': {
                'id': new_article.article_id,
                'title': new_article.title,
                'status': new_article.status,
                'created_at': new_article.created_at.isoformat()
            }
        }), 201

    except Exception as e:
        import traceback
        print(f"[ERROR] 发生异常：{str(e)}")
        print(traceback.format_exc())
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'创建文章失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/article/<int:article_id>', methods=['GET'])
@admin_required
def get_article(user_id, article_id):
    """获取单个文章详情"""
    try:
        article = Article.query.filter_by(article_id=article_id).first_or_404()
        content = ArticleContent.query.filter_by(aid=article.article_id).first()

        return jsonify({
            'success': True,
            'data': {
                'id': article.article_id,
                'title': article.title,
                'slug': article.slug,
                'excerpt': article.excerpt,
                'status': article.status,
                'cover_image': article.cover_image,
                'tags': article.tags.split(',') if article.tags else [],
                'views': article.views,
                'likes': article.likes,
                'comment_count': 0,
                'is_featured': article.is_featured,
                'hidden': article.hidden,
                'created_at': article.created_at.isoformat() if article.created_at else None,
                'updated_at': article.updated_at.isoformat() if article.updated_at else None,
                'author': {
                    'id': article.author.id,
                    'username': article.author.username,
                    'email': article.author.email
                } if article.author else None,
                'category': {
                    'id': article.category_id if article.category_id else None,
                    'name': article.category.name if article.category else None
                },
                'content': {
                    'content': content.content if content else '',
                    'language_code': content.language_code if content else 'zh-CN'
                }
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取文章详情失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/article/<int:article_id>', methods=['PUT'])
@admin_required
def update_article(user_id, article_id):
    """更新文章"""
    try:
        article = Article.query.filter_by(article_id=article_id).first_or_404()
        data = request.get_json()
        # print(data)
        # 更新文章基本信息
        if 'title' in data:
            article.title = data['title']
        if 'excerpt' in data:
            article.excerpt = data['excerpt']
        if 'cover_image' in data:
            article.cover_image = data['cover_image']
        if 'tags' in data:
            article.tags = data['tags']
        if 'is_featured' in data:
            article.is_featured = data['is_featured']
        if 'hidden' in data:
            article.hidden = data['hidden']
        if 'status' in data:
            status_mapping = {
                'Draft': 0,
                'Published': 1,
                'Deleted': -1
            }
            article.status = status_mapping.get(data['status']) if data['status'] in status_mapping else 0
        if 'category_id' in data:
            article.category_id = data.get('category_id', None)

        article.updated_at = datetime.today()
        print(f"Article {article_id} updated successfully")

        # 保存更改到数据库
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '文章更新成功',
            'data': {
                'id': article.article_id,
                'title': article.title,
                'status': article.status,
                'updated_at': article.updated_at.isoformat()
            }
        }), 200

    except Exception as e:
        print(f"Failed to update article {article_id}: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'更新文章失败: {str(e)}'
        }), 500


@admin_bp.route('/article/<int:article_id>', methods=['DELETE'])
@admin_required
def delete_article(user_id, article_id):
    """删除文章"""
    try:
        article = db.session.query(Article).filter_by(article_id=article_id).first()
        if article is None:
            return jsonify({
                'success': False,
                'message': f'删除文章失败: 文章不存在'
            }), 500

        # 删除相关的文章内容
        db.session.query(ArticleContent).filter_by(aid=article.article_id).delete()
        # 删除相关的国际化内容
        db.session.query(ArticleI18n).filter_by(article_id=article.article_id).delete()

        title = article.title
        db.session.delete(article)
        db.session.commit()  # 确保提交会话

        return jsonify({
            'success': True,
            'message': f'文章 "{title}" 删除成功'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'删除文章失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/article/<int:article_id>/status', methods=['PUT'])
@admin_required
def update_article_status(user_id, article_id):
    """更新文章状态"""
    try:
        article = Article.query.filter_by(article_id=article_id).first_or_404()
        data = request.get_json()

        # 参数检查强化
        if 'status' not in data:
            return jsonify({'success': False, 'message': '缺少状态参数'}), 400

        # 定义状态映射关系
        status_mapping = {
            'Draft': 0,
            'Published': 1,
            'Deleted': -1
        }

        # 双重验证：输入值必须为合法字符串，且能在映射表中找到
        input_status = data['status']
        if not isinstance(input_status, str) or input_status not in status_mapping:
            return jsonify({
                'success': False,
                'message': f'无效的状态值，有效值为: {", ".join(status_mapping.keys())}'
            }), 400

        # 执行状态转换
        article.status = status_mapping[input_status]

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'文章状态已更新为: {input_status}',
            'data': {
                'id': article.article_id,
                'status_code': article.status,  # 返回整型状态码
                'status_label': input_status  # 返回可读状态标签
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'更新文章状态失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/article/stats', methods=['GET'])
@admin_required
def get_article_stats(user_id):
    """获取文章统计信息"""
    try:
        total_articles = Article.query.count()
        published_articles = Article.query.filter_by(status=1).count()
        draft_articles = Article.query.filter_by(status=0).count()
        deleted_articles = Article.query.filter_by(status=-1).count()

        # 本月新增文章
        current_month_start = datetime.today().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_articles = Article.query.filter(
            Article.created_at >= current_month_start
        ).count()

        # 总浏览量
        total_views = db.session.query(func.sum(Article.views)).scalar() or 0

        # 总点赞数
        total_likes = db.session.query(func.sum(Article.likes)).scalar() or 0

        return jsonify({
            'success': True,
            'data': {
                'total_articles': total_articles,
                'published_articles': published_articles,
                'draft_articles': draft_articles,
                'deleted_articles': deleted_articles,
                'monthly_articles': monthly_articles,
                'total_views': total_views,
                'total_likes': total_likes,
                'avg_views_per_article': round(total_views / total_articles, 1) if total_articles > 0 else 0
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取文章统计失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/categories', methods=['GET'])
@admin_required
def get_categories(user_id):
    """获取分类列表"""
    try:
        categories = Category.query.order_by(Category.name).all()

        categories_data = []
        for category in categories:
            categories_data.append({
                'id': category.id,
                'name': category.name,
                'description': category.description,
                'article_count': category.articles.count()
            })

        return jsonify({
            'success': True,
            'data': categories_data
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取分类列表失败: {str(e)}'
        }), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/authors', methods=['GET'])
@admin_required
def get_authors(user_id):
    """获取作者列表"""

    db_session = db.session()
    try:
        # 获取有文章的用户作为作者
        authors = db_session.query(User).join(Article).distinct().all()

        authors_data = []
        for author in authors:
            article_count = author.articles.count()
            authors_data.append({
                'id': author.id,
                'username': author.username,
                'email': author.email,
                'article_count': article_count
            })

        return jsonify({
            'success': True,
            'data': authors_data
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取作者列表失败: {str(e)}'
        }), 500
    finally:
        db_session.close()
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/categories', methods=['POST', 'PUT', 'DELETE'])
@admin_required
@limiter.limit("10 per minute")
def admin_categories(user_id):
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        # 处理删除请求
        if request.method == 'DELETE':
            category_id = request.json.get('category_id')
            category = db.session.query(Category).filter_by(id=category_id).first()
            if category:
                # 检查是否有文章关联到这个分类
                article_count = db.session.query(Article).filter_by(category_id=category_id).count()
                if article_count > 0:
                    return jsonify({'success': False, 'message': f'无法删除，该分类下有 {article_count} 篇文章'})

                # 删除分类订阅
                db.session.query(CategorySubscription).filter_by(category_id=category_id).delete()

                db.session.delete(category)
                db.session.commit()
                return jsonify({'success': True, 'message': '分类已删除'})
            return jsonify({'success': False, 'message': '分类不存在'})

        # 处理创建/更新请求
        elif request.method == 'POST' or request.method == 'PUT':
            name = request.form.get('name')
            description = request.form.get('description', '')

            if not name:
                return jsonify({'success': False, 'message': '分类名称不能为空'})
            if len(name) > 50:
                return jsonify({'success': False, 'message': '分类名称不能超过50个字符'})
            if not re.match(r'^[\u4e00-\u9fa5a-zA-Z0-9_-]+$', name):
                return jsonify({'success': False, 'message': '分类名称只能包含中文、英文、数字、下划线、中划线'})
            # 检查名称是否已存在
            existing_category = db.session.query(Category).filter(
                func.lower(Category.name) == func.lower(name)
            ).first()

            if request.method == 'POST':  # 创建
                if existing_category:
                    return jsonify({'success': False, 'message': '分类名称已存在'})

                category = Category(
                    name=name,
                    description=description,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                db.session.add(category)
                db.session.commit()
                return jsonify({'success': True, 'message': '分类创建成功'})

            else:  # 更新()
                category_id = request.form.get('category_id')
                category = db.session.query(Category).filter_by(id=category_id).first()

                if not category:
                    return jsonify({'success': False, 'message': '分类不存在'})

                # 检查名称冲突（排除自己）
                if existing_category and existing_category.id != int(category_id):
                    return jsonify({'success': False, 'message': '分类名称已存在'})

                category.name = name
                category.description = description
                category.updated_at = datetime.now()
                db.session.commit()
                return jsonify({'success': True, 'message': '分类更新成功'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/category', methods=['GET'])
@admin_required
def list_categories(user_id):
    try:

        db_session = db.session()

        # 获取当前用户信息
        current_user = db_session.query(User).filter_by(id=user_id).first()

        # GET请求 - 显示分类列表
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search = request.args.get('search', '')

        # 构建查询
        query = db_session.query(
            Category,
            func.count(Article.article_id).label('article_count'),
            func.count(CategorySubscription.id).label('subscriber_count')
        ).outerjoin(Article, Category.id == Article.category_id) \
            .outerjoin(CategorySubscription, Category.id == CategorySubscription.category_id)

        if search:
            query = query.filter(
                Category.name.ilike(f'%{search}%') |
                Category.description.ilike(f'%{search}%')
            )

        # 分组并分页
        categories = query.group_by(Category.id) \
            .order_by(Category.created_at.desc()) \
            .paginate(page=page, per_page=per_page, error_out=False)

        return render_template('dashboard/category.html',
                               categories=categories,
                               current_user=current_user,
                               search=search)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")
