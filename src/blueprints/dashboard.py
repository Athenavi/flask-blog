from datetime import datetime

import bcrypt
from MySQLdb import IntegrityError
from flask import Blueprint, request, render_template
from flask import jsonify

from src.config.theme import get_all_themes
from src.database import get_db_connection
from src.models import User, db, Article, ArticleContent, ArticleI18n, Category
# from src.error import error
from src.user.authz.decorators import admin_required
from src.utils.security.ip_utils import get_client_ip
from src.utils.security.safe import validate_email

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates')


@dashboard_bp.route('/admin', methods=['GET'])
@admin_required
def admin_index(user_id):
    return render_template('dashboard/user.html')


@dashboard_bp.route('/admin/blog', methods=['GET'])
@admin_required
def admin_blog(user_id):
    return render_template('dashboard/blog.html')


@dashboard_bp.route('/admin/user', methods=['GET'])
@admin_required
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
                db.or_(
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
                'comment_count': user.comments.count()
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


@dashboard_bp.route('/admin/user', methods=['POST'])
@admin_required
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
        if not validate_email(data['email']):
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
        if len(data['password']) < 6:
            return jsonify({
                'success': False,
                'message': '密码长度至少6个字符'
            }), 400

        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

        # 创建新用户
        new_user = User(
            username=data['username'],
            password=hashed_password.decode('utf-8'),
            email=data['email'],
            profile_picture=data.get('profile_picture'),
            bio=data.get('bio'),
            register_ip=get_client_ip()
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '用户创建成功',
            'data': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email,
                'created_at': new_user.created_at.isoformat()
            }
        }), 201

    except IntegrityError as e:
        db.session.rollback()
        if 'username' in str(e):
            message = '用户名已存在'
        elif 'email' in str(e):
            message = '邮箱已存在'
        else:
            message = '数据完整性错误'

        return jsonify({
            'success': False,
            'message': message
        }), 409

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'创建用户失败: {str(e)}'
        }), 500


@dashboard_bp.route('/admin/user/<int:user_id2>', methods=['PUT'])
@admin_required
def update_user(user_id, user_id2):
    """更新用户信息"""
    try:
        user = User.query.get_or_404(user_id2)
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
            if not validate_email(data['email']):
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

    except IntegrityError as e:
        db.session.rollback()
        if 'username' in str(e):
            message = '用户名已存在'
        elif 'email' in str(e):
            message = '邮箱已存在'
        else:
            message = '数据完整性错误'

        return jsonify({
            'success': False,
            'message': message
        }), 409

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'更新用户失败: {str(e)}'
        }), 500


@dashboard_bp.route('/admin/user/<int:user_id2>', methods=['DELETE'])
@admin_required
def delete_user(user_id, user_id2):
    """删除用户"""
    try:
        user = User.query.get_or_404(user_id2)

        # 检查用户是否有关联数据
        media_count = len(user.media)
        comment_count = user.comments.count()

        if media_count > 0 or comment_count > 0:
            return jsonify({
                'success': False,
                'message': f'无法删除用户，该用户有 {media_count} 个媒体文件和 {comment_count} 条评论',
                'details': {
                    'media_count': media_count,
                    'comment_count': comment_count
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


@dashboard_bp.route('/admin/user/<int:user_id2>', methods=['GET'])
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
                'comment_count': user.comments.count()
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取用户详情失败: {str(e)}'
        }), 500


@dashboard_bp.route('/admin/stats', methods=['GET'])
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


@dashboard_bp.route('/admin/analytics/user-growth', methods=['GET'])
@admin_required
def get_user_growth_analytics(user_id):
    """获取用户增长分析数据"""
    try:
        # 获取时间范围参数
        days = request.args.get('days', 30, type=int)

        # 模拟用户增长数据 - 在实际应用中应该从数据库查询
        from datetime import datetime, timedelta
        import random

        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        growth_data = []
        current_date = start_date
        base_users = 100

        while current_date <= end_date:
            # 模拟每日新增用户数据
            daily_new = random.randint(5, 25)
            base_users += daily_new

            growth_data.append({
                'date': current_date.strftime('%Y-%m-%d'),
                'new_users': daily_new,
                'total_users': base_users,
                'active_users': int(base_users * 0.7 + random.randint(-10, 10))
            })
            current_date += timedelta(days=1)

        return jsonify({
            'success': True,
            'data': growth_data
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取用户增长数据失败: {str(e)}'
        }), 500


# -*- coding: utf-8 -*-

def create_delete_route(route_path, table_name, id_param, id_column='id', chinese_name=''):
    """创建删除操作的通用路由工厂"""

    endpoint_name = f"delete_{table_name}"

    @dashboard_bp.route(route_path, methods=['DELETE'])
    @admin_required
    def delete_handler(user_id):
        # 参数验证
        target_id = request.args.get(id_param)
        if not target_id or not target_id.isdigit():
            return jsonify({"message": "无效的ID参数"}), 400

        try:
            target_id = int(target_id)
            # 特殊校验（如保护管理员账户）
            if table_name == 'users' and target_id == 1:
                return jsonify({"message": "禁止操作系统管理员"}), 403

            # 执行删除操作
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    query = f"DELETE FROM `{table_name}` WHERE `{id_column}` = %s"
                    cursor.execute(query, (target_id,))
                    conn.commit()

            # 记录操作日志
            print(f"用户 {user_id} 删除了{chinese_name} {target_id}")
            return jsonify({"message": f"{chinese_name}删除成功"}), 200

        except Exception as e:
            conn.rollback()
            print(f"删除{chinese_name}失败: {str(e)}")
            return jsonify({"message": f"{chinese_name}删除失败", "error": str(e)}), 500

    # 设置唯一端点名称
    delete_handler.__name__ = endpoint_name
    return delete_handler


# 删除路由配置（路径，表名，参数名，ID列名，中文名称）
delete_routes = [
    ('/dashboard/overview', 'events', 'id', 'id', '事件'),
    ('/dashboard/urls', 'urls', 'id', 'id', '短链接'),
    ('/dashboard/articles', 'articles', 'aid', 'article_id', '文章'),
    ('/dashboard/users', 'users', 'uid', 'id', '用户'),
    ('/dashboard/comments', 'comments', 'cid', 'id', '评论'),
    ('/dashboard/media', 'media', 'file-id', 'id', '媒体文件'),
    ('/dashboard/notifications', 'notifications', 'nid', 'id', '通知'),
    ('/dashboard/reports', 'reports', 'rid', 'id', '举报信息')
]

# 批量注册删除路由
for config in delete_routes:
    create_delete_route(*config)


@dashboard_bp.route('/dashboard/permissions', methods=['GET', 'POST'])
@admin_required
def manage_permissions(user_id):
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # 处理权限操作
    if request.method == 'POST':
        # 添加新权限
        if 'add_permission' in request.form:
            code = request.form['code']
            description = request.form['description']
            cursor.execute('INSERT INTO permissions (code, description) VALUES (%s, %s)', (code, description))

        # 添加新角色
        elif 'add_role' in request.form:
            name = request.form['name']
            description = request.form['description']
            cursor.execute('INSERT INTO roles (name, description) VALUES (%s, %s)', (name, description))

        # 分配权限给角色
        elif 'assign_permission' in request.form:
            role_id = request.form['role_id']
            permission_id = request.form['permission_id']
            cursor.execute('INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (%s, %s)',
                           (role_id, permission_id))

        # 分配角色给用户
        elif 'assign_role' in request.form:
            user_id = request.form['user_id']
            role_id = request.form['role_id']
            cursor.execute('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (%s, %s)',
                           (user_id, role_id))

        db.commit()

    # 获取所有数据
    cursor.execute('SELECT * FROM permissions')
    permissions = cursor.fetchall()

    cursor.execute('SELECT * FROM roles')
    roles = cursor.fetchall()

    cursor.execute(
        'SELECT u.id, u.username, GROUP_CONCAT(r.name) as roles FROM users u LEFT JOIN user_roles ur ON u.id = ur.user_id LEFT JOIN roles r ON ur.role_id = r.id GROUP BY u.id')
    users = cursor.fetchall()

    cursor.execute(
        'SELECT r.id as role_id, r.name as role_name, GROUP_CONCAT(p.code) as permissions FROM roles r LEFT JOIN role_permissions rp ON r.id = rp.role_id LEFT JOIN permissions p ON rp.permission_id = p.id GROUP BY r.id')
    role_permissions = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('permissions.html',
                           permissions=permissions,
                           roles=roles,
                           users=users,
                           role_permissions=role_permissions)


@dashboard_bp.route('/dashboard/display', methods=['GET'])
@admin_required
def m_display(user_id):
    return render_template('dashboard/M-display.html', displayList=get_all_themes(), user_id=user_id)


def query_dashboard_data(route, template, table_name, menu_active=None):
    @admin_required
    def route_function(user_id):
        if request.method == 'GET':
            return render_template(template, menu_active=menu_active)
        try:
            with get_db_connection() as connection:
                with connection.cursor(dictionary=True) as cursor:
                    query = f"SELECT * FROM `{table_name}`"
                    cursor.execute(query)
                    data = cursor.fetchall()
                    if not data:
                        return jsonify({"message": f"没有{table_name}数据"}), 404
            return jsonify(data), 200
        except Exception as e:
            referrer = request.referrer
            # app.logger.error(f"{referrer}.user_{user_id}: queried all {table_name}")
            return jsonify({"message": "操作失败", "error": str(e)}), 500

    # 为每个路由函数设置唯一的名称以避免端点冲突
    route_function.__name__ = f"route_function_{table_name}"
    dashboard_bp.route(route, methods=['GET', 'POST'])(route_function)
    return route_function


# 定义路由
dashboard_v2_media = query_dashboard_data('/dashboard/v2/media', 'dashboardV2/media.html', 'media', menu_active='media')
dashboard_v2_url = query_dashboard_data('/dashboard/v2/url', 'dashboardV2/url.html', 'urls', menu_active='url')


@dashboard_bp.route('/admin/article', methods=['GET'])
@admin_required
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
                db.or_(
                    Article.title.contains(search),
                    Article.excerpt.contains(search)
                )
            )

        # 状态筛选
        if status:
            query = query.filter(Article.status == status)

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
            content = ArticleContent.query.filter_by(aid=article.article_id).first()

            articles_data.append({
                'id': article.article_id,
                'title': article.title,
                'excerpt': article.excerpt,
                'status': article.status,
                'cover_image': article.cover_image,
                'views': article.views,
                'likes': article.likes,
                'comment_count': article.comment_count,
                'created_at': article.created_at.isoformat() if article.created_at else None,
                'updated_at': article.updated_at.isoformat() if article.updated_at else None,
                'author': {
                    'id': article.author.id,
                    'username': article.author.username
                } if article.author else None,
                'content_preview': content.content[:200] + '...' if content and content.content else '',
                'tags': article.tags.split(',') if article.tags else []
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


@dashboard_bp.route('/admin/article', methods=['POST'])
@admin_required
def create_article(user_id):
    """创建新文章"""
    try:
        data = request.get_json()

        # 验证必填字段
        required_fields = ['title', 'user_id']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'缺少必填字段: {field}'
                }), 400

        # 验证作者是否存在
        author = User.query.get(data['user_id'])
        if not author:
            return jsonify({
                'success': False,
                'message': '作者不存在'
            }), 404

        import re
        slug = re.sub(r'[^\w\s-]', '', data['title']).strip().lower()
        slug = re.sub(r'[-\s]+', '-', slug)

        # 确保slug唯一
        base_slug = slug
        counter = 1
        while Article.query.filter_by(slug=slug).first():
            slug = f"{base_slug}-{counter}"
            counter += 1

        # 创建新文章
        new_article = Article(
            title=data['title'],
            slug=slug,
            user_id=data['user_id'],
            excerpt=data.get('excerpt', ''),
            cover_image=data.get('cover_image'),
            tags=data.get('tags', ''),
            status=data.get('status', 'Draft'),
            article_type=data.get('article_type', 'article'),
            is_featured=data.get('is_featured', False)
        )

        db.session.add(new_article)
        db.session.flush()  # 获取文章ID

        # 创建文章内容
        if data.get('content'):
            article_content = ArticleContent(
                aid=new_article.article_id,
                content=data['content'],
                language_code=data.get('language_code', 'zh-CN')
            )
            db.session.add(article_content)

        db.session.commit()

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
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'创建文章失败: {str(e)}'
        }), 500


@dashboard_bp.route('/admin/article/<int:article_id>', methods=['GET'])
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
                'comment_count': article.comment_count,
                'article_type': article.article_type,
                'is_featured': article.is_featured,
                'hidden': article.hidden,
                'created_at': article.created_at.isoformat() if article.created_at else None,
                'updated_at': article.updated_at.isoformat() if article.updated_at else None,
                'author': {
                    'id': article.author.id,
                    'username': article.author.username,
                    'email': article.author.email
                } if article.author else None,
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


@dashboard_bp.route('/admin/article/<int:article_id>', methods=['PUT'])
@admin_required
def update_article(user_id, article_id):
    """更新文章"""
    try:
        article = Article.query.filter_by(article_id=article_id).first_or_404()
        data = request.get_json()

        # 更新文章基本信息
        if 'title' in data:
            article.title = data['title']
        if 'excerpt' in data:
            article.excerpt = data['excerpt']
        if 'cover_image' in data:
            article.cover_image = data['cover_image']
        if 'tags' in data:
            article.tags = data['tags']
        if 'article_type' in data:
            article.article_type = data['article_type']
        if 'is_featured' in data:
            article.is_featured = data['is_featured']
        if 'hidden' in data:
            article.hidden = data['hidden']

        # 更新状态
        if 'status' in data:
            article.status = data['status']

        # 更新文章内容
        if 'content' in data:
            content = ArticleContent.query.filter_by(aid=article.article_id).first()
            if content:
                content.content = data['content']
                if 'language_code' in data:
                    content.language_code = data['language_code']
            else:
                # 创建新的内容记录
                new_content = ArticleContent(
                    aid=article.article_id,
                    content=data['content'],
                    language_code=data.get('language_code', 'zh-CN')
                )
                db.session.add(new_content)

        article.updated_at = datetime.today()
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
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'更新文章失败: {str(e)}'
        }), 500


@dashboard_bp.route('/admin/article/<int:article_id>', methods=['DELETE'])
@admin_required
def delete_article(user_id, article_id):
    """删除文章"""
    try:
        article = Article.query.filter_by(article_id=article_id).first_or_404()

        # 删除相关的文章内容
        ArticleContent.query.filter_by(aid=article.article_id).delete()

        # 删除相关的国际化内容
        ArticleI18n.query.filter_by(article_id=article.article_id).delete()

        title = article.title
        db.session.delete(article)
        db.session.commit()

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


@dashboard_bp.route('/admin/article/<int:article_id>/status', methods=['PUT'])
@admin_required
def update_article_status(user_id, article_id):
    """更新文章状态"""
    try:
        article = Article.query.filter_by(article_id=article_id).first_or_404()
        data = request.get_json()

        if 'status' not in data:
            return jsonify({
                'success': False,
                'message': '缺少状态参数'
            }), 400

        valid_statuses = ['Draft', 'Published', 'Deleted']
        if data['status'] not in valid_statuses:
            return jsonify({
                'success': False,
                'message': f'无效的状态值，有效值为: {", ".join(valid_statuses)}'
            }), 400

        article.status = data['status']
        article.updated_at = datetime.today()
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'文章状态已更新为: {data["status"]}',
            'data': {
                'id': article.article_id,
                'status': article.status
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'更新文章状态失败: {str(e)}'
        }), 500


@dashboard_bp.route('/admin/article/stats', methods=['GET'])
@admin_required
def get_article_stats(user_id):
    """获取文章统计信息"""
    try:
        total_articles = Article.query.count()
        published_articles = Article.query.filter_by(status='Published').count()
        draft_articles = Article.query.filter_by(status='Draft').count()
        deleted_articles = Article.query.filter_by(status='Deleted').count()

        # 本月新增文章
        current_month_start = datetime.today().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_articles = Article.query.filter(
            Article.created_at >= current_month_start
        ).count()

        # 总浏览量
        total_views = db.session.query(db.func.sum(Article.views)).scalar() or 0

        # 总点赞数
        total_likes = db.session.query(db.func.sum(Article.likes)).scalar() or 0

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


@dashboard_bp.route('/admin/categories', methods=['GET'])
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


@dashboard_bp.route('/admin/authors', methods=['GET'])
@admin_required
def get_authors(user_id):
    """获取作者列表"""
    try:
        # 获取有文章的用户作为作者
        authors = db.session.query(User).join(Article).distinct().all()

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
