import re
from datetime import datetime, timedelta

import bcrypt
from flask import Blueprint, request, jsonify, render_template, json

from src.database import get_db
from src.models import User, Article, ArticleContent, ArticleI18n, Category, Comment, db, CategorySubscription, Menus, \
    MenuItems, Pages, SystemSettings
# from src.error import error
from src.user.authz.decorators import admin_required
from src.utils.config.theme import get_all_themes
from src.utils.security.safe import validate_email

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates', url_prefix='/admin')


@dashboard_bp.route('/comments', methods=['GET', 'POST', 'DELETE'])
@admin_required
def admin_comments(user_id):
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        # 处理删除请求
        if request.method == 'DELETE':
            comment_id = request.json.get('comment_id')
            comment = db.session.query(Comment).filter_by(id=comment_id).first()
            if comment:
                db.session.delete(comment)
                db.session.commit()
                return jsonify({'success': True, 'message': '评论已删除'})
            return jsonify({'success': False, 'message': '评论不存在'})

        # 处理状态更新请求
        if request.method == 'POST':
            action = request.form.get('action')
            comment_id = request.form.get('comment_id')
            comment = db.session.query(Comment).filter_by(id=comment_id).first()

            if comment and action == 'approve':
                # 这里可以添加状态字段的更新逻辑
                comment.status = 'published'  # 假设这是您想要更新的状态
                db.session.commit()
                return jsonify({'success': True, 'message': '评论已审核通过'})

            return jsonify({'success': False, 'message': '操作失败'})

        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        status = request.args.get('status', 'all')
        search = request.args.get('search', '')
        article_id = request.args.get('article_id', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')

        # 构建查询
        query = db.session.query(Comment)

        # 应用筛选条件
        if status != 'all':
            if status == 'pending':
                query = query.filter(Comment.status == 'pending')
            elif status == 'published':
                query = query.filter(Comment.status == 'published')
            elif status == 'deleted':
                query = query.filter(Comment.status == 'deleted')

        if search:
            query = query.filter(
                or_(
                    Comment.content.ilike(f'%{search}%'),
                    User.username.ilike(f'%{search}%')
                )
            ).join(User)
        else:
            query = query.join(User)

        if article_id:
            query = query.filter(Comment.article_id == article_id)

        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Comment.created_at >= date_from_obj)
            except ValueError:
                pass

        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(Comment.created_at < date_to_obj)
            except ValueError:
                pass

        # 使用 paginate 方法进行分页
        comments = query.order_by(Comment.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

        # 获取文章列表用于筛选
        articles = db.session.query(Article).all()

        return render_template('dashboard/comments.html',
                               comments=comments,
                               articles=articles,
                               current_user=current_user,
                               status=status,
                               search=search,
                               article_id=article_id,
                               date_from=date_from,
                               date_to=date_to)

    except Exception as e:
        return jsonify({'error': str(e)})


@dashboard_bp.route('/index', methods=['GET'])
@admin_required
def admin_index(user_id):
    try:
        with get_db() as db:
            # 获取用户信息
            users_count = db.query(User).count()
            # 获取文章数量
            articles_count = db.query(Article).count()
            # 获取评论数量
            comments_count = db.query(Comment).count()
            current_user = db.query(User).filter_by(id=user_id).first()
            return render_template('dashboard/index.html', users_count=users_count, articles_count=articles_count,
                                   comments_count=comments_count, current_user=current_user)
    except Exception as e:
        return jsonify({'error': str(e)})


@dashboard_bp.route('/', methods=['GET'])
@admin_required
def admin_user(user_id):
    try:
        with get_db() as db:
            current_user = db.query(User).filter_by(id=user_id).first()
            return render_template('dashboard/user.html', current_user=current_user)
    except Exception as e:
        return jsonify({'error': str(e)})


@dashboard_bp.route('/blog', methods=['GET'])
@admin_required
def admin_blog(user_id):
    with get_db() as db:
        current_user = db.query(User).filter_by(id=user_id).first()
        return render_template('dashboard/blog.html', current_user=current_user)


@dashboard_bp.route('/user', methods=['GET'])
@admin_required
def get_users(user_id):
    """获取用户列表 - 支持分页和搜索"""
    with get_db() as db:
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


@dashboard_bp.route('/user', methods=['POST'])
@admin_required
def create_user(user_id):
    """创建新用户"""
    with get_db() as db:
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
                register_ip="（系统维护）"
            )

            db.add(new_user)
            db.flush()  # 确保 new_user.id 和 created_at 已经被设置

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
            db.rollback()
            return jsonify({
                'success': False,
                'message': f'创建用户失败: {str(e)}'
            }), 500


@dashboard_bp.route('/user/<int:user_id2>', methods=['PUT'])
@admin_required
def update_user(user_id, user_id2):
    """更新用户信息"""
    with get_db() as db:
        try:
            user = db.query(User).filter_by(id=user_id2).first()
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

        except Exception as e:
            db.rollback()
            return jsonify({
                'success': False,
                'message': f'更新用户失败: {str(e)}'
            }), 500


@dashboard_bp.route('/user/<int:user_id2>', methods=['DELETE'])
@admin_required
def delete_user(user_id, user_id2):
    """删除用户"""
    with get_db() as db:
        try:
            user = db.query(User).filter_by(id=user_id2).first()

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
            db.delete(user)

            return jsonify({
                'success': True,
                'message': f'用户 {username} 删除成功'
            }), 200

        except Exception as e:
            db.rollback()
            return jsonify({
                'success': False,
                'message': f'删除用户失败: {str(e)}'
            }), 500


@dashboard_bp.route('/user/<int:user_id2>', methods=['GET'])
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


@dashboard_bp.route('/stats', methods=['GET'])
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


@dashboard_bp.route('/display', methods=['GET'])
@admin_required
def m_display(user_id):
    with get_db() as db:
        current_user = db.query(User).filter_by(id=user_id).first()
        return render_template('dashboard/M-display.html',
                               current_user=current_user,
                               displayList=get_all_themes(), user_id=user_id)


@dashboard_bp.route('/article', methods=['GET'])
@admin_required
def get_articles(user_id):
    """获取文章列表 - 支持分页和搜索"""
    with get_db() as db:
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
                # content = ArticleContent.query.filter_by(aid=article.article_id).first()

                articles_data.append({
                    'id': article.article_id,
                    'title': article.title,
                    'excerpt': article.excerpt,
                    'status': article.status,
                    'cover_image': article.cover_image,
                    'views': article.views,
                    'likes': article.likes,
                    'comment_count': Comment.query.filter_by(article_id=article.article_id).count(),
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


@dashboard_bp.route('/article', methods=['POST'])
@admin_required
def create_article(user_id):
    """创建新文章"""
    with get_db() as db:
        try:
            data = request.get_json()
            print(data)

            # 验证必填字段
            required_fields = ['title', 'author_id']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({
                        'success': False,
                        'message': f'缺少必填字段: {field}'
                    }), 400

            # 验证作者是否存在
            author = User.query.get(data['author_id'])
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
                user_id=data['author_id'] or user_id,
                excerpt=data.get('excerpt', ''),
                cover_image=data.get('cover_image'),
                tags=data.get('tags', ''),
                status=data.get('status', 'Draft'),
                is_featured=data.get('is_featured', False),
                category_id=data.get('category_id', None)
            )

            db.add(new_article)
            db.flush()  # 获取文章ID

            # 创建文章内容
            if data.get('content'):
                article_content = ArticleContent(
                    aid=new_article.article_id,
                    content=data['content'],
                    language_code=data.get('language_code', 'zh-CN')
                )
                db.add(article_content)

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
            db.rollback()
            return jsonify({
                'success': False,
                'message': f'创建文章失败: {str(e)}'
            }), 500


@dashboard_bp.route('/article/<int:article_id>', methods=['GET'])
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
                'comment_count': Comment.query.filter_by(article_id=article.article_id).count(),
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


@dashboard_bp.route('/article/<int:article_id>', methods=['PUT'])
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
            article.status = data['status'] or 'Draft'
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


@dashboard_bp.route('/article/<int:article_id>', methods=['DELETE'])
@admin_required
def delete_article(user_id, article_id):
    """删除文章"""
    with get_db() as db_session:
        try:
            article = db_session.query(Article).filter_by(article_id=article_id).first()
            if article is None:
                return jsonify({
                    'success': False,
                    'message': f'删除文章失败: 文章不存在'
                }), 500

            # 删除相关的文章内容
            db_session.query(ArticleContent).filter_by(aid=article.article_id).delete()
            # 删除相关的国际化内容
            db_session.query(ArticleI18n).filter_by(article_id=article.article_id).delete()

            title = article.title
            db_session.delete(article)
            db_session.commit()  # 确保提交会话

            return jsonify({
                'success': True,
                'message': f'文章 "{title}" 删除成功'
            }), 200

        except Exception as e:
            db_session.rollback()
            return jsonify({
                'success': False,
                'message': f'删除文章失败: {str(e)}'
            }), 500


@dashboard_bp.route('/article/<int:article_id>/status', methods=['PUT'])
@admin_required
def update_article_status(user_id, article_id):
    """更新文章状态"""
    with get_db() as db:
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

            return jsonify({
                'success': True,
                'message': f'文章状态已更新为: {data["status"]}',
                'data': {
                    'id': article.article_id,
                    'status': article.status
                }
            }), 200

        except Exception as e:
            db.rollback()
            return jsonify({
                'success': False,
                'message': f'更新文章状态失败: {str(e)}'
            }), 500


from sqlalchemy import func, or_


@dashboard_bp.route('/article/stats', methods=['GET'])
@admin_required
def get_article_stats(user_id):
    """获取文章统计信息"""
    with get_db() as db:
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
            total_views = db.query(func.sum(Article.views)).scalar() or 0

            # 总点赞数
            total_likes = db.query(func.sum(Article.likes)).scalar() or 0

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


@dashboard_bp.route('/categories', methods=['GET'])
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


@dashboard_bp.route('/authors', methods=['GET'])
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


@dashboard_bp.route('/categories', methods=['POST', 'PUT', 'DELETE'])
@admin_required
def admin_categories(user_id):
    try:
        with get_db() as db:
            # 获取当前用户信息
            current_user = db.query(User).filter_by(id=user_id).first()

            # 处理删除请求
            if request.method == 'DELETE':
                category_id = request.json.get('category_id')
                category = db.query(Category).filter_by(id=category_id).first()
                if category:
                    # 检查是否有文章关联到这个分类
                    article_count = db.query(Article).filter_by(category_id=category_id).count()
                    if article_count > 0:
                        return jsonify({'success': False, 'message': f'无法删除，该分类下有 {article_count} 篇文章'})

                    # 删除分类订阅
                    db.query(CategorySubscription).filter_by(category_id=category_id).delete()

                    db.delete(category)
                    db.commit()
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
                existing_category = db.query(Category).filter(
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
                    db.add(category)
                    db.commit()
                    return jsonify({'success': True, 'message': '分类创建成功'})

                else:  # 更新()
                    category_id = request.form.get('category_id')
                    category = db.query(Category).filter_by(id=category_id).first()

                    if not category:
                        return jsonify({'success': False, 'message': '分类不存在'})

                    # 检查名称冲突（排除自己）
                    if existing_category and existing_category.id != int(category_id):
                        return jsonify({'success': False, 'message': '分类名称已存在'})

                    category.name = name
                    category.description = description
                    category.updated_at = datetime.now()
                    db.commit()
                    return jsonify({'success': True, 'message': '分类更新成功'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/category', methods=['GET'])
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


@dashboard_bp.route('/settings', methods=['GET', 'POST', 'PUT', 'DELETE'])
@admin_required
def admin_settings(user_id):
    try:
        with get_db() as db:
            # 获取当前用户信息
            current_user = db.query(User).filter_by(id=user_id).first()

            # 处理系统设置保存
            if request.method == 'POST' and 'settings' in request.form:
                settings_data = request.form.get('settings')
                try:
                    settings = json.loads(settings_data)
                    for key, value in settings.items():
                        setting = db.query(SystemSettings).filter_by(key=key).first()
                        if setting:
                            setting.value = value
                            setting.updated_at = datetime.now()
                            setting.updated_by = user_id
                        else:
                            setting = SystemSettings(
                                key=key,
                                value=value,
                                updated_at=datetime.now(),
                                updated_by=user_id
                            )
                            db.add(setting)
                    db.commit()
                    return jsonify({'success': True, 'message': '设置已保存'})
                except Exception as e:
                    return jsonify({'success': False, 'message': f'保存失败: {str(e)}'})

            # 处理菜单操作
            if request.method == 'POST' and 'menu_action' in request.form:
                action = request.form.get('menu_action')

                if action == 'create_menu':
                    name = request.form.get('name')
                    slug = request.form.get('slug')
                    description = request.form.get('description', '')

                    if not name or not slug:
                        return jsonify({'success': False, 'message': '菜单名称和标识不能为空'})

                    existing_menu = db.query(Menus).filter_by(slug=slug).first()
                    if existing_menu:
                        return jsonify({'success': False, 'message': '菜单标识已存在'})

                    menu = Menus(
                        name=name,
                        slug=slug,
                        description=description,
                        created_at=datetime.now(),
                        updated_at=datetime.now()
                    )
                    db.add(menu)
                    db.commit()
                    return jsonify({'success': True, 'message': '菜单创建成功', 'menu_id': menu.id})

                elif action == 'update_menu':
                    menu_id = request.form.get('menu_id')
                    name = request.form.get('name')
                    description = request.form.get('description', '')
                    is_active = request.form.get('is_active') == 'true'

                    menu = db.query(Menus).filter_by(id=menu_id).first()
                    if menu:
                        menu.name = name
                        menu.description = description
                        menu.is_active = is_active
                        menu.updated_at = datetime.now()
                        db.commit()
                        return jsonify({'success': True, 'message': '菜单更新成功'})
                    return jsonify({'success': False, 'message': '菜单不存在'})

                elif action == 'delete_menu':
                    menu_id = request.form.get('menu_id')
                    menu = db.query(Menus).filter_by(id=menu_id).first()
                    if menu:
                        # 删除菜单项
                        db.query(MenuItems).filter_by(menu_id=menu_id).delete()
                        db.delete(menu)
                        db.commit()
                        return jsonify({'success': True, 'message': '菜单已删除'})
                    return jsonify({'success': False, 'message': '菜单不存在'})

            # 处理菜单项操作
            if request.method == 'POST' and 'menu_item_action' in request.form:
                action = request.form.get('menu_item_action')

                if action == 'create_item':
                    menu_id = request.form.get('menu_id')
                    parent_id = request.form.get('parent_id')
                    title = request.form.get('title')
                    url = request.form.get('url')
                    target = request.form.get('target', '_self')
                    order_index = request.form.get('order_index', 0)

                    if not title:
                        return jsonify({'success': False, 'message': '菜单项标题不能为空'})

                    item = MenuItems(
                        menu_id=menu_id,
                        parent_id=parent_id if parent_id else None,
                        title=title,
                        url=url,
                        target=target,
                        order_index=order_index,
                        created_at=datetime.now()
                    )
                    db.add(item)
                    db.commit()
                    return jsonify({'success': True, 'message': '菜单项创建成功'})

                elif action == 'update_item':
                    item_id = request.form.get('item_id')
                    title = request.form.get('title')
                    url = request.form.get('url')
                    target = request.form.get('target', '_self')
                    order_index = request.form.get('order_index', 0)
                    is_active = request.form.get('is_active') == 'true'

                    item = db.query(MenuItems).filter_by(id=item_id).first()
                    if item:
                        item.title = title
                        item.url = url
                        item.target = target
                        item.order_index = order_index
                        item.is_active = is_active
                        db.commit()
                        return jsonify({'success': True, 'message': '菜单项更新成功'})
                    return jsonify({'success': False, 'message': '菜单项不存在'})

                elif action == 'delete_item':
                    item_id = request.form.get('item_id')
                    item = db.query(MenuItems).filter_by(id=item_id).first()
                    if item:
                        # 检查是否有子项
                        child_count = db.query(MenuItems).filter_by(parent_id=item_id).count()
                        if child_count > 0:
                            return jsonify({'success': False, 'message': '请先删除子菜单项'})

                        db.delete(item)
                        db.commit()
                        return jsonify({'success': True, 'message': '菜单项已删除'})
                    return jsonify({'success': False, 'message': '菜单项不存在'})

            # 处理页面操作
            if request.method == 'POST' and 'page_action' in request.form:
                action = request.form.get('page_action')

                if action == 'create_page':
                    title = request.form.get('title')
                    slug = request.form.get('slug')
                    content = request.form.get('content', '')
                    excerpt = request.form.get('excerpt', '')
                    template = request.form.get('template', 'default')
                    status = request.form.get('status', 0, type=int)
                    parent_id = request.form.get('parent_id')
                    order_index = request.form.get('order_index', 0)
                    meta_title = request.form.get('meta_title', '')
                    meta_description = request.form.get('meta_description', '')
                    meta_keywords = request.form.get('meta_keywords', '')

                    if not title or not slug:
                        return jsonify({'success': False, 'message': '页面标题和别名不能为空'})

                    existing_page = db.query(Pages).filter_by(slug=slug).first()
                    if existing_page:
                        return jsonify({'success': False, 'message': '页面别名已存在'})

                    page = Pages(
                        title=title,
                        slug=slug,
                        content=content,
                        excerpt=excerpt,
                        template=template,
                        status=status,
                        author_id=user_id,
                        parent_id=parent_id if parent_id else None,
                        order_index=order_index,
                        meta_title=meta_title,
                        meta_description=meta_description,
                        meta_keywords=meta_keywords,
                        created_at=datetime.now(),
                        updated_at=datetime.now(),
                        published_at=datetime.now() if status == 1 else None
                    )
                    db.add(page)
                    db.commit()
                    return jsonify({'success': True, 'message': '页面创建成功', 'page_id': page.id})

                elif action == 'update_page':
                    page_id = request.form.get('page_id')
                    title = request.form.get('title')
                    slug = request.form.get('slug')
                    content = request.form.get('content', '')
                    excerpt = request.form.get('excerpt', '')
                    template = request.form.get('template', 'default')
                    status = request.form.get('status', 0, type=int)
                    parent_id = request.form.get('parent_id')
                    order_index = request.form.get('order_index', 0)
                    meta_title = request.form.get('meta_title', '')
                    meta_description = request.form.get('meta_description', '')
                    meta_keywords = request.form.get('meta_keywords', '')

                    page = db.query(Pages).filter_by(id=page_id).first()
                    if not page:
                        return jsonify({'success': False, 'message': '页面不存在'})

                    # 检查别名冲突
                    existing_page = db.query(Pages).filter(
                        Pages.slug == slug,
                        Pages.id != page_id
                    ).first()
                    if existing_page:
                        return jsonify({'success': False, 'message': '页面别名已存在'})

                    page.title = title
                    page.slug = slug
                    page.content = content
                    page.excerpt = excerpt
                    page.template = template
                    page.status = status
                    page.parent_id = parent_id if parent_id else None
                    page.order_index = order_index
                    page.meta_title = meta_title
                    page.meta_description = meta_description
                    page.meta_keywords = meta_keywords
                    page.updated_at = datetime.now()

                    if status == 1 and not page.published_at:
                        page.published_at = datetime.now()

                    db.commit()
                    return jsonify({'success': True, 'message': '页面更新成功'})

                elif action == 'delete_page':
                    page_id = request.form.get('page_id')
                    page = db.query(Pages).filter_by(id=page_id).first()
                    if page:
                        # 检查是否有子页面
                        child_count = db.query(Pages).filter_by(parent_id=page_id).count()
                        if child_count > 0:
                            return jsonify({'success': False, 'message': '请先删除子页面'})

                        db.delete(page)
                        db.commit()
                        return jsonify({'success': True, 'message': '页面已删除'})
                    return jsonify({'success': False, 'message': '页面不存在'})

            # GET请求 - 显示设置页面
            # 获取系统设置
            system_settings = db.query(SystemSettings).all()
            settings_dict = {setting.key: setting.value for setting in system_settings}

            # 获取菜单
            menus = db.query(Menus).order_by(Menus.created_at.desc()).all()

            # 获取所有菜单项并按菜单分组
            menu_items = {}
            for menu in menus:
                items = db.query(MenuItems).filter_by(menu_id=menu.id).order_by(MenuItems.order_index).all()
                menu_items[menu.id] = items

            # 获取页面
            pages = db.query(Pages).order_by(Pages.created_at.desc()).all()

            return render_template('dashboard/settings.html',
                                   settings=settings_dict,
                                   menus=menus,
                                   menu_items=menu_items,
                                   pages=pages,
                                   current_user=current_user)

    except Exception as e:
        return jsonify({'error': str(e)})
