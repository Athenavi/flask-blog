from datetime import datetime

import bcrypt
from flask import Blueprint, request, render_template
from flask import jsonify

from src.database import get_db
from src.models import User, Article, ArticleContent, ArticleI18n, Category, Comment, db
# from src.error import error
from src.user.authz.decorators import admin_required
from src.utils.config.theme import get_all_themes
from src.utils.security.safe import validate_email

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates', url_prefix='/admin')


@dashboard_bp.route('/', methods=['GET'])
@admin_required
def admin_index(user_id):
    try:
        return render_template('dashboard/user.html')
    except Exception as e:
        return jsonify({'error': str(e)})


@dashboard_bp.route('/blog', methods=['GET'])
@admin_required
def admin_blog(user_id):
    return render_template('dashboard/blog.html')


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
    return render_template('dashboard/M-display.html', displayList=get_all_themes(), user_id=user_id)


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


from sqlalchemy import func


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
    with get_db() as db:
        try:
            # 获取有文章的用户作为作者
            authors = db.query(User).join(Article).distinct().all()

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
