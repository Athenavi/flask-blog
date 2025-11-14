import inspect
import re

import bcrypt
from flask import Blueprint, json

from src.auth import admin_required
from src.models import User, Article, ArticleContent, ArticleI18n, Category, Comment, db, CategorySubscription, Menus, \
    MenuItems, Pages, SystemSettings, FileHash, Media, Url, SearchHistory, Event, Report
# from src.error import error
from src.utils.config.theme import get_all_themes
from src.utils.security.safe import validate_email_base
from update import base_dir

admin_bp = Blueprint('admin', __name__, template_folder='templates', url_prefix='/admin')


@admin_bp.route('/comments', methods=['GET', 'POST', 'DELETE'])
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


@admin_bp.route('/index', methods=['GET'])
@admin_required
def admin_index(user_id):
    try:
        # 获取用户信息
        users_count = db.session.query(User).count()
        # 获取文章数量
        articles_count = db.session.query(Article).count()
        # 获取评论数量
        comments_count = db.session.query(Comment).count()
        current_user = db.session.query(User).filter_by(id=user_id).first()
        return render_template('dashboard/index.html', users_count=users_count, articles_count=articles_count,
                               comments_count=comments_count, current_user=current_user)
    except Exception as e:
        return jsonify({'error': str(e)})


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


@admin_bp.route('/user', methods=['GET'])
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
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/user', methods=['POST'])
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
                'comment_count': user.comments.count()
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


@admin_bp.route('/display', methods=['GET'])
@admin_required
def m_display(user_id):
    current_user = db.session.query(User).filter_by(id=user_id).first()
    return render_template('dashboard/M-display.html',
                           current_user=current_user,
                           displayList=get_all_themes(), user_id=user_id)


@admin_bp.route('/article', methods=['GET'])
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
                db.session.or_(
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
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/article', methods=['POST'])
@admin_required
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


@admin_bp.route('/settings', methods=['GET', 'POST', 'PUT', 'DELETE'])
@admin_required
def admin_settings(user_id):
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        # 处理系统设置保存
        if request.method == 'POST' and 'settings' in request.form:
            settings_data = request.form.get('settings')
            try:
                settings = json.loads(settings_data)
                for key, value in settings.items():
                    setting = db.session.query(SystemSettings).filter_by(key=key).first()
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
                        db.session.add(setting)
                db.session.commit()
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

                existing_menu = db.session.query(Menus).filter_by(slug=slug).first()
                if existing_menu:
                    return jsonify({'success': False, 'message': '菜单标识已存在'})

                menu = Menus(
                    name=name,
                    slug=slug,
                    description=description,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                db.session.add(menu)
                db.session.commit()
                return jsonify({'success': True, 'message': '菜单创建成功', 'menu_id': menu.id})

            elif action == 'update_menu':
                menu_id = request.form.get('menu_id')
                name = request.form.get('name')
                description = request.form.get('description', '')
                is_active = request.form.get('is_active') == 'true'

                menu = db.session.query(Menus).filter_by(id=menu_id).first()
                if menu:
                    menu.name = name
                    menu.description = description
                    menu.is_active = is_active
                    menu.updated_at = datetime.now()
                    db.session.commit()
                    return jsonify({'success': True, 'message': '菜单更新成功'})
                return jsonify({'success': False, 'message': '菜单不存在'})

            elif action == 'delete_menu':
                menu_id = request.form.get('menu_id')
                menu = db.session.query(Menus).filter_by(id=menu_id).first()
                if menu:
                    # 删除菜单项
                    db.session.query(MenuItems).filter_by(menu_id=menu_id).delete()
                    db.session.delete(menu)
                    db.session.commit()
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
                db.session.add(item)
                db.session.commit()
                return jsonify({'success': True, 'message': '菜单项创建成功'})

            elif action == 'update_item':
                item_id = request.form.get('item_id')
                title = request.form.get('title')
                url = request.form.get('url')
                target = request.form.get('target', '_self')
                order_index = request.form.get('order_index', 0)
                is_active = request.form.get('is_active') == 'true'

                item = db.session.query(MenuItems).filter_by(id=item_id).first()
                if item:
                    item.title = title
                    item.url = url
                    item.target = target
                    item.order_index = order_index
                    item.is_active = is_active
                    db.session.commit()
                    return jsonify({'success': True, 'message': '菜单项更新成功'})
                return jsonify({'success': False, 'message': '菜单项不存在'})

            elif action == 'delete_item':
                item_id = request.form.get('item_id')
                item = db.session.query(MenuItems).filter_by(id=item_id).first()
                if item:
                    # 检查是否有子项
                    child_count = db.session.query(MenuItems).filter_by(parent_id=item_id).count()
                    if child_count > 0:
                        return jsonify({'success': False, 'message': '请先删除子菜单项'})

                    db.session.delete(item)
                    db.session.commit()
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

                page = db.session.query(Pages).filter_by(id=page_id).first()
                if not page:
                    return jsonify({'success': False, 'message': '页面不存在'})

                # 检查别名冲突
                existing_page = db.session.query(Pages).filter(
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

                db.session.commit()
                return jsonify({'success': True, 'message': '页面更新成功'})

            elif action == 'delete_page':
                page_id = request.form.get('page_id')
                page = db.session.query(Pages).filter_by(id=page_id).first()
                if page:
                    # 检查是否有子页面
                    child_count = db.session.query(Pages).filter_by(parent_id=page_id).count()
                    if child_count > 0:
                        return jsonify({'success': False, 'message': '请先删除子页面'})

                    db.session.delete(page)
                    db.session.commit()
                    return jsonify({'success': True, 'message': '页面已删除'})
                return jsonify({'success': False, 'message': '页面不存在'})

        # GET请求 - 显示设置页面
        # 获取系统设置
        system_settings = db.session.query(SystemSettings).all()
        settings_dict = {setting.key: setting.value for setting in system_settings}

        # 获取菜单
        menus = db.session.query(Menus).order_by(Menus.created_at.desc()).all()

        # 获取所有菜单项并按菜单分组
        menu_items = {}
        for menu in menus:
            items = db.session.query(MenuItems).filter_by(menu_id=menu.id).order_by(MenuItems.order_index).all()
            menu_items[menu.id] = items

        # 获取页面
        pages = db.session.query(Pages).order_by(Pages.created_at.desc()).all()

        return render_template('dashboard/settings.html',
                               settings=settings_dict,
                               menus=menus,
                               menu_items=menu_items,
                               pages=pages,
                               current_user=current_user)

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/media', methods=['GET', 'DELETE'])
@admin_required
def admin_media(user_id):
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        # 处理删除请求
        if request.method == 'DELETE':
            media_hash = request.args.get('media_hash')
            if file_record := db.session.query(FileHash).filter_by(hash=media_hash).first():
                try:
                    # 检查文件是否存在
                    file_dir = Path(base_dir) / file_record.storage_path
                    if not os.path.exists(file_dir):
                        pass
                    else:
                        os.remove(file_dir)
                except Exception as e:
                    print(f"删除文件失败: {str(e)}")
                db.session.delete(file_record)
            db.session.commit()
            return jsonify({'success': True, 'message': '附件已删除'})

        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        mime_type = request.args.get('mime_type', '')
        user_id_filter = request.args.get('user_id', '')
        search = request.args.get('search', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')

        # 构建查询
        query = db.session.query(Media).join(FileHash, Media.hash == FileHash.hash).join(User, Media.user_id == User.id)

        # 应用筛选条件
        if mime_type:
            if mime_type == 'image':
                query = query.filter(FileHash.mime_type.like('image/%'))
            elif mime_type == 'video':
                query = query.filter(FileHash.mime_type.like('video/%'))
            elif mime_type == 'audio':
                query = query.filter(FileHash.mime_type.like('audio/%'))
            elif mime_type == 'document':
                query = query.filter(or_(
                    FileHash.mime_type.like('application/pdf'),
                    FileHash.mime_type.like('application/msword'),
                    FileHash.mime_type.like('application/vnd.openxmlformats-officedocument.%')
                ))
            else:
                query = query.filter(FileHash.mime_type == mime_type)

        if user_id_filter:
            query = query.filter(Media.user_id == user_id_filter)

        if search:
            query = query.filter(or_(
                FileHash.filename.ilike(f'%{search}%'),
                Media.original_filename.ilike(f'%{search}%'),
                User.username.ilike(f'%{search}%')
            ))

        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Media.created_at >= date_from_obj)
            except ValueError:
                pass

        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(Media.created_at < date_to_obj)
            except ValueError:
                pass

        # 获取用户列表用于筛选
        users = db.session.query(User).all()

        # 执行分页查询
        media_items = query.order_by(Media.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return render_template('dashboard/media.html',
                               media_items=media_items,
                               users=users,
                               current_user=current_user,
                               mime_type=mime_type,
                               user_id_filter=user_id_filter,
                               search=search,
                               date_from=date_from,
                               date_to=date_to)

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/media/preview/<int:media_id>')
@admin_required
def media_preview(user_id, media_id):
    try:
        media = db.session.query(Media).filter_by(id=media_id).first()
        if not media:
            return jsonify({'error': '文件不存在'}), 404

        file_record = db.session.query(FileHash).filter_by(hash=media.hash).first()
        if not file_record:
            return jsonify({'error': '文件哈希记录不存在'}), 404

        # 检查文件是否存在
        file_dir = Path(base_dir) / file_record.storage_path
        if not os.path.exists(file_dir):
            return jsonify({'error': '文件不存在'}), 404

        # 根据MIME类型决定返回方式
        file_type = 'unknown'
        if file_record.mime_type.startswith('image/'):
            file_type = 'image'
        if file_record.mime_type.startswith('video/'):
            file_type = 'video'
        elif file_record.mime_type.startswith('text/'):
            try:
                with open(file_dir, 'r', encoding='utf-8') as f:
                    content = f.read()
                    file_type = 'text'
                return jsonify({
                    'type': file_type,
                    'content': content,
                    'mime_type': file_record.mime_type
                })
            except IOError as e:
                return jsonify({'error': str(e)}), 500
        return jsonify({
            'type': file_type,
            'filename': file_record.filename,
            'mime_type': file_record.mime_type,
            'size': file_record.file_size,
            'view_url': f'/shared?data={file_record.hash}',
            'url': f'/admin/media/download/{media_id}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


# ===============

import os
from flask import send_file

from pathlib import Path
from src.utils.database.backup import create_backup_tool


@admin_bp.route('/backup', methods=['GET', 'POST'])
@admin_required
def backup(user_id):
    try:
        # 获取当前用户信息
        current_user = db.session.query(User).filter_by(id=user_id).first()

        # 初始化备份工具
        backup_dir = Path(base_dir) / 'backup'
        backup_tool = create_backup_tool(db, str(backup_dir))

        # 处理备份请求
        if request.method == 'POST':
            backup_type = request.form.get('backup_type')

            if backup_type == 'schema':
                # 使用工具类备份表结构
                result = backup_tool.backup_schema()

                if result:
                    filename = Path(result).name
                    return jsonify({
                        'success': True,
                        'message': f'数据库结构备份成功: {filename}',
                        'filename': filename
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': '数据库结构备份失败'
                    })

            elif backup_type == 'data':
                # 使用工具类备份表数据
                result = backup_tool.backup_data()

                if result:
                    filename = Path(result).name
                    return jsonify({
                        'success': True,
                        'message': f'数据库数据备份成功: {filename}',
                        'filename': filename
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': '数据库数据备份失败'
                    })

            elif backup_type == 'all':
                # 使用工具类完整备份数据库
                result = backup_tool.backup_all()

                if result and 'full' in result:
                    filename = Path(result['full']).name
                    return jsonify({
                        'success': True,
                        'message': f'完整数据库备份成功: {filename}',
                        'filename': filename
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': '完整数据库备份失败'
                    })

            elif backup_type == 'delete':
                # 删除备份文件
                filename = request.form.get('filename')
                if filename and filename.endswith(('.sql', '.sql.gz', '.zip')):
                    filepath = backup_dir / filename
                    if filepath.exists() and filepath.parent == backup_dir:
                        filepath.unlink()
                        return jsonify({
                            'success': True,
                            'message': f'备份文件已删除: {filename}'
                        })

                return jsonify({
                    'success': False,
                    'message': '文件删除失败'
                })

        # GET请求 - 显示备份页面
        backup_list = []
        if backup_dir.exists():
            # 使用工具类列出备份文件
            backups = backup_tool.list_backups()

            for backup_info in backups:
                filename = backup_info['name']
                file_size = backup_info['size']
                created_at = backup_info['modified']

                # 确定备份类型
                if filename.startswith('schema_backup_'):
                    backup_type = 'schema'
                elif filename.startswith('data_backup_'):
                    backup_type = 'data'
                elif filename.startswith('full_backup_'):
                    backup_type = 'all'
                else:
                    backup_type = 'unknown'

                backup_list.append({
                    'name': filename,
                    'size': file_size,
                    'created_at': created_at,
                    'type': backup_type
                })

        # 按创建时间倒序排列
        backup_list.sort(key=lambda x: x['created_at'], reverse=True)

        return render_template('dashboard/backup.html',
                               backup_list=backup_list,
                               current_user=current_user)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


@admin_bp.route('/backup/download/<filename>')
@admin_required
def download_backup(user_id, filename):
    try:
        backup_dir = Path(base_dir) / 'backup'
        filepath = backup_dir / filename

        # 安全检查：确保文件在备份目录内
        if not filepath.exists() or filepath.parent != backup_dir:
            return jsonify({'error': '文件不存在'}), 404
        # 处理压缩文件的下载名称
        download_name = filename
        return send_file(
            filepath,
            as_attachment=True,
            download_name=download_name
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")


from flask import request, jsonify, render_template
from sqlalchemy import or_, func
from datetime import datetime, timedelta


@admin_bp.route('/misc', methods=['GET', 'POST', 'PUT', 'DELETE'])
@admin_required
def admin_misc(user_id):
    try:
        db_session = db.session()
        # 获取当前用户信息
        current_user = db_session.query(User).filter_by(id=user_id).first()

        # 获取分页参数
        page_events = request.args.get('page_events', 1, type=int)
        page_reports = request.args.get('page_reports', 1, type=int)
        page_urls = request.args.get('page_urls', 1, type=int)
        page_search = request.args.get('page_search', 1, type=int)

        per_page = 10  # 每页显示数量

        # 处理事件操作
        if request.method == 'POST' and 'event_action' in request.form:
            action = request.form.get('event_action')

            if action == 'create_event':
                title = request.form.get('title')
                description = request.form.get('description', '')
                event_date = request.form.get('event_date')

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
                event_id = request.form.get('event_id')
                title = request.form.get('title')
                description = request.form.get('description', '')
                event_date = request.form.get('event_date')

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
                event_id = request.form.get('event_id')
                event = db_session.query(Event).filter_by(id=event_id).first()
                if event:
                    db_session.delete(event)
                    db_session.commit()
                    return jsonify({'success': True, 'message': '事件已删除'})
                return jsonify({'success': False, 'message': '事件不存在'})

        # 处理举报操作
        if request.method == 'POST' and 'report_action' in request.form:
            action = request.form.get('report_action')

            if action == 'delete_report':
                report_id = request.form.get('report_id')
                report = db_session.query(Report).filter_by(id=report_id).first()
                if report:
                    db_session.delete(report)
                    db_session.commit()
                    return jsonify({'success': True, 'message': '举报记录已删除'})
                return jsonify({'success': False, 'message': '举报记录不存在'})

            elif action == 'process_report':
                report_id = request.form.get('report_id')
                # 这里可以添加处理举报的逻辑，比如标记为已处理
                return jsonify({'success': True, 'message': '举报已处理'})

        # 处理短链接操作
        if request.method == 'POST' and 'url_action' in request.form:
            action = request.form.get('url_action')

            if action == 'create_url':
                long_url = request.form.get('long_url')
                short_url = request.form.get('short_url')
                user_id_url = request.form.get('user_id')

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
                url_id = request.form.get('url_id')
                url = db_session.query(Url).filter_by(id=url_id).first()
                if url:
                    db_session.delete(url)
                    db_session.commit()
                    return jsonify({'success': True, 'message': '短链接已删除'})
                return jsonify({'success': False, 'message': '短链接不存在'})

        # 处理搜索历史操作
        if request.method == 'POST' and 'search_history_action' in request.form:
            action = request.form.get('search_history_action')

            if action == 'delete_history':
                history_id = request.form.get('history_id')
                history = db_session.query(SearchHistory).filter_by(id=history_id).first()
                if history:
                    db_session.delete(history)
                    db_session.commit()
                    return jsonify({'success': True, 'message': '搜索记录已删除'})
                return jsonify({'success': False, 'message': '搜索记录不存在'})

            elif action == 'clear_user_history':
                user_id_history = request.form.get('user_id')
                db_session.query(SearchHistory).filter_by(user_id=user_id_history).delete()
                db_session.commit()
                return jsonify({'success': True, 'message': '用户搜索记录已清空'})

            elif action == 'clear_all_history':
                db_session.query(SearchHistory).delete()
                db_session.commit()
                return jsonify({'success': True, 'message': '所有搜索记录已清空'})

        # GET请求 - 显示杂项管理页面
        # 获取事件列表（带分页）
        events_query = db_session.query(Event).order_by(Event.event_date.desc())
        events_pagination = events_query.paginate(
            page=page_events, per_page=per_page, error_out=False
        )

        # 获取举报列表（带分页）
        reports_query = db_session.query(Report).join(User, Report.reported_by == User.id) \
            .order_by(Report.created_at.desc())
        reports_pagination = reports_query.paginate(
            page=page_reports, per_page=per_page, error_out=False
        )

        # 获取短链接列表（带分页）
        urls_query = db_session.query(Url).join(User, Url.user_id == User.id) \
            .order_by(Url.created_at.desc())
        urls_pagination = urls_query.paginate(
            page=page_urls, per_page=per_page, error_out=False
        )

        # 获取搜索历史列表（带分页）
        search_history_query = db_session.query(SearchHistory).order_by(SearchHistory.created_at.desc())
        search_history_pagination = search_history_query.paginate(
            page=page_search, per_page=per_page, error_out=False
        )

        # 获取用户列表用于筛选
        # users = db_session.query(User).all()

        # 获取搜索统计（前10个热门关键词）
        search_stats = db_session.query(
            SearchHistory.keyword,
            func.count(SearchHistory.id).label('search_count')
        ).group_by(SearchHistory.keyword) \
            .order_by(func.count(SearchHistory.id).desc()) \
            .limit(10).all()

        return render_template('dashboard/misc.html',
                               events_pagination=events_pagination,
                               reports_pagination=reports_pagination,
                               urls_pagination=urls_pagination,
                               search_history_pagination=search_history_pagination,
                               search_stats=search_stats,
                               # users=users,
                               current_user=current_user,
                               page_events=page_events,
                               page_reports=page_reports,
                               page_urls=page_urls,
                               page_search=page_search)

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        current_func_name = inspect.currentframe().f_code.co_name
        # 输出当前视图名称和操作人ID
        print(f"==>{current_func_name}, User ID: {user_id}")
