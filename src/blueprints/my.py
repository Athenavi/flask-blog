from flask import Blueprint, flash

from src.database import get_db
from src.models import Article
from src.models import Url, Comment
from src.user.authz.decorators import jwt_required
from src.utils.shortener.links import generate_short_url
from user.authz.password import validate_password, update_password
from utils.security.ip_utils import get_client_ip

my_bp = Blueprint('my', __name__, url_prefix='/my')


@my_bp.route('/urls')
@jwt_required
def user_urls(user_id):
    """用户URL管理页面"""

    page = request.args.get('page', 1, type=int)
    per_page = 10

    urls = Url.query.filter_by(user_id=user_id).order_by(Url.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('my/user_urls.html', urls=urls)


@my_bp.route('/urls/create', methods=['POST'])
@jwt_required
def create_short_url(user_id):
    """创建短链接"""
    with get_db() as db:
        long_url = request.form.get('long_url')

        if not long_url:
            flash('请输入有效的URL', 'error')
            return redirect(url_for('my.user_urls'))

        # 生成短链接
        short_code = generate_short_url()
        while Url.query.filter_by(short_url=short_code).first():
            short_code = generate_short_url()

        try:
            new_url = Url(
                long_url=long_url,
                short_url=short_code,
                user_id=user_id
            )
            db.add(new_url)

            flash('短链接创建成功', 'success')
        except Exception as e:
            db.rollback()
            flash(f'创建失败: {str(e)}', 'error')

        return redirect(url_for('my.user_urls'))


@my_bp.route('/urls/delete/<int:url_id>', methods=['POST'])
@jwt_required
def delete_url(user_id, url_id):
    """删除短链接"""
    url = Url.query.filter_by(id=url_id, user_id=user_id).first()
    if not url:
        flash('链接不存在', 'error')
        return redirect(url_for('my.user_urls'))
    with get_db() as db:
        try:
            db.delete(url)

            flash('链接删除成功', 'success')
        except Exception as e:
            db.rollback()
            flash(f'删除失败: {str(e)}', 'error')

        return redirect(url_for('my.user_urls'))


@my_bp.route('/comments')
@jwt_required
def user_comments(user_id):
    """用户评论管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = 10

    comments = Comment.query.filter_by(user_id=user_id).order_by(Comment.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template('my/user_comments.html', comments=comments)


@my_bp.route('/comments/edit/<int:comment_id>', methods=['GET', 'POST'])
@jwt_required
def edit_comment(user_id, comment_id):
    """编辑评论"""
    with get_db() as db:
        # 获取要编辑的评论
        comment = db.query(Comment).filter_by(id=comment_id, user_id=user_id).first()

        if not comment:
            flash('评论不存在', 'error')
            return redirect(url_for('my.user_comments'))

        if request.method == 'POST':
            # 检查该评论是否有回复
            has_replies = Comment.query.filter_by(parent_id=comment_id).first() is not None
            if has_replies:
                flash('不允许编辑已经存在回复的评论', 'error')
                return redirect(url_for('my.user_comments'))
            content = request.form.get('content')
            if content:
                comment.content = content
                comment.updated_at = datetime.now()
                flash('评论更新成功', 'success')
                return redirect(url_for('my.user_comments'))
        return render_template('my/edit_comment.html', comment=comment)


@my_bp.route('/comments/delete/<int:comment_id>', methods=['POST'])
@jwt_required
def delete_comment(user_id, comment_id):
    """删除评论"""
    with get_db() as db:
        comment = db.query(Comment).filter_by(id=comment_id, user_id=user_id).first()
        if not comment:
            flash('评论不存在', 'error')
            return redirect(url_for('my.user_comments'))

        try:
            db.delete(comment)

            flash('评论删除成功', 'success')
        except Exception as e:
            db.rollback()
            flash(f'删除失败: {str(e)}', 'error')

        return redirect(url_for('my.user_comments'))


@my_bp.route('/posts')
@jwt_required
def my_posts(user_id):
    try:
        status_filter = request.args.get('status', 'all')
        search_query = request.args.get('search', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        # 构建查询
        query = Article.query.filter_by(user_id=user_id)

        # 状态筛选
        if status_filter != 'all':
            query = query.filter_by(status=status_filter.title())

        # 搜索筛选
        if search_query:
            query = query.filter(Article.title.contains(search_query))

        # 排序和分页
        articles = query.order_by(Article.updated_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        # 统计数据
        stats = {
            'total': Article.query.filter_by(user_id=user_id).count(),
            'published': Article.query.filter_by(user_id=user_id, status=1).count(),
            'draft': Article.query.filter_by(user_id=user_id, status=0).count(),
            'deleted': Article.query.filter_by(user_id=user_id, status=-1).count(),
        }

        return render_template('my/user_posts.html',
                               articles=articles,
                               stats=stats,
                               status_filter=status_filter,
                               search_query=search_query)
    except Exception as e:
        print(e)


from flask import session, redirect, request, render_template, url_for
from datetime import datetime, timedelta, timezone


@my_bp.route('/pw/confirm', methods=['GET', 'POST'])
@jwt_required
def confirm_password(user_id):
    if request.method == 'POST':
        if validate_password(user_id):
            session.permanent = True  # 使 session 持久化
            session[f"tmp-change-key_{user_id}"] = True
            session[f"tmp-change-key-time_{user_id}"] = datetime.now(timezone.utc)  # 记录当前时间，并指定时区为 UTC
            return redirect(url_for('my.change_password', user_id=user_id))
    return render_template('Authentication.html', form='confirm')


@my_bp.route('/pw/change', methods=['GET', 'POST'])
@jwt_required
def change_password(user_id):
    if not session.get(f"tmp-change-key_{user_id}"):
        return redirect(url_for('my.confirm_password', user_id=user_id))

    # 检查时间戳是否超过 15 分钟
    confirm_time = session.get(f"tmp-change-key-time_{user_id}")
    if confirm_time is None or datetime.now(timezone.utc) - confirm_time > timedelta(
            minutes=15):  # 使用 timezone.utc 以确保时区一致
        session.pop(f"tmp-change-key_{user_id}", None)
        session.pop(f"tmp-change-key-time_{user_id}", None)
        return redirect(url_for('my.confirm_password', user_id=user_id))

    if request.method == 'POST':
        ip = get_client_ip(request)
        new_pass = request.form.get('new_password')
        repeat_pass = request.form.get('confirm_password')
        if update_password(user_id, new_password=new_pass, confirm_password=repeat_pass, ip=ip):
            session.pop(f"tmp-change-key_{user_id}")
            session.pop(f"tmp-change-key-time_{user_id}")
            return render_template('inform.html', status_code='200', message='密码修改成功！')
        else:
            return render_template('Authentication.html', form='change')

    return render_template('Authentication.html', form='change')
