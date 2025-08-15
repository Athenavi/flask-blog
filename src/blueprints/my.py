from datetime import datetime

from flask import Blueprint, request, render_template, redirect, flash, url_for

from src.models import db, Url, Comment
from src.user.authz.decorators import jwt_required
from src.utils.shortener.links import generate_short_url

# from src.error import error

my_bp = Blueprint('my', __name__, template_folder='templates')


@my_bp.route('/my/urls')
@jwt_required
def user_urls(user_id):
    """用户URL管理页面"""

    page = request.args.get('page', 1, type=int)
    per_page = 10

    urls = Url.query.filter_by(user_id=user_id).order_by(Url.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('my/user_urls.html', urls=urls)


@my_bp.route('/my/urls/create', methods=['POST'])
@jwt_required
def create_short_url(user_id):
    """创建短链接"""
    long_url = request.form.get('long_url')

    if not long_url:
        flash('请输入有效的URL', 'error')
        return redirect(url_for('user_urls'))

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
        db.session.add(new_url)
        db.session.commit()
        flash('短链接创建成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'创建失败: {str(e)}', 'error')

    return redirect(url_for('user_urls'))


@my_bp.route('/my/urls/delete/<int:url_id>', methods=['POST'])
@jwt_required
def delete_url(user_id, url_id):
    """删除短链接"""
    url = Url.query.filter_by(id=url_id, user_id=user_id).first()
    if not url:
        flash('链接不存在', 'error')
        return redirect(url_for('user_urls'))

    try:
        db.session.delete(url)
        db.session.commit()
        flash('链接删除成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {str(e)}', 'error')

    return redirect(url_for('user_urls'))


@my_bp.route('/my/comments')
@jwt_required
def user_comments(user_id):
    """用户评论管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = 10

    comments = Comment.query.filter_by(user_id=user_id).order_by(Comment.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('my/user_comments.html', comments=comments)


@my_bp.route('/my/comments/edit/<int:comment_id>', methods=['GET', 'POST'])
@jwt_required
def edit_comment(user_id, comment_id):
    """编辑评论"""
    comment = Comment.query.filter_by(id=comment_id, user_id=user_id).first()
    if not comment:
        flash('评论不存在', 'error')
        return redirect(url_for('user_comments'))

    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            try:
                comment.content = content
                comment.updated_at = datetime.now()
                db.session.commit()
                flash('评论更新成功', 'success')
                return redirect(url_for('user_comments'))
            except Exception as e:
                db.session.rollback()
                flash(f'更新失败: {str(e)}', 'error')

    return render_template('my/edit_comment.html', comment=comment)


@my_bp.route('/my/comments/delete/<int:comment_id>', methods=['POST'])
@jwt_required
def delete_comment(user_id, comment_id):
    """删除评论"""

    comment = Comment.query.filter_by(id=comment_id, user_id=user_id).first()
    if not comment:
        flash('评论不存在', 'error')
        return redirect(url_for('user_comments'))

    try:
        db.session.delete(comment)
        db.session.commit()
        flash('评论删除成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {str(e)}', 'error')

    return redirect(url_for('user_comments'))
