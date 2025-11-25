from flask import render_template, request, jsonify, current_app
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, Length, Optional, Regexp

from src.models import User, db
from src.other.sendEmail import request_email_change
from src.user.entities import check_user_conflict, change_username, bind_email
from src.user.profile.edit import edit_profile
from src.utils.security.safe import valid_language_codes


class ProfileForm(FlaskForm):
    username = StringField('用户名', validators=[
        DataRequired(message='用户名不能为空'),
        Length(min=4, max=16, message='用户名长度应为4-16个字符'),
        Regexp(r'^[a-zA-Z0-9_]+$', message='用户名只能包含字母、数字和下划线')
    ])

    email = StringField('邮箱', validators=[
        DataRequired(message='邮箱不能为空'),
        Email(message='请输入有效的邮箱地址')
    ])

    bio = TextAreaField('个人简介', validators=[
        Optional(),
        Length(max=500, message='个人简介不能超过500个字符')
    ])

    profile_private = BooleanField('私密资料')

    locale = SelectField('语言', choices=[
        ('zh_CN', '中文简体'),
        ('zh_TW', '中文繁体'),
        ('en_US', 'English')
    ], validators=[DataRequired()])


class ChangeEmailForm(FlaskForm):
    email = StringField('新邮箱', validators=[
        DataRequired(message='邮箱不能为空'),
        Email(message='请输入有效的邮箱地址')
    ])


def setting_profiles_back(user_id, user_info, cache_instance, avatar_url_api):
    try:
        if user_info is None:
            return "用户信息未找到", 404

        # 获取用户对象
        user = User.query.filter(User.id == user_id).first()
        if not user:
            return "用户不存在", 404

        # 创建表单实例并预填充数据
        profile_form = ProfileForm(
            username=user.username,
            email=user.email,
            bio=user.bio or "",
            profile_private=user.profile_private,
            locale=user.locale or 'zh_CN'
        )

        avatar_url = user.profile_picture if user.profile_picture else avatar_url_api
        bio = user.bio or "这人很懒，什么也没留下"

        return render_template(
            'my/setting.html',
            avatar_url=avatar_url,
            username=user.username,
            limit_username_lock=cache_instance.get(f'limit_username_lock_{user_id}'),
            Bio=bio,
            userEmail=user.email,
            ProfilePrivate=user.profile_private,
            profile_form=profile_form,
            change_email_form=ChangeEmailForm()
        )
    except Exception as e:
        print(f"Error in setting_profiles_back: {e}")
        return "服务器内部错误", 500


def change_profiles_back(user_id, cache_instance, domain):
    change_type = request.args.get('change_type')
    if not change_type:
        return jsonify({'error': 'Change type is required'}), 400

    if change_type not in ['avatar', 'username', 'email', 'password', 'bio', 'privacy']:
        return jsonify({'error': 'Invalid change type'}), 400

    # 清除缓存
    cache_instance.delete_memoized(current_app.view_functions['api.api_user_profile'], user_id=user_id)

    user = User.query.filter(User.id == user_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if change_type == 'username':
        form = ProfileForm()
        if form.validate_on_submit():
            username = form.username.data

            # 检查用户名修改限制
            limit_username_lock = cache_instance.get(f'limit_username_lock_{user_id}')
            if limit_username_lock:
                return jsonify({'error': 'Cannot change username more than once a week'}), 400

            # 检查用户名冲突
            if check_user_conflict(zone='username', value=username):
                return jsonify({'error': 'Username already exists'}), 400

            # 更新用户名
            change_username(user_id, new_username=username)
            cache_instance.set(f'limit_username_lock_{user_id}', True, timeout=604800)
            return jsonify({'message': 'Username updated successfully'}), 200
        else:
            return jsonify({'error': form.errors}), 400

    elif change_type == 'email':
        form = ChangeEmailForm()
        if form.validate_on_submit():
            email = form.email.data

            # 检查邮箱冲突
            if check_user_conflict(zone='email', value=email):
                return jsonify({'error': 'Email already exists'}), 400

            # 请求邮箱变更
            request_email_change(user_id, cache_instance, domain, email)
            return jsonify({'message': 'Email updated successfully'}), 200
        else:
            return jsonify({'error': form.errors}), 400

    elif change_type == 'bio':
        form = ProfileForm()
        if form.validate_on_submit():
            bio = form.bio.data
            user.bio = bio
            db.session.commit()
            return jsonify({'message': 'Bio updated successfully'}), 200
        else:
            return jsonify({'error': form.errors}), 400

    elif change_type == 'privacy':
        profile_private = request.json.get('profile_private', False)
        user.profile_private = bool(profile_private)
        db.session.commit()
        return jsonify({'message': 'Privacy settings updated successfully'}), 200

    elif change_type == 'locale':
        locale = request.json.get('locale', 'zh_CN')
        if valid_language_codes(locale):
            return jsonify({'error': 'Invalid locale'}), 400
        user.locale = locale
        db.session.commit()
        return jsonify({'message': 'Locale updated successfully'}), 200

    else:
        return edit_profile(request, change_type, user_id)


def confirm_email_back(user_id, cache_instance, token):
    new_email = cache_instance.get(f"temp_email_{user_id}").get('new_email')
    token_value = cache_instance.get(f"temp_email_{user_id}").get('token')

    # 验证令牌匹配
    if token != token_value:
        return jsonify({"error": "Invalid verification data"}), 400

    bind_email(user_id, new_email)
    cache_instance.delete_memoized(current_app.view_functions['api_user_profile'], user_id=user_id)

    return render_template('inform.html', status_code=200, message='Email updated successfully')
