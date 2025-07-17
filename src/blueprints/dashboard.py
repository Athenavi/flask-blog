from flask import Blueprint, request, render_template
from flask import jsonify

from src.config.theme import get_all_themes
from src.database import get_db_connection
# from src.error import error
from src.user.authz.decorators import admin_required

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates')


@dashboard_bp.route('/dashboard', methods=['GET'])
@admin_required
def m_overview(user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SHOW TABLE STATUS WHERE Name IN ('articles', 'users', 'comments','media','events');")
        dash_info = cursor.fetchall()
        cursor.execute('SELECT * FROM events')
        events = cursor.fetchall()
        cursor.close()
        connection.close()
        return render_template('dashboard/M-overview.html', dashInfo=dash_info, events=events)
    except Exception as e:
        return jsonify({"message": f"获取Overview时出错: {str(e)}"}), 500


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


@dashboard_bp.route('/dashboard/articles', methods=['PUT'])
@admin_required
def m_articles_edit(user_id):
    data = request.get_json()
    article_id = data.get('ArticleID')
    article_title = data.get('Title')
    article_status = data.get('Status')
    if not article_id or not article_title:
        return jsonify({"message": "操作失败"}), 400

    validators = {
        'Title': lambda v: 1 <= len(v) <= 255,
        'Status': lambda v: v in ['Published', 'Draft', 'Deleted']
    }

    if not validators['Title'](article_title):
        return jsonify({"message": "标题长度必须在1到255个字符之间"}), 400

    if article_status is not None and not validators['Status'](article_status):
        return jsonify({"message": "无效的状态"}), 400

    try:
        with get_db_connection() as connection:
            with connection.cursor(dictionary=True) as cursor:
                query = "UPDATE `articles` SET `Title` = %s,`Status`= %s WHERE `article_id` = %s;"
                cursor.execute(query, (article_title, article_status, int(article_id)))
                connection.commit()

        return jsonify({"message": "操作成功"}), 200

    except Exception as e:
        return jsonify({"message": "操作失败", "error": str(e)}), 500
    finally:
        referrer = request.referrer
        print(f"{referrer} : modify article {article_id} by  {user_id}")


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


@dashboard_bp.route('/dashboard/users', methods=['PUT'])
@admin_required
def m_users_edit(user_id):
    data = request.get_json()
    u_id = data.get('UId')
    user_name = data.get('UName')
    user_role = data.get('URole')
    if not u_id or not user_name:
        return jsonify({"message": "操作失败"}), 400

    try:
        with get_db_connection() as connection:
            with connection.cursor(dictionary=True) as cursor:
                query = "UPDATE `users` SET `username` = %s WHERE `id` = %s;"
                cursor.execute(query, (user_name, int(u_id)))
                connection.commit()

        return jsonify({"message": "操作成功"}), 200

    except Exception as e:
        return jsonify({"message": "操作失败", "error": str(e)}), 500
    finally:
        referrer = request.referrer
        print(f"{referrer} edit {u_id} to {user_role} by: {user_id}")


@dashboard_bp.route('/dashboard/v2/user', methods=['GET', 'POST'])
@admin_required
def dashboard_v2_user(user_id):
    if request.method == 'POST':
        try:
            with get_db_connection() as connection:
                with connection.cursor(dictionary=True) as cursor:
                    # 查询所有用户数据
                    json_data = []
                    query = "SELECT `id`, `username`, `updated_at`,`email`,`bio`, `profile_picture` FROM `users`"
                    cursor.execute(query)
                    user_data = cursor.fetchall()
                    if not user_data:
                        return jsonify({"message": "没有用户数据"}), 404
                    for user in user_data:
                        formatted_data = {
                            'id': user['id'],
                            'username': user['username'],
                            'email': user['email'],
                            'bio': user['bio'] if user['bio'] else '',
                            'profilePicture': user['profile_picture'] if user['profile_picture'] else None,
                            'lastActive': user['updated_at'].strftime('%Y-%m-%d') if user['updated_at'] else None
                        }
                        json_data.append(formatted_data)
            return jsonify(json_data), 200

        except Exception as e:
            # app.logger.error(f"Error in searching users: {e} by {user_id}")
            referrer = request.referrer
            # app.logger.info(f"{referrer}: queried all users")
            return jsonify({"message": "操作失败", "error": str(e)}), 500
    return render_template('dashboardV2/user.html', menu_active='user')


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
dashboard_v2_blog = query_dashboard_data('/dashboard/v2/blog', 'dashboardV2/blog.html', 'articles', menu_active='blog')
dashboard_v2_comment = query_dashboard_data('/dashboard/v2/comment', 'dashboardV2/comment.html', 'comments',
                                            menu_active='comment')
dashboard_v2_media = query_dashboard_data('/dashboard/v2/media', 'dashboardV2/media.html', 'media', menu_active='media')
dashboard_v2_notification = query_dashboard_data('/dashboard/v2/notification', 'dashboardV2/notification.html',
                                                 'notifications', menu_active='notification')
dashboard_v2_report = query_dashboard_data('/dashboard/v2/report', 'dashboardV2/report.html', 'reports',
                                           menu_active='report')
dashboard_v2_url = query_dashboard_data('/dashboard/v2/url', 'dashboardV2/url.html', 'urls', menu_active='url')
