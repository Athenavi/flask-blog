from MySQLdb import IntegrityError
from flask import Blueprint, request, render_template
from flask import jsonify

from src.models import User, db, Role, Permission, UserRole, RolePermission

role_bp = Blueprint('role', __name__, template_folder='templates')


@role_bp.route('/admin/role', methods=['GET'])
def admin_roles():
    return render_template('dashboard/role.html')


@role_bp.route('/admin/role', methods=['POST'])
def create_role():
    """创建新角色"""
    try:
        data = request.get_json()

        required_fields = ['name', 'description']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'缺少必填字段: {field}'
                }), 400

        new_role = Role(
            name=data['name'],
            description=data['description']
        )

        db.session.add(new_role)
        db.session.flush()

        # 添加权限关联
        if 'permission_ids' in data:
            for permission_id in data['permission_ids']:
                permission = Permission.query.get(permission_id)
                if permission:
                    new_role.permissions.append(permission)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '角色创建成功',
            'data': {
                'id': new_role.id,
                'name': new_role.name,
                'description': new_role.description
            }
        }), 201

    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': '角色名称已存在'
        }), 409

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'创建角色失败: {str(e)}'
        }), 500


@role_bp.route('/admin/role/<int:role_id>', methods=['PUT'])
def update_role(role_id):
    """更新角色"""
    try:
        role = Role.query.get_or_404(role_id)
        data = request.get_json()

        if 'name' in data:
            role.name = data['name']
        if 'description' in data:
            role.description = data['description']

        # 更新权限关联
        if 'permission_ids' in data:
            role.permissions.clear()
            for permission_id in data['permission_ids']:
                permission = Permission.query.get(permission_id)
                if permission:
                    role.permissions.append(permission)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '角色更新成功',
            'data': {
                'id': role.id,
                'name': role.name,
                'description': role.description
            }
        }), 200

    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': '角色名称已存在'
        }), 409

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'更新角色失败: {str(e)}'
        }), 500


@role_bp.route('/admin/role/<int:role_id>', methods=['DELETE'])
def delete_role(role_id):
    """删除角色"""
    try:
        role = Role.query.get_or_404(role_id)

        if len(role.users) > 0:
            return jsonify({
                'success': False,
                'message': f'无法删除角色，该角色已分配给 {len(role.users)} 个用户'
            }), 409

        role_name = role.name
        db.session.delete(role)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'角色 "{role_name}" 删除成功'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'删除角色失败: {str(e)}'
        }), 500


@role_bp.route('/admin/permission', methods=['GET'])
def get_permissions():
    """获取权限列表"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search = request.args.get('search', '', type=str)

        query = Permission.query

        if search:
            query = query.filter(
                db.or_(
                    Permission.code.contains(search),
                    Permission.description.contains(search)
                )
            )

        permissions = query.paginate(page=page, per_page=per_page, error_out=False)

        permissions_data = []
        for permission in permissions.items:
            permissions_data.append({
                'id': permission.id,
                'code': permission.code,
                'description': permission.description,
                'role_count': len(permission.roles)
            })

        return jsonify({
            'success': True,
            'data': permissions_data,
            'pagination': {
                'page': permissions.page,
                'pages': permissions.pages,
                'per_page': permissions.per_page,
                'total': permissions.total,
                'has_next': permissions.has_next,
                'has_prev': permissions.has_prev
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取权限列表失败: {str(e)}'
        }), 500


@role_bp.route('/admin/permission', methods=['POST'])
def create_permission():
    """创建新权限"""
    try:
        data = request.get_json()

        required_fields = ['code', 'description']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'缺少必填字段: {field}'
                }), 400

        new_permission = Permission(
            code=data['code'],
            description=data['description']
        )

        db.session.add(new_permission)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '权限创建成功',
            'data': {
                'id': new_permission.id,
                'code': new_permission.code,
                'description': new_permission.description
            }
        }), 201

    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': '权限代码已存在'
        }), 409

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'创建权限失败: {str(e)}'
        }), 500


@role_bp.route('/admin/permission/<int:permission_id>', methods=['PUT'])
def update_permission(permission_id):
    """更新权限"""
    try:
        permission = Permission.query.get_or_404(permission_id)
        data = request.get_json()

        if 'code' in data:
            permission.code = data['code']
        if 'description' in data:
            permission.description = data['description']

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '权限更新成功',
            'data': {
                'id': permission.id,
                'code': permission.code,
                'description': permission.description
            }
        }), 200

    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': '权限代码已存在'
        }), 409

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'更新权限失败: {str(e)}'
        }), 500


@role_bp.route('/admin/permission/<int:permission_id>', methods=['DELETE'])
def delete_permission(permission_id):
    """删除权限"""
    try:
        permission = Permission.query.get_or_404(permission_id)

        if len(permission.roles) > 0:
            return jsonify({
                'success': False,
                'message': f'无法删除权限，该权限已分配给 {len(permission.roles)} 个角色'
            }), 409

        permission_code = permission.code
        db.session.delete(permission)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'权限 "{permission_code}" 删除成功'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'删除权限失败: {str(e)}'
        }), 500


@role_bp.route('/admin/user/<int:user_id>/roles', methods=['GET'])
def get_user_roles(user_id):
    """获取用户的角色"""
    try:
        user = User.query.get_or_404(user_id)

        user_roles = []
        for role in user.roles:
            user_roles.append({
                'id': role.id,
                'name': role.name,
                'description': role.description
            })

        return jsonify({
            'success': True,
            'data': {
                'user_id': user.id,
                'username': user.username,
                'roles': user_roles
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取用户角色失败: {str(e)}'
        }), 500


@role_bp.route('/admin/user/<int:user_id>/roles', methods=['PUT'])
def update_user_roles(user_id):
    """更新用户角色"""
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()

        if 'role_ids' not in data:
            return jsonify({
                'success': False,
                'message': '缺少角色ID列表'
            }), 400

        # 清除现有角色
        user.roles.clear()

        # 添加新角色
        for role_id in data['role_ids']:
            role = Role.query.get(role_id)
            if role:
                user.roles.append(role)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '用户角色更新成功',
            'data': {
                'user_id': user.id,
                'username': user.username,
                'role_count': len(user.roles)
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'更新用户角色失败: {str(e)}'
        }), 500


@role_bp.route('/admin/role-permission/stats', methods=['GET'])
def get_role_permission_stats():
    """获取角色权限统计信息"""
    try:
        total_roles = Role.query.count()
        total_permissions = Permission.query.count()
        total_user_roles = UserRole.query.count()
        total_role_permissions = RolePermission.query.count()

        return jsonify({
            'success': True,
            'data': {
                'total_roles': total_roles,
                'total_permissions': total_permissions,
                'total_user_roles': total_user_roles,
                'total_role_permissions': total_role_permissions
            }
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取统计信息失败: {str(e)}'
        }), 500
