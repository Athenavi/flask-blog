from functools import wraps

from flask_principal import Permission, RoleNeed

# 定义权限需求
# 基于角色的权限
admin_role = RoleNeed('admin')
manager_role = RoleNeed('manager')
user_role = RoleNeed('user')


# 基于权限代码的权限（更细粒度）
def permission_need(permission_code):
    return PermissionNeed(permission_code)


# 创建权限对象
class PermissionNeed:
    def __init__(self, code):
        self.code = code

    def __hash__(self):
        return hash(self.code)

    def __eq__(self, other):
        return isinstance(other, PermissionNeed) and self.code == other.code


# 常用权限组合
admin_permission = Permission(admin_role)
manager_permission = Permission(manager_role)
user_permission = Permission(user_role)


def create_permission(permission_code):
    """创建基于权限代码的权限对象"""
    return Permission(PermissionNeed(permission_code))


# 权限装饰器
def permission_required(permission):
    """权限检查装饰器"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            with permission.require():
                return f(*args, **kwargs)

        return decorated_function

    return decorator


def role_required(role_name):
    """角色检查装饰器"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            with Permission(RoleNeed(role_name)).require():
                return f(*args, **kwargs)

        return decorated_function

    return decorator


def init_security_headers(app):
    """初始化安全头配置"""
    
    @app.after_request
    def after_request(response):
        # 添加安全头
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # 允许同源iframe嵌套
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # 如果启用了HTTPS，添加Strict-Transport-Security头
        if not app.debug and not app.testing:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
        return response