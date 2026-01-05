"""
Dashboard 系统设置模块
包含系统设置、菜单管理、页面管理等功能
"""
import inspect
import json
from datetime import datetime

from flask import request, render_template, jsonify

from src.auth_utils import admin_required
from src.extensions import limiter
from src.models import User, db, Menus, MenuItems, Pages, SystemSettings
from src.utils.config_manager import config_manager
from . import admin_bp


def has_circular_dependency(parent_id, current_item_id=None, menu_id=None):
    """
    检查是否存在循环依赖
    :param parent_id: 要设置为父项的菜单项ID
    :param current_item_id: 当前正在编辑的菜单项ID（在更新时使用，避免自己成为自己的父项）
    :param menu_id: 菜单ID，用于限制检查范围
    :return: 如果存在循环依赖返回True，否则返回False
    """
    if not parent_id or not current_item_id:
        return False

    # 检查目标父项是否是自身（自己不能成为自己的父项）
    if parent_id == current_item_id:
        return True

    # 获取所有菜单项和它们的父级关系
    all_items = db.session.query(MenuItems.id, MenuItems.parent_id).filter_by(menu_id=menu_id).all()

    # 构建父->子映射和子->父映射
    parent_child_map = {}
    child_parent_map = {}

    for item in all_items:
        if item.parent_id:
            # 构建父->子映射
            if item.parent_id not in parent_child_map:
                parent_child_map[item.parent_id] = []
            parent_child_map[item.parent_id].append(item.id)

            # 构建子->父映射
            child_parent_map[item.id] = item.parent_id

    # 模拟更新：更新当前项的父级
    # 首先移除当前项从其原始父级的子列表中
    if current_item_id in child_parent_map:
        original_parent = child_parent_map[current_item_id]
        if original_parent in parent_child_map and current_item_id in parent_child_map[original_parent]:
            parent_child_map[original_parent].remove(current_item_id)

    # 如果parent_id不为None，将当前项添加到新父级的子列表中
    if parent_id:
        if parent_id not in parent_child_map:
            parent_child_map[parent_id] = []
        parent_child_map[parent_id].append(current_item_id)

    # 更新子->父映射
    if parent_id:
        child_parent_map[current_item_id] = parent_id
    elif current_item_id in child_parent_map:
        del child_parent_map[current_item_id]

    # 查找循环：检查从parent_id开始，是否能找到一条路径回到current_item_id
    visited = set()

    def dfs(node_id):
        """深度优先搜索检查循环"""
        # 如果当前节点就是我们要检查的目标，说明找到了循环
        if node_id == current_item_id:
            return True

        # 如果已经访问过这个节点，避免无限递归
        if node_id in visited:
            return False

        visited.add(node_id)

        # 检查当前节点的所有子节点
        if node_id in parent_child_map:
            for child_id in parent_child_map[node_id]:
                if dfs(child_id):
                    return True

        return False

    # 从parent_id开始检查是否能到达current_item_id
    return dfs(parent_id)


@admin_bp.route('/settings', methods=['GET', 'POST', 'PUT', 'DELETE'])
@admin_required
@limiter.limit("10 per minute")
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
                    # 将值序列化为JSON字符串以存储到数据库
                    # 处理 None、空字典和其他特殊值
                    if value is None:
                        serialized_value = None
                    elif isinstance(value, (dict, list)):
                        serialized_value = json.dumps(value, ensure_ascii=False)
                    else:
                        serialized_value = str(value)
                    setting = db.session.query(SystemSettings).filter_by(key=key).first()
                    if setting:
                        setting.value = serialized_value
                        setting.updated_at = datetime.now()
                        setting.updated_by = user_id
                    else:
                        setting = SystemSettings(
                            key=key,
                            value=serialized_value,
                            updated_at=datetime.now(),
                            updated_by=user_id
                        )
                        db.session.add(setting)
                db.session.commit()

                db.session.commit()

                # 刷新配置（如果需要）
                config_keys = ['mail_host', 'mail_port', 'mail_user', 'mail_password',
                               'redis_host', 'redis_port', 'redis_password', 'redis_db',
                               's3_enabled', 's3_endpoint', 's3_access_key', 's3_secret_key',
                               's3_bucket', 's3_region', 's3_use_ssl']

                if any(key in config_keys for key in settings.keys()):
                    try:
                        config_manager.refresh_all_configs()
                        print('配置已实时更新')
                    except Exception as refresh_error:
                        print(f'配置刷新失败: {str(refresh_error)}')

                return jsonify({'success': True, 'message': '设置已保存'})
            except Exception as e:
                return jsonify({'success': False, 'message': f'保存失败: {str(e)}'})

        # 处理站点图像上传
        if request.method == 'POST' and request.form.get('action') == 'upload_site_image':
            try:
                from flask import current_app
                from werkzeug.utils import secure_filename
                import os
                import hashlib

                # 检查是否有文件上传
                if 'file' not in request.files:
                    return jsonify({'success': False, 'message': '没有上传文件'}), 400

                file = request.files['file']
                if file.filename == '':
                    return jsonify({'success': False, 'message': '没有选择文件'}), 400

                # 验证文件类型
                allowed_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp']
                if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
                    return jsonify(
                        {'success': False, 'message': '不支持的文件类型，仅支持PNG, JPG, JPEG, GIF, WEBP'}), 400

                # 检查文件大小
                file.seek(0, 2)  # 移动到文件末尾
                file_size = file.tell()
                file.seek(0)  # 重置文件指针

                if file_size > 5 * 1024 * 1024:  # 5MB
                    return jsonify({'success': False, 'message': '文件大小不能超过5MB'}), 400

                # 读取文件内容
                file_content = file.read()

                # 计算文件哈希
                file_hash = hashlib.sha256(file_content).hexdigest()

                # 保存文件到存储位置
                upload_dir = os.path.join(current_app.root_path, '..', 'static', 'site_images')
                os.makedirs(upload_dir, exist_ok=True)

                # 生成安全的文件名
                file_ext = os.path.splitext(secure_filename(file.filename))[1]
                safe_filename = f"{file_hash}{file_ext}"
                file_path = os.path.join(upload_dir, safe_filename)

                # 保存文件
                with open(file_path, 'wb') as f:
                    f.write(file_content)

                # 构建文件URL
                file_url = f"{request.url_root}static/site_images/{safe_filename}"

                # 保存到系统设置
                setting = db.session.query(SystemSettings).filter_by(key='site_img').first()
                # 将文件URL作为字符串值保存
                serialized_file_url = str(file_url) if file_url is not None else None
                if setting:
                    setting.value = serialized_file_url
                    setting.updated_at = datetime.now()
                    setting.updated_by = user_id
                else:
                    setting = SystemSettings(
                        key='site_img',
                        value=serialized_file_url,
                        updated_at=datetime.now(),
                        updated_by=user_id
                    )
                    db.session.add(setting)
                db.session.commit()

                # 返回成功响应
                return jsonify({
                    'success': True,
                    'message': '站点图像上传成功',
                    'uploaded': [{
                        'filename': file.filename,
                        'url': file_url,
                        'hash': file_hash
                    }]
                })

            except Exception as e:
                db.session.rollback()
                return jsonify({'success': False, 'message': f'上传失败: {str(e)}'}), 500

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

                # 验证parent_id是否属于同一菜单，同时检查循环依赖
                if parent_id:
                    parent_item = db.session.query(MenuItems).filter_by(id=parent_id).first()
                    if not parent_item or parent_item.menu_id != int(menu_id):
                        return jsonify({'success': False, 'message': '父菜单项不存在或不属于当前菜单'})

                    # 检查循环依赖：不能将菜单项设置为其自身的子项或间接子项
                    # 创建时没有原始父ID，所以传入None
                    if has_circular_dependency(parent_id, None, int(menu_id), None):
                        return jsonify({'success': False, 'message': '不能形成循环依赖：所选父菜单项是当前菜单项的子项'})

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
                parent_id = request.form.get('parent_id')

                item = db.session.query(MenuItems).filter_by(id=item_id).first()
                if item:
                    # 保存原来的父ID用于循环依赖检测
                    original_parent_id = item.parent_id

                    item.title = title
                    item.url = url
                    item.target = target
                    item.order_index = order_index
                    item.is_active = is_active

                    # 更新父菜单项
                    if parent_id:
                        parent_item = db.session.query(MenuItems).filter_by(id=parent_id).first()
                        if not parent_item or parent_item.menu_id != item.menu_id:
                            return jsonify({'success': False, 'message': '父菜单项不存在或不属于当前菜单'})

                        # 检查循环依赖：不能将菜单项设置为其自身的子项或间接子项
                        if has_circular_dependency(parent_id, item.id, item.menu_id, original_parent_id):
                            return jsonify(
                                {'success': False, 'message': '不能形成循环依赖：所选父菜单项是当前菜单项的子项'})

                        item.parent_id = parent_id
                    else:
                        item.parent_id = None

                    db.session.commit()
                    return jsonify({'success': True, 'message': '菜单项更新成功'})
                return jsonify({'success': False, 'message': '菜单项不存在'})

            elif action == 'update_order':
                menu_id = request.form.get('menu_id')
                order_updates = request.form.get('order_updates')

                if order_updates:
                    try:
                        order_updates = json.loads(order_updates)

                        for update in order_updates:
                            item_id = update.get('id')
                            order_index = update.get('order_index', 0)

                            item = db.session.query(MenuItems).filter_by(id=item_id).first()
                            if item:
                                item.order_index = order_index

                        db.session.commit()
                        return jsonify({'success': True, 'message': '菜单项排序更新成功'})
                    except Exception as e:
                        db.session.rollback()
                        return jsonify({'success': False, 'message': f'更新排序失败: {str(e)}'})

                return jsonify({'success': False, 'message': '没有提供排序更新数据'})

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

                existing_page = db.session.query(Pages).filter_by(slug=slug).first()
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
                db.session.add(page)
                db.session.commit()
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
        settings_dict = {}
        for setting in system_settings:
            if setting.value is None:
                settings_dict[setting.key] = None
            else:
                try:
                    # 尝试将值反序列化为JSON对象
                    settings_dict[setting.key] = json.loads(setting.value)
                except (json.JSONDecodeError, TypeError):
                    # 如果不是JSON格式，则直接使用原始值
                    settings_dict[setting.key] = setting.value

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
