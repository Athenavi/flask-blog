import importlib
import os
import sys
import traceback


class PluginManager:
    def __init__(self, app=None):
        self.app = app
        self.plugins = {}
        self.blueprints = {}
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.plugin_manager = self  # 将管理器附加到app

    def is_plugin_enabled(self, plugin_path):
        """检查插件是否启用（没有__off__文件则为启用）"""
        off_file = os.path.join(plugin_path, "__off__")
        return not os.path.exists(off_file)

    def load_plugins(self, plugin_dir="plugins"):
        """动态加载所有插件，并根据__off__文件判断是否启用"""
        plugin_path = os.path.join(os.path.dirname(__file__))
        print(f"🔍 正在扫描插件目录: {plugin_path}")

        if not os.path.exists(plugin_path):
            print(f"⚠️ 插件目录不存在: {plugin_path}")
            return

        for plugin_name in os.listdir(plugin_path):
            # 跳过非目录文件
            if not os.path.isdir(os.path.join(plugin_path, plugin_name)):
                continue

            # 检查插件是否启用
            if not self.is_plugin_enabled(plugin_path=os.path.join(plugin_path, plugin_name)):
                print(f"🚫 插件已禁用: {plugin_name} (发现 __off__ 文件)")
                continue

            try:
                # 动态导入插件模块
                module = importlib.import_module(f"{plugin_dir}.{plugin_name}")

                # 检查是否有效插件（包含register_plugin函数）
                if hasattr(module, 'register_plugin'):
                    plugin = module.register_plugin(self.app)
                    self.plugins[plugin_name] = plugin
                    print(f"✅ 已加载插件: {plugin_name}")
                else:
                    print(f"⚠️ 插件无效: {plugin_name} (缺少 register_plugin 函数)")

            except ImportError as e:
                print(f"❌ 加载插件 {plugin_name} 失败: {str(e)}")
            except Exception as e:
                print(f"❌ 初始化插件 {plugin_name} 时出错: {str(e)}")

    def register_blueprints(self):
        """注册所有已启用插件的蓝图"""
        for name, plugin in self.plugins.items():
            if hasattr(plugin, 'blueprint'):
                # 存储蓝图引用
                self.blueprints[name] = plugin.blueprint
                self.app.register_blueprint(plugin.blueprint)
                print(f"🔵 已注册蓝图: {name}")

    def register_blueprint_single(self, plugin_name):
        """注册单个插件的蓝图（修复版）"""
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            if hasattr(plugin, 'blueprint'):
                # 生成唯一的蓝图名称避免冲突
                unique_name = f"{plugin_name}_{id(plugin)}"
                plugin.blueprint.name = unique_name

                # 存储蓝图引用
                self.blueprints[plugin_name] = plugin.blueprint
                self.app.register_blueprint(plugin.blueprint)
                print(f"🔵 已注册蓝图: {plugin_name} -> {unique_name}")

                # 调试：打印新注册的路由
                print(f"🗺️ 新注册的路由:")
                for rule in self.app.url_map.iter_rules():
                    if rule.endpoint.startswith(f"{unique_name}."):
                        print(f"  - {rule.rule} [{', '.join(rule.methods)}]")
                return True
        return False

    def unregister_blueprint(self, plugin_name):
        """注销指定插件的蓝图（增强版）"""
        if plugin_name in self.blueprints:
            blueprint = self.blueprints[plugin_name]

            # 1. 从应用中移除蓝图
            if blueprint.name in self.app.blueprints:
                del self.app.blueprints[blueprint.name]

            # 2. 清理所有相关路由
            for rule in list(self.app.url_map._rules):
                if rule.endpoint.startswith(f"{blueprint.name}."):
                    self.app.url_map._rules.remove(rule)

            # 3. 清理视图函数
            for endpoint in list(self.app.view_functions):
                if endpoint.startswith(f"{blueprint.name}."):
                    del self.app.view_functions[endpoint]

            print(f"🔴 已注销蓝图: {plugin_name} ({blueprint.name})")
            del self.blueprints[plugin_name]

    def reload_plugin(self, plugin_name):
        """重新加载插件（修复蓝图注册限制问题）"""
        plugin_base_path = os.path.join(os.path.dirname(__file__))
        current_plugin_path = os.path.join(plugin_base_path, plugin_name)

        module_name = f"plugins.{plugin_name}"

        # 1. 如果已加载则先卸载
        if plugin_name in self.plugins:
            self.unregister_blueprint(plugin_name)
            del self.plugins[plugin_name]

        # 2. 递归清除所有相关模块缓存
        modules_to_remove = [
            name for name in sys.modules
            if name == module_name or name.startswith(f"{module_name}.")
        ]
        for name in modules_to_remove:
            del sys.modules[name]
            print(f"🗑️ 已移除模块缓存: {name}")

        # 3. 重新加载插件（仅当插件启用时）
        try:
            if self.is_plugin_enabled(current_plugin_path):
                # 重新导入模块
                module = importlib.import_module(module_name)

                # 重新注册插件
                if hasattr(module, 'register_plugin'):
                    plugin = module.register_plugin(self.app)
                    self.plugins[plugin_name] = plugin
                    print(f"✅ 成功重新加载插件: {plugin_name}")

                    # 检查应用状态：只有在应用未运行或未处理请求时才注册蓝图
                    app_started = getattr(self.app, '_got_first_request', False)

                    if hasattr(plugin, 'blueprint'):
                        if not app_started:
                            # 应用未启动，安全注册蓝图
                            self.register_blueprint_single(plugin_name)
                            print(f"🔵 已注册蓝图: {plugin_name}")
                            return True
                        else:
                            # 应用已运行，无法注册新蓝图
                            print(f"⚠️ 应用已启动，无法注册蓝图: {plugin_name}")
                            print("提示: 蓝图功能将不可用，但插件其他功能仍可工作")
                            return True  # 插件加载成功，只是蓝图未注册
                    else:
                        print(f"ℹ️ 插件 {plugin_name} 不包含蓝图")
                        return True
                else:
                    print(f"⚠️ 重新加载的插件无效: {plugin_name} (缺少 register_plugin 函数)")
                    return False
            else:
                print(f"🚫 插件 {plugin_name} 处于禁用状态，跳过加载")
                return False
        except Exception as e:
            print(f"❌ 重新加载插件 {plugin_name} 失败: {str(e)}", file=sys.stderr)
            traceback.print_exc()
            return False

    def execute_hook(self, hook_name, *args, **kwargs):
        """执行指定钩子（仅限已启用插件）"""
        results = []
        for name, plugin in self.plugins.items():
            if hasattr(plugin, hook_name):
                try:
                    hook = getattr(plugin, hook_name)
                    result = hook(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    print(f"⚠️ 执行钩子 {hook_name} 时出错 [{name}]: {str(e)}")
        return results

    def get_plugin_list(self):
        """获取所有插件信息（包括启用状态）"""
        plugins = []
        plugin_base_path = os.path.join(os.path.dirname(__file__))
        # 获取所有插件目录（无论是否启用）
        all_plugins = [name for name in os.listdir(plugin_base_path)
                       if os.path.isdir(os.path.join(plugin_base_path, name))]

        for plugin_name in all_plugins:
            plugin_path = os.path.join(plugin_base_path, plugin_name)
            is_enabled = self.is_plugin_enabled(plugin_path)

            plugin_info = {
                'name': plugin_name,
                'enabled': is_enabled,
                'status': 'active' if is_enabled else 'disabled',
                'version': 'unknown',
                'description': 'No description available',
                'author': 'Unknown',
                'routes': []
            }

            # 如果插件已加载，补充详细信息
            if plugin_name in self.plugins:
                plugin = self.plugins[plugin_name]
                plugin_info.update({
                    'version': getattr(plugin, 'version', 'unknown'),
                    'description': getattr(plugin, 'description', 'No description available'),
                    'author': getattr(plugin, 'author', 'Unknown')
                })

                # 获取插件注册的路由
                if hasattr(plugin, 'blueprint') and plugin_name in self.blueprints:
                    for rule in self.app.url_map.iter_rules():
                        if rule.endpoint.startswith(f"{self.blueprints[plugin_name].name}."):
                            plugin_info['routes'].append({
                                'url': rule.rule,
                                'methods': sorted(rule.methods)
                            })

            plugins.append(plugin_info)
        return plugins

    def enable_plugin(self, plugin_name):
        """启用插件（增强版）"""
        plugin_base_path = os.path.join(os.path.dirname(__file__))
        plugin_path = os.path.join(plugin_base_path, plugin_name)
        off_file = os.path.join(plugin_path, "__off__")

        # 检查应用状态
        app_started = getattr(self.app, '_got_first_request', False)

        if os.path.exists(off_file):
            os.remove(off_file)
            print(f"🟢 已移除禁用标记: {plugin_name}")

            # 重新加载插件
            success = self.reload_plugin(plugin_name)
            if success:
                print(f"✅ 成功启用并加载插件: {plugin_name}")

                # 特殊处理：如果应用已运行且插件有蓝图
                if app_started and plugin_name in self.plugins:
                    plugin = self.plugins[plugin_name]
                    if hasattr(plugin, 'blueprint'):
                        print(f"⚠️ 警告: 由于应用已运行，{plugin_name} 的蓝图功能需要重启才能生效")
                return True
            else:
                # 创建回退文件防止状态不一致
                with open(off_file, 'w') as f:
                    f.write("自动回滚：启用失败")
                print(f"❌ 启用插件失败，已恢复禁用状态: {plugin_name}")
                return False
        else:
            print(f"⚠️ 插件 {plugin_name} 已经是启用状态")
            if plugin_name not in self.plugins:
                return self.reload_plugin(plugin_name)
            return True

    def disable_plugin(self, plugin_name):
        """禁用插件"""
        plugin_base_path = os.path.join(os.path.dirname(__file__))
        plugin_path = os.path.join(plugin_base_path, plugin_name)
        off_file = os.path.join(plugin_path, "__off__")

        if not os.path.exists(off_file):
            with open(off_file, 'w') as file:
                file.write("")  # 创建一个空的__off__文件以禁用插件

            print(f"🔴 已添加禁用标记: {plugin_name}")
            if plugin_name in self.plugins:
                self.unregister_blueprint(plugin_name)
                del self.plugins[plugin_name]
                print(f"🔄 已禁用并卸载插件: {plugin_name}")
                return True
            return True  # 即使未加载也返回成功
        else:
            print(f"⚠️ 插件 {plugin_name} 已经是禁用状态")
            return True
