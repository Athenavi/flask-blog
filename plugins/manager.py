import importlib
import os


class PluginManager:
    def __init__(self, app=None):
        self.app = app
        self.plugins = {}
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.plugin_manager = self  # 将管理器附加到app

    def load_plugins(self, plugin_dir="plugins"):
        """动态加载所有插件"""
        base_path = os.path.join(os.path.dirname(__file__))
        print(f"🔍 正在加载插件目录: {base_path}")
        for plugin_name in os.listdir(base_path):
            if not os.path.isdir(os.path.join(base_path, plugin_name)):
                continue

            try:
                # 动态导入插件模块
                module = importlib.import_module(f"{plugin_dir}.{plugin_name}")

                # 检查是否有效插件（包含register_plugin函数）
                if hasattr(module, 'register_plugin'):
                    plugin = module.register_plugin(self.app)
                    self.plugins[plugin_name] = plugin
                    print(f"✅ 已加载插件: {plugin_name}")

            except ImportError as e:
                print(f"❌ 加载插件 {plugin_name} 失败: {str(e)}")

    def register_blueprints(self):
        """注册所有插件的蓝图"""
        for name, plugin in self.plugins.items():
            if hasattr(plugin, 'blueprint'):
                self.app.register_blueprint(plugin.blueprint)
                print(f"🔵 已注册蓝图: {name}")

    def execute_hook(self, hook_name, *args, **kwargs):
        """执行指定钩子"""
        results = []
        for name, plugin in self.plugins.items():
            if hasattr(plugin, hook_name):
                hook = getattr(plugin, hook_name)
                result = hook(*args, **kwargs)
                results.append(result)
        return results
