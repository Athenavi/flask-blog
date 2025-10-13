import threading
import time

from flask import Blueprint

from plugins.kuaiMD.kuaiMD import start_server, convert_markdown_to_html, get_main_page
from plugins.tools import proxy_request
from src.database import get_db
from src.models import Article, ArticleContent

kuaiMD_bp = Blueprint('kuaiMD', __name__)

kuaiMD_port = 12001
server_started = False  # 添加服务器状态标志


def register_plugin(app):
    # 创建蓝图
    bp = Blueprint('kuaiMD_plugin', __name__)

    # 注册路由
    bp.register_blueprint(kuaiMD_bp)

    # 创建插件对象（包含元数据）
    plugin = type('Plugin', (), {
        'name': 'KuaiMD Plugin',
        'version': '0.0.1',
        'description': 'A plugin demonstrating plugin system capabilities',
        'author': '--kuaibote.com--',
        'blueprint': bp,
        'enabled': True,
        'config': app.config.get('HELLO_PLUGIN_CONFIG', {})
    })()

    # 添加自定义方法
    plugin.greet = lambda: f"Hello from {plugin.name}!"

    # 使用线程启动服务器
    global server_started
    if not server_started:
        server_thread = threading.Thread(target=start_server, kwargs={'port': kuaiMD_port})
        server_thread.daemon = True  # 设置为守护线程
        server_thread.start()

        # 等待服务器启动
        time.sleep(1)  # 给服务器一点启动时间
        server_started = True

    return plugin


@kuaiMD_bp.route('/kuaiMD', methods=['GET', 'POST', 'PUT', 'DELETE'])
@kuaiMD_bp.route('/kuaiMD/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def index(path=''):
    return proxy_request(target_url=f'http://localhost:{kuaiMD_port}/{path}')


@kuaiMD_bp.route('/p/<slug>.md/fullscreen', methods=['GET', 'POST'])
def fullscreen(slug):
    with get_db() as db:
        try:
            article = db.query(Article).filter(
                Article.slug == slug,
                Article.status == 1,
            ).first()

            print(f'0. {article}')

            if article:
                # 获取文章内容
                content = db.query(ArticleContent).filter_by(aid=article.article_id).first()

                # 获取多语言版本
                # i18n_versions = db.query(ArticleI18n).filter_by(article_id=article.article_id).all()

                # 获取作者信息
                # author = db.query(User).get(article.user_id)
                # print(f'1. author: {author}')
                # print(f'2. content: {content}')
                # print(f'3. i18n: {i18n_versions}')
                return get_main_page(your_content=content.content)
            return None
        except Exception as e:
            print(f'Error: {e}')
            return None
