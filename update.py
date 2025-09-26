import os
import shutil
import threading
import time
import zipfile
from pathlib import Path

import markdown
import requests
from flask import Flask, render_template, jsonify
from packaging import version

base_dir = os.path.dirname(os.path.abspath(__file__))  # 项目根目录

app = Flask(__name__, template_folder=Path(base_dir) / 'templates')


def get_current_version():
    # 从version.txt中读取当前版本
    with open(Path(base_dir) / 'version.txt', 'r') as f:
        return f.read().strip()


# 配置信息
CONFIG = {
    'github_repo': 'Athenavi/zb',  # GitHub仓库名
    'current_version': get_current_version(),
    'auto_check_interval': 3600,  # 自动检查间隔(秒)
    'backup_before_update': True,  # 更新前是否备份
}

# 更新状态
update_status = {
    'available': False,
    'latest_version': '',
    'changelog': '',
    'progress': 0,
    'message': '',
    'is_updating': False
}


def ensure_directory_exists(path):
    """确保目录存在，如果不存在则创建"""
    if not os.path.exists(path):
        os.makedirs(path)


def get_latest_release():
    """
    从GitHub获取最新发行版信息，包含错误处理
    """
    url = f"https://api.github.com/repos/{CONFIG['github_repo']}/releases/latest"
    try:
        # 禁用 SSL 验证（不推荐用于生产环境）
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except requests.exceptions.SSLError as e:
        # 专门处理SSL错误
        print(f"SSL证书验证失败: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        # 处理连接问题（如网络断开、DNS失败）
        print(f"网络连接错误: {e}")
        return None
    except requests.exceptions.Timeout as e:
        # 处理请求超时
        print(f"请求超时: {e}")
        return None
    except requests.exceptions.RequestException as e:
        # 处理所有其他requests异常
        print(f"获取最新版本时发生未知错误: {e}")
        return None


def check_for_update():
    """检查是否有更新"""
    latest_release = get_latest_release()
    if not latest_release:
        return False, None, None

    latest_version = latest_release['tag_name']
    changelog = latest_release.get('body', '')
    changelog = markdown.markdown(changelog, extensions=['markdown.extensions.fenced_code', 'toc'])

    # 使用packaging.version进行精确版本比较
    current_ver = version.parse(CONFIG['current_version'])
    latest_ver = version.parse(latest_version)

    if latest_ver > current_ver:
        return True, latest_version, changelog
    else:
        return False, latest_version, changelog


def download_release(version):
    """下载指定版本的发行包"""
    url = f"https://github.com/{CONFIG['github_repo']}/archive/refs/tags/{version}.zip"
    download_path = f"{base_dir}/temp/{version}.zip"
    ensure_directory_exists(os.path.dirname(download_path))  # 确保下载目录存在

    try:
        response = requests.get(url, stream=True, verify=False)
        total_size = int(response.headers.get('content-length', 0))

        with open(download_path, 'wb') as f:
            downloaded = 0
            for data in response.iter_content(chunk_size=4096):
                downloaded += len(data)
                f.write(data)
                # 更新下载进度
                if total_size > 0:
                    update_status['progress'] = int((downloaded / total_size) * 100)

        return download_path
    except Exception as e:
        print(f"下载失败: {e}")
        return None


def backup_current_version():
    """备份当前版本"""
    backup_dir = f"{base_dir}/temp/backup_{CONFIG['current_version']}"
    ensure_directory_exists(os.path.dirname(backup_dir))  # 确保备份目录存在

    if os.path.exists(backup_dir):
        shutil.rmtree(backup_dir)

    # 排除不需要备份的文件和目录
    exclude = ['__pycache__', '.git', 'venv', 'env', '.vscode', 'backups', 'hashed_files', 'logs', 'temp', '.gitignore',
               'thumbnails']
    shutil.copytree(base_dir, backup_dir, ignore=shutil.ignore_patterns(*exclude))
    return backup_dir


def apply_update(zip_path):
    """应用更新"""
    try:
        # 解压更新包
        extract_dir = f"{base_dir}/temp/update_extract"
        ensure_directory_exists(extract_dir)  # 确保解压目录存在

        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)

        # 找到解压后的目录（GitHub会自动添加版本后缀）
        extracted_folders = os.listdir(extract_dir)
        if not extracted_folders:
            return False, "更新包为空"

        source_dir = os.path.join(extract_dir, extracted_folders[0])

        # 备份当前版本（如果需要）
        if CONFIG['backup_before_update']:
            update_status['message'] = "正在备份当前版本..."
            backup_current_version()

        # 排除不需要覆盖的文件和目录
        exclude = ['config.py', 'settings.ini', 'data', 'uploads', '__pycache__', '.git']

        # 复制文件
        update_status['message'] = "正在应用更新..."
        for item in os.listdir(source_dir):
            if item in exclude:
                continue

            source_item = os.path.join(source_dir, item)
            dest_item = os.path.join(base_dir, item)

            if os.path.isdir(source_item):
                if os.path.exists(dest_item):
                    shutil.rmtree(dest_item)
                shutil.copytree(source_item, dest_item)
            else:
                shutil.copy2(source_item, dest_item)

        # 清理临时文件
        # shutil.rmtree(extract_dir)
        # os.remove(zip_path)

        return True, "更新成功"
    except Exception as e:
        return False, f"更新失败: {str(e)}"


def update_worker():
    """更新工作线程"""
    update_status['is_updating'] = True
    update_status['progress'] = 0
    update_status['message'] = "开始更新..."

    # 下载最新版本
    update_status['message'] = "正在下载更新..."
    zip_path = download_release(update_status['latest_version'])
    if not zip_path:
        update_status['message'] = "下载更新失败"
        update_status['is_updating'] = False
        return

    # 应用更新
    success, message = apply_update(zip_path)
    update_status['message'] = message
    update_status['is_updating'] = False

    if success:
        # 更新配置中的版本号
        CONFIG['current_version'] = update_status['latest_version']
        with open(Path(base_dir) / 'version.txt', 'w') as f:
            f.write(CONFIG['current_version'])
        update_status['available'] = False


def auto_check_updates():
    """自动检查更新"""
    while True:
        try:
            available, latest_version, changelog = check_for_update()
            if available:
                update_status['available'] = True
                update_status['latest_version'] = latest_version
                update_status['changelog'] = changelog
        except Exception as e:
            print(f"自动检查更新失败: {e}")

        # 等待下一次检查
        time.sleep(CONFIG['auto_check_interval'])


# 启动自动更新检查线程
update_thread = threading.Thread(target=auto_check_updates, daemon=True)
update_thread.start()


# Flask路由
@app.route('/')
def index():
    return render_template('update.html', config=CONFIG, update_status=update_status)


@app.route('/check_update')
def check_update():
    available, latest_version, changelog = check_for_update()
    if available:
        update_status['available'] = True
        update_status['latest_version'] = latest_version
        update_status['changelog'] = changelog
        return jsonify({
            'status': 'update_available',
            'current_version': CONFIG['current_version'],
            'latest_version': latest_version,
            'changelog': update_status['changelog']
        })
    else:
        return jsonify({
            'status': 'up_to_date',
            'current_version': CONFIG['current_version'],
            'latest_version': latest_version
        })


@app.route('/do_update', methods=['POST'])
def do_update():
    if update_status['is_updating']:
        return jsonify({'status': 'error', 'message': '更新正在进行中'})

    if not update_status['available']:
        return jsonify({'status': 'error', 'message': '没有可用的更新'})

    # 启动更新线程
    thread = threading.Thread(target=update_worker, daemon=True)
    thread.start()

    return jsonify({'status': 'success', 'message': '更新已开始'})


def main():
    """更新主函数"""
    print("开始更新检查...")

    update, latest_version, changelog = check_for_update()
    if not update:
        print("当前已是最新版本")
        return True

    print(f"发现新版本: {latest_version}")
    user_input = input("是否立即更新? (y/N): ")
    if user_input.lower() != 'y':
        print("取消更新")
        return False

    if not download_release(update):
        print("下载更新失败")
        return False

    if not do_update():
        print("应用更新失败")
        return False

    print("更新成功完成!")
    print("请重启应用程序以使更新生效")
    return True


@app.route('/update_status')
def get_update_status():
    return jsonify({
        'is_updating': update_status['is_updating'],
        'progress': update_status['progress'],
        'message': update_status['message']
    })


if __name__ == '__main__':
    app.run(debug=True)
