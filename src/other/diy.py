from pathlib import Path

from bs4 import BeautifulSoup
from flask import request, jsonify


def diy_space_put(base_dir, user_id, encoding='utf-8'):
    try:
        index_data = request.get_json(force=True)
        print(f"Received JSON data: {index_data}")

        # 2. 处理HTML内容
        soup = BeautifulSoup(index_data.get('html'), 'html.parser')

        # 安全措施：移除危险标签
        for tag in soup.find_all(['script', 'iframe', 'form', 'link', 'meta']):
            tag.decompose()

        # 添加Tailwind CSS
        tailwind_css = soup.new_tag(
            'link',
            rel='stylesheet',
            href='/static/css/tailwind.min.css'
        )

        if soup.head:
            soup.head.append(tailwind_css)
        else:
            # 创建必要的HTML结构
            head = soup.new_tag('head')
            head.append(tailwind_css)

            if not soup.html:
                html = soup.new_tag('html')
                soup.append(html)

            if not soup.body:
                body = soup.new_tag('body')
                soup.html.append(body)

            soup.html.insert(0, head)

        # 3. 保存文件
        user_dir = Path(base_dir) / 'media' / str(user_id)
        user_dir.mkdir(parents=True, exist_ok=True)

        index_path = user_dir / 'index.html'
        index_path.write_text(str(soup), encoding=encoding)

        return jsonify({'message': '主页更新成功'}), 200

    except Exception as e:
        # 记录完整错误信息
        import traceback
        error_trace = traceback.format_exc()
        print(f"Error occurred: {error_trace}")

        # 根据错误类型返回更具体的错误信息
        if isinstance(e, (TypeError, AttributeError)):
            return jsonify({'error': '数据格式错误，请检查请求内容'}), 400
        elif isinstance(e, (OSError, PermissionError)):
            return jsonify({'error': '文件保存失败，权限或路径问题'}), 500
        else:
            return jsonify({'error': f'服务器内部错误: {str(e)}'}), 500
