from pathlib import Path

from bs4 import BeautifulSoup
from flask import jsonify, request


def diy_space_put(base_dir,user_name,encoding='utf-8'):
    index_data = request.get_json()
    if not index_data or 'html' not in index_data:
        return jsonify({'error': '缺少 HTML 内容'}), 400
    html_content = index_data['html']
    soup = BeautifulSoup(html_content, 'html.parser')
    # for tag in soup.find_all(['script', 'iframe', 'form']):
    #    tag.decompose()
    tailwind_css = soup.new_tag(
        'link',
        rel='stylesheet',
        href='/static/css/tailwind.min.css'
    )
    if soup.head:
        soup.head.append(tailwind_css)
    else:
        head = soup.new_tag('head')
        head.append(tailwind_css)
        if soup.html:
            soup.html.insert(0, head)
        else:
            # 重建完整 HTML 结构
            html = soup.new_tag('html')
            html.append(head)
            body = soup.new_tag('body')
            html.append(body)
            soup.append(html)
    try:
        user_dir = Path(base_dir) / 'media' / user_name
        user_dir.mkdir(parents=True, exist_ok=True)
        index_path = user_dir / 'index.html'
        index_path.write_text(str(soup), encoding=encoding)
    except Exception as e:
        #app.logger.error(f"Error in file upload: {e} by {user_id}")
        return jsonify({'error': f'保存失败: {str(e)}'}), 500

    return jsonify({'message': '主页更新成功'}), 200