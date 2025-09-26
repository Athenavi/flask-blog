import re
from datetime import datetime, timedelta, timezone

from flask import Response
from flask import stream_with_context


def send_chunk_md(content, aid, iso=None):
    # 生成安全的文件名
    safe_date = re.sub(r'[^\w\-.]', '_', str(datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")))
    if iso:
        filename = f"i18n{iso}_blog_{aid}.md"
    else:
        filename = f"blog_{aid}_{safe_date}.md"

    # 创建生成器函数用于流式传输
    def generate():
        chunk_size = 4096
        for i in range(0, len(content), chunk_size):
            yield content[i:i + chunk_size]

    # 设置响应头
    headers = {
        "Content-Disposition": f"attachment; filename={filename}",
        "Content-Type": "text/markdown; charset=utf-8",

        # 缓存控制头
        "Cache-Control": "public, max-age=600",
        "Expires": (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "Pragma": "cache",
        "ETag": f'"{hash(content)}"'  # 内容哈希作为ETag
    }

    # 使用流式响应
    return Response(
        stream_with_context(generate()),
        headers=headers
    )

