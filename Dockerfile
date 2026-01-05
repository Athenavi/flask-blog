# 第一阶段：构建阶段
FROM python:3.12.4 AS builder

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libpq-dev \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 第二阶段：运行阶段
FROM python:3.12.4-slim

WORKDIR /app

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libmagic-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制已安装的Python包
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

# 复制应用代码
COPY . .

# 创建必要的目录
RUN mkdir -p logs temp_uploads thumbnails && \
    touch logs/gunicorn_access.log logs/gunicorn_error.log

# 暴露端口
EXPOSE 9421

# 启动命令
CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:application"]