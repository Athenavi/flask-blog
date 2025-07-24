# 第一阶段：构建阶段
FROM python:3.12.4 AS builder

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libmariadb-dev \
    libmariadb-dev-compat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# 第二阶段：运行阶段
FROM python:3.12.4-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libmariadb3 \
    # 健康检查工具
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 从构建阶段复制已安装的Python包
COPY --from=builder /root/.local /root/.local
# 复制应用代码
COPY . .

# 添加路径确保可找到安装的包
ENV PATH=/root/.local/bin:$PATH

# 创建非root用户
RUN groupadd -r appuser && useradd -r -g appuser appuser \
    # 创建日志目录并授权
    && mkdir -p /app/temp \
    && chown -R appuser:appuser /app

# 设置环境变量
ENV DB_HOST='host.docker.internal'
ENV DB_PORT='3306'
ENV DB_NAME='zb'
ENV DB_USER='root'
ENV DB_PASSWORD='123456'
ENV DB_POOL_SIZE='16'

# 暴露端口
EXPOSE 9421 9422

# 健康检查 (每30秒检查，超时3秒)
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:9421/health || exit 1

# 切换到非root用户
USER appuser

# 启动命令
CMD ["python", "wsgi.py"]