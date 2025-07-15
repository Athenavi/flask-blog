# 使用基础镜像
FROM python:3.12.4

# 设置工作目录
WORKDIR /app

# 更新包列表并安装必要的编译工具、pkg-config 和 MySQL 客户端开发库
RUN apt-get update && apt-get install -y \
    build-essential \
    libgl1-mesa-glx \
    pkg-config \
    libmariadb-dev \
    libmariadb-dev-compat

# 将应用程序代码复制到容器中
COPY . /app

# 安装依赖
RUN pip install -r requirements.txt

# 清理不必要的包以减小镜像大小
RUN apt-get remove -y build-essential && apt-get autoremove -y && apt-get clean

# 暴露端口
EXPOSE 9421,9422

# 定义环境变量，用于数据库配置

ENV DB_HOST='host.docker.internal'
ENV DB_PORT='3306'
ENV DB_NAME='zb'
ENV DB_USER='root'
ENV DB_PASSWORD='123456'

# 创建日志文件并设置权限
RUN mkdir -p /app/temp
RUN chmod 777 /app/temp

# 定义启动命令
CMD ["python", "wsgi.py"]
