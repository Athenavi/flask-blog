# Docker 部署指南

## 概述

本文档提供了使用 Docker 和 Docker Compose 部署 zyBLOG 的完整指南。Docker 部署方式可以确保环境一致性，并简化部署过程。

## 系统要求

- Docker Engine 20.10 或更高版本
- Docker Compose v2 或更高版本
- 至少 4GB 可用内存（推荐 8GB）
- 至少 2GB 可用磁盘空间

## 部署步骤

### 1. 准备环境

首先，确保系统已安装 Docker 和 Docker Compose：

```bash
# 检查 Docker 版本
docker --version

# 检查 Docker Compose 版本
docker-compose --version
```

### 2. 获取源代码

```bash
git clone https://github.com/Athenavi/zb.git
cd zb
```

### 3. 配置环境变量

复制环境变量配置文件：

```bash
cp .env_example .env
```

编辑 `.env` 文件，根据需要修改配置：

```bash
# 数据库配置
DB_ENGINE=postgresql
DB_HOST=db
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=123456  # 建议修改为更安全的密码
DB_NAME=flaskblog

# 应用配置
DOMAIN=http://your-domain.com  # 替换为实际域名
SECRET_KEY=your-very-secure-secret-key  # 强烈建议修改
```

### 4. 准备目录结构

创建必要的目录：

```bash
mkdir -p hashed_files temp_uploads logs static cert
```

### 5. 启动服务

使用 Docker Compose 启动所有服务：

```bash
# 后台启动所有服务
docker-compose up -d

# 查看服务状态
docker-compose ps

# 查看日志
docker-compose logs -f
```

### 6. 初始设置

首次启动后，需要运行引导程序来初始化数据库和配置：

```bash
# 进入应用容器
docker-compose exec app bash

# 运行引导程序
python guide.py
```

## 服务说明

Docker Compose 配置包含以下服务：

### app (Flask应用)
- 端口: 9421
- 用途: 运行 zyBLOG 主程序
- 配置文件: gunicorn.conf.py

### db (PostgreSQL数据库)
- 端口: 5432
- 数据库: flaskblog
- 用户: postgres
- 初始化脚本: sql/*.sql

### redis (缓存服务)
- 端口: 6379
- 用途: 会话存储和缓存

### nginx (反向代理)
- 端口: 80, 443
- 静态文件服务
- SSL终止

## 管理命令

### 基本操作

```bash
# 启动所有服务
docker-compose up -d

# 停止所有服务
docker-compose down

# 重启特定服务
docker-compose restart app

# 查看日志
docker-compose logs app
docker-compose logs -f app  # 实时查看

# 进入容器
docker-compose exec app bash
docker-compose exec db psql -U postgres
```

### 构建和更新

```bash
# 重新构建镜像
docker-compose build

# 构建并启动
docker-compose up -d --build

# 拉取最新镜像
docker-compose pull
```

### 数据库管理

```bash
# 备份数据库
docker-compose exec db pg_dump -U postgres flaskblog > backup.sql

# 恢复数据库
docker-compose exec -T db psql -U postgres flaskblog < backup.sql
```

## SSL配置

要启用HTTPS，需要在 `cert` 目录中放置SSL证书：

```bash
# 在项目根目录下创建cert目录
mkdir -p cert

# 放置证书文件
# cert/cert.pem - 证书文件
# cert/key.pem - 私钥文件
```

## 故障排除

### 服务启动失败

检查日志以确定问题：

```bash
docker-compose logs app
docker-compose logs db
docker-compose logs nginx
```

### 数据库连接问题

确保数据库服务已启动：

```bash
docker-compose ps
```

检查数据库是否正常运行：

```bash
docker-compose exec db pg_isready
```

### 端口冲突

如果端口已被占用，修改 `docker-compose.yml` 中的端口映射：

```yaml
ports:
  - "9422:9421"  # 将主机端口改为9422
```

### 存储问题

确保主机目录有适当的权限：

```bash
sudo chown -R $USER:$USER hashed_files temp_uploads logs
```

## 生产环境建议

### 安全配置

1. 修改所有默认密码
2. 使用强密钥替换 SECRET_KEY
3. 配置防火墙限制访问
4. 定期更新镜像

### 性能优化

1. 调整数据库连接池大小
2. 配置适当的内存限制
3. 使用外部数据库服务
4. 配置负载均衡

### 备份策略

```bash
# 定期备份数据库
docker-compose exec db pg_dump -U postgres flaskblog > backup-$(date +%Y%m%d).sql

# 备份上传文件
tar -czf uploads-$(date +%Y%m%d).tar.gz hashed_files/
```

## 环境变量说明

| 变量 | 默认值 | 说明 |
|------|--------|------|
| DB_ENGINE | postgresql | 数据库引擎 |
| DB_HOST | db | 数据库主机 |
| DB_PORT | 5432 | 数据库端口 |
| DB_USER | postgres | 数据库用户 |
| DB_PASSWORD | 123456 | 数据库密码 |
| DB_NAME | flaskblog | 数据库名 |
| REDIS_HOST | redis | Redis主机 |
| REDIS_PORT | 6379 | Redis端口 |
| DOMAIN | http://localhost:9421 | 应用域名 |
| SECRET_KEY | your-secret-key-change-in-production | 应用密钥 |

## 常见问题

### Q: 容器启动后立即退出
A: 检查日志，通常是数据库连接失败或环境变量配置错误

### Q: 无法访问应用
A: 确认端口映射正确，防火墙未阻止端口访问

### Q: 数据库初始化失败
A: 检查 sql 目录下的 SQL 文件是否存在，数据库服务是否已完全启动