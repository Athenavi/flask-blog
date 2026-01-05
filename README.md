<div align="center">
<h1>zyBLOG - 现代化Python Flask博客系统</h1>

[![Python Version](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://www.python.org/)
[![Flask Version](https://img.shields.io/badge/flask-3.1.x-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-Apache%202.0-orange.svg)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/Athenavi/flask-blog.svg?style=social)](https://github.com/Athenavi/flask-blog/stargazers)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Athenavi/flask-blog)

一个功能丰富、易于部署的现代化博客系统，支持主题定制、插件扩展和响应式页面。

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [配置说明](#-配置说明) • [开发指南](#-开发指南) • [API文档](#-api文档) • [Docker部署](#-docker部署)

</div>

## 🌟 功能特性

### 核心功能

- **文章管理** - 支持Markdown编辑器、标签分类、全文搜索
- **用户系统** - 完整的用户注册/登录、权限管理、个人主页
- **评论系统** - Giscus
- **媒体管理** - 基于S3协议的图片上传、本地的自动缩略图生成
- **SEO优化** - 自动sitemap生成、友好URL、元标签优化

### 扩展功能

- **主题系统** - 支持切换主题、主题开发API
- **插件架构** - 模块化插件系统，支持功能扩展
- **数据统计** - 
  - 访问量统计：记录页面访问、用户行为、设备信息
  - 用户行为分析：追踪用户活动、分析用户模式、生成洞察报告
  - 统计API：提供仪表板、页面统计、用户活动等API端点
- **安全防护** - 
  - SQL注入防护：参数化查询、输入验证、安全查询构建器
  - XSS过滤：HTML转义、内容过滤、安全输出
  - 输入验证：多种验证函数、安全装饰器、文件名清理
- **API接口** - RESTful API设计，支持第三方集成

### 技术特性

- **高性能** - 数据库连接池、缓存机制、静态文件优化
- **可扩展** - 微服务架构、蓝图模块化设计
- **易部署** - 支持Docker、宝塔面板部署
- **多平台** - 完美适配桌面和移动设备

## 🚀 快速开始

### 系统要求

- Python 3.14+ [5](#0-4)
- Postgres 17.4+
- 2GB+ 内存推荐

### Vercel一键部署（推荐）

点击下方按钮，即可在Vercel上一键部署：

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2FAthenavi%2Fflask-blog&env=DB_ENGINE,DB_HOST,DB_PORT,DB_NAME,DB_USER,DB_PASSWORD,DB_SSLMODE&envDescription=Database%20configuration%20for%20your%20application&project-name=zyblog-deployment&repository-name=zyblog)

### 方式一：手动部署

```
# 1. 克隆项目
git clone https://github.com/Athenavi/flask-blog.git
cd flask-blog

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置环境变量
cp .env_example .env
# 编辑.env文件（详见配置说明）

# 5. 初始化数据库
createdb -U postgres flaskblog
psql -U postgres -d flaskblog -f sql/blog.sql

# 6. 启动应用
python wsgi.py
```

## 🐳 Docker部署

### Docker快速部署

```
# 1. 复制环境变量配置
cp .env_example .env
# 编辑 .env 文件以配置数据库和其他设置

# 2. 构建并启动服务
docker-compose up -d

# 3. 访问应用
# 应用将在 http://localhost:80 或 http://localhost:9421 可用
```

### Docker镜像构建

```
# 构建镜像
docker build -t zyblog .

# 运行容器（需要数据库等依赖服务）
docker run -d -p 9421:9421 --name zyblog-app zyblog
```

### Docker Compose服务

Docker Compose配置包括以下服务：
- **app**: Flask应用服务器，运行zyBLOG主程序
- **db**: PostgreSQL数据库，存储应用数据
- **redis**: Redis缓存，提供会话和缓存支持
- **nginx**: 反向代理服务器，处理静态文件和SSL

## 🔧 配置说明

应用启动前需要配置 `.env` 文件，主要配置项说明：

### 数据库配置 [6](#0-5)

```env
DB_HOST=127.0.0.1      # 数据库主机
DB_PORT=5432           # 数据库端口
DB_USER=postgres       # 数据库用户名
DB_PASSWORD=123456     # 数据库密码
DB_NAME=flaskblog      # 数据库名称
DB_ENGINE=postgresql   # 数据库引擎 (postgresql/sqlite)
```

### 应用配置 [7](#0-6)

```env
DOMAIN=http://localhost:9421  # 应用访问域名
TITLE=flask-blog              # 网站标题
SECRET_KEY=your-secret-key   # 应用密钥（必须修改）
TIME_ZONE=Asia/Shanghai      # 时区设置
```

### 邮件配置 [8](#0-7)

```env
MAIL_HOST=smtp.163.com       # SMTP服务器
MAIL_PORT=465               # SMTP端口
MAIL_USER=your@email.com    # 发件邮箱
MAIL_PASSWORD=your-password # 邮箱密码或授权码
```

## 📁 项目结构

```
flask-blog/
├── src/                    # 核心源代码
│   ├── blog/              # 博客模块
│   ├── user/              # 用户模块  
│   ├── blueprints/        # 蓝图路由
│   ├── models.py          # 数据模型
│   └── app.py             # 应用入口
├── templates/             # 前端模板
├── static/               # 静态资源
├── plugins/              # 插件目录
├── requirements.txt      # Python依赖
├── blog.sql             # 数据库结构
├── wsgi.py              # WSGI入口
└── Dockerfile           # Docker配置
```

## 🛠️ 开发指南

### 主题开发

主题文件结构： [10](#0-9)

```
themes/mytheme/
├── index.html           # 首页模板
├── screenshot.png       # 主题预览图
└── template.ini        # 主题配置
```

主题配置示例： [11](#0-10)

### 插件开发

插件文件结构： [12](#0-11)

```
plugins/myplugin/
├── __init__.py         # 插件初始化
├── views.py           # 路由处理
└── requirements.txt   # 插件依赖
```

### API接口

应用提供RESTful API接口，详细文档请访问：`/api/docs`

#### 统计与分析API

系统提供以下统计分析API端点：

- `GET /api/analytics/dashboard` - 获取仪表板统计数据
- `GET /api/analytics/page-views` - 获取页面访问统计
- `GET /api/analytics/user-activities` - 获取用户活动统计
- `GET /api/analytics/top-pages` - 获取热门页面统计
- `GET /api/analytics/user-behavior/<user_id>` - 获取用户行为分析

#### 安全功能API

安全相关的API和工具函数：

- `src.utils.security.safe` - 安全工具模块
- `src.utils.analytics` - 统计分析工具模块
- `src.models.misc` - 统计相关数据模型

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

1. Fork本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开Pull Request

## 📄 开源协议

本项目采用 [Apache License 2.0](./LICENSE) 开源协议。

## 获取帮助&&故障排除

[docs](./docs/)]
---

**默认管理员账号**: `test` / `123456` [16](#0-15)   
**访问地址**: `http://localhost:9421` [17](#0-16) 

