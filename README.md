<div align="center">
<h1>zyBLOG - 现代化Python Flask博客系统</h1>

[![Python Version](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://www.python.org/)
[![Flask Version](https://img.shields.io/badge/flask-3.1.x-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-Apache%202.0-orange.svg)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/Athenavi/flask-blog.svg?style=social)](https://github.com/Athenavi/flask-blog/stargazers)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Athenavi/flask-blog)

一个功能丰富、易于部署的现代化博客系统，支持主题定制、插件扩展和响应式页面。

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [配置说明](#-配置说明) • [开发指南](#-开发指南) • [API文档](#-api文档)

</div>

## 🌟 功能特性

### 核心功能
- **文章管理** - 支持Markdown编辑器、标签分类、全文搜索
- **用户系统** - 完整的用户注册/登录、权限管理、个人主页
- **评论系统** - 支持嵌套评论、实时通知、审核机制
- **媒体管理** - 图片上传、自动缩略图生成
- **SEO优化** - 自动sitemap生成、友好URL、元标签优化

### 扩展功能
- **主题系统** - 支持切换主题、主题开发API
- **插件架构** - 模块化插件系统，支持功能扩展
- **数据统计** - 访问量统计、用户行为分析
- **安全防护** - SQL注入防护、XSS过滤
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


### 方式一：手动部署

```bash
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
psql -U postgres -d flaskblog -f blog.sql

# 6. 启动应用
python wsgi.py
```

### 方式二：Docker部署

```bash
# 构建并运行
docker build -t zyblog .
docker run -d -p 9421:9421 --name zyblog-app zyblog
```

## 🔧 配置说明

应用启动前需要配置 `.env` 文件，主要配置项说明：

### 数据库配置 [6](#0-5) 
```env
DB_HOST=127.0.0.1      # 数据库主机
DB_PORT=3306           # 数据库端口
DB_USER=postgres       # 数据库用户名
DB_PASSWORD=123456     # 数据库密码
DB_NAME=flaskblog      # 数据库名称
```

### 应用配置 [7](#0-6) 
```env
DOMAIN=http://localhost:9421  # 应用访问域名
TITLE=我的博客               # 网站标题
SECRET_KEY=your-secret-key   # 应用密钥（必须修改）
```

### 邮件配置 [8](#0-7) 
```env
MAIL_HOST=smtp.163.com       # SMTP服务器
MAIL_PORT=465               # SMTP端口
MAIL_USER=your@email.com    # 发件邮箱
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

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

若使用 Windows with Python 3.14.0 进行开发
需要安装MS build tools工具-->
```
    MSVC v143-VS 2022 C++ x64/x86生成工...
    用于Windows 的 C++ CMake 工具
    适用于最新v143 生成工具的C++ATL(x86...
    Windows 10（11） SDK 
```

1. Fork本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开Pull Request

## 📄 开源协议

本项目采用 [Apache License 2.0](./LICENSE) 开源协议。 [15](#0-14) 

##  获取帮助

- **示例网站**: [athenavi.cn](https://athenavi.cn)
- **问题反馈**: [GitHub Issues](https://github.com/Athenavi/flask-blog/issues)  
- **文档Wiki**: [项目Wiki](https://deepwiki.com/Athenavi/flask-blog)

---

**默认管理员账号**: `test` / `123456` [16](#0-15)   
**访问地址**: `http://localhost:9421` [17](#0-16) 

