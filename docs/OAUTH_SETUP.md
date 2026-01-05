# OAuth 第三方登录配置指南

本项目支持通过GitHub和Google进行第三方登录。本文档将指导您如何配置这些功能。

## GitHub OAuth 配置

### 1. 创建 GitHub OAuth 应用

1. 访问 GitHub 开发者设置页面：[https://github.com/settings/developers](https://github.com/settings/developers)
2. 点击 "New OAuth App" 按钮
3. 填写应用信息：
   - **Application name**: 您的应用名称（例如：My Flask Blog）
   - **Homepage URL**: 您的网站地址（例如：https://yourdomain.com/）
   - **Authorization callback URL**: `https://yourdomain.com/auth/github/callback`

### 2. 获取凭证

创建应用后，您将获得：
- Client ID
- Client Secret

### 3. 配置环境变量

将以下环境变量添加到您的系统中：

```bash
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
```

## Google OAuth 配置

### 1. 创建 Google OAuth 应用

1. 访问 Google Cloud Console：[https://console.cloud.google.com/](https://console.cloud.google.com/)
2. 创建新项目或选择现有项目
3. 启用 "Google+ API"（如果需要用户信息）
4. 转到 "凭据" 部分，点击 "创建凭据" -> "OAuth 2.0 客户端 ID"
5. 配置 OAuth 同意屏幕（如果尚未配置）
6. 选择 "Web 应用程序" 作为应用程序类型
7. 填写信息：
   - **名称**: 您的应用名称
   - **授权重定向 URI**: `https://yourdomain.com/auth/google/callback`

### 2. 获取凭证

创建客户端后，您将获得：
- Client ID
- Client Secret

### 3. 配置环境变量

将以下环境变量添加到您的系统中：

```bash
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

## 环境变量配置方式

### 方法1：使用 .env 文件

在项目根目录创建 `.env` 文件：

```env
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

### 方法2：系统环境变量

在 Linux/macOS 中：

```bash
export GITHUB_CLIENT_ID=your_github_client_id
export GITHUB_CLIENT_SECRET=your_github_client_secret
export GOOGLE_CLIENT_ID=your_google_client_id
export GOOGLE_CLIENT_SECRET=your_google_client_secret
```

在 Windows 中：

```cmd
set GITHUB_CLIENT_ID=your_github_client_id
set GITHUB_CLIENT_SECRET=your_github_client_secret
set GOOGLE_CLIENT_ID=your_google_client_id
set GOOGLE_CLIENT_SECRET=your_google_client_secret
```

## 数据库模型

系统使用 `SocialAccount` 模型来存储第三方登录信息，包括：

- `provider`: 提供商名称（'github' 或 'google'）
- `provider_user_id`: 第三方平台的用户ID
- `provider_username`: 第三方平台的用户名
- `provider_email`: 第三方平台的邮箱
- `extra_data`: 额外的用户信息（JSON格式）

## 功能说明

- 用户可以通过GitHub或Google账户首次登录时自动创建账户
- 如果用户使用已注册的邮箱登录，系统会将第三方账户关联到现有账户
- 已关联的账户可以直接登录，无需输入密码
- 用户信息会自动从第三方平台同步（如头像、姓名等）

## 安全说明

- 请确保Callback URL与您配置的完全一致
- 保护好您的Client Secret，不要将其暴露在前端代码中
- 定期检查和轮换您的OAuth凭证