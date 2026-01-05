# Giscus 集成说明(自托管)

本项目已集成 Giscus 评论系统，这是一个基于 GitHub Discussions 的评论系统，无需后端支持。

## 配置步骤

### 1. 准备 GitHub 仓库
- 确保你有一个公开的 GitHub 仓库（例如：Athenavi/flask-blog）
- 在仓库的 Settings -> Features 中启用 Discussions 功能

### 2. 安装 Giscus App
- 访问 [giscus.app](https://giscus.app)
- 使用 GitHub 账号登录，并授权 Giscus 应用访问你的仓库

### 3. 获取配置参数
在 giscus.app 页面上完成配置后，系统会自动生成脚本代码，包含以下参数：

- `data-repo`：仓库名称（格式：用户名/仓库名）
- `data-repo-id`：仓库 ID
- `data-category`：讨论分类名称
- `data-category-id`：讨论分类 ID

### 4. 更新配置
在 [templates/blog/detail.html](file:///D:/desket/GitClone/zb/templates/blog/detail.html) 文件中，将以下参数替换为你的实际配置：

```html
<script src="https://giscus.app/client.js"
        data-repo="Athenavi/flask-blog"  <!-- 替换为你的仓库 -->
        data-repo-id="your-repo-id"      <!-- 替换为你的仓库ID -->
        data-category="Announcements"    <!-- 替换为你的分类 -->
        data-category-id="your-category-id" <!-- 替换为你的分类ID -->
        ...
</script>
```

## 核心配置项说明

- `data-mapping="pathname"`：使用页面的 URL 路径来关联讨论，这是最常用的选择
- `data-theme="preferred_color_scheme"`：评论框主题会自动跟随用户设备的深色/浅色模式
- `data-lang="zh-CN"`：将界面语言设置为简体中文

## 验证与调试

### 检查是否成功
部署后，打开一篇博客文章，滚动到文章底部。应该能看到评论框，并显示 "0 comments" 或类似的提示。

### 发表第一条评论
以 GitHub 账号登录后尝试发表评论。成功后，刷新你的 GitHub 仓库的 Discussions 板块，应该能看到一个新的话题被自动创建。

### 常见问题排查
- **评论区不显示**：按 F12 打开浏览器开发者工具，查看 Console 有无红色报错。最常见的原因是仓库未公开、Discussions 未开启或配置信息填写错误。
- **不同文章出现相同评论**：确认 `data-mapping` 参数设置正确。对于动态路由，确保每篇文章有唯一的 URL。

## 高级优化建议

### 懒加载提升性能
如果评论区在页面首屏之外，可以仅在用户滚动到附近时再加载 Giscus 脚本，这能提升页面初始加载速度。

### 自定义样式
Giscus 评论框的样式可以通过 CSS 进行微调（例如宽度、圆角等），以更好地匹配你的博客设计。