# 数据库连接故障排除指南

## 错误信息解析

当您看到类似以下错误时：

```
(psycopg2.OperationalError) connection to server at "172.22.224.1", port 5432 failed: FATAL: no pg_hba.conf entry for host "172.22.234.254", user "fb_user", database "flask_blog", no encryption
```

这表示PostgreSQL拒绝了您的连接请求，因为它没有在`pg_hba.conf`文件中配置允许该主机连接。

## 错误原因分析

PostgreSQL使用`pg_hba.conf`（Host-Based Authentication）文件来控制客户端认证。当出现"No pg_hba.conf entry"错误时，说明：

1. 您的客户端IP地址未在配置文件中列出
2. 用户名和数据库组合未被允许
3. 连接方法（加密要求）不匹配

## 解决方案

### 方案一：修改pg_hba.conf文件（推荐）

1. 找到pg_hba.conf文件位置：
   - Linux: 通常在 `/etc/postgresql/[version]/main/pg_hba.conf`
   - Windows: 在PostgreSQL安装目录下的 `data` 文件夹中
   - Docker: 需要在容器内修改或挂载自定义配置

2. 编辑pg_hba.conf文件，在合适的位置添加一行：

```conf
# 允许特定用户从特定IP连接到特定数据库
host    flask_blog      fb_user         172.22.234.254/32         md5

# 或者允许特定用户从任何IP连接（仅限开发环境）
host    flask_blog      fb_user         0.0.0.0/0              md5

# 或者允许任何用户从特定网络连接（谨慎使用）
host    all             all             172.22.0.0/16          md5
```

3. 保存文件并重启PostgreSQL服务使更改生效：
   ```bash
   sudo systemctl restart postgresql
   # 或者
   pg_ctl restart
   ```

### 方案二：修改应用配置连接到允许的主机

如果无法修改PostgreSQL配置，您可以修改应用配置以连接到允许的主机：

1. 修改`.env`文件中的数据库配置：
   ```env
   DB_HOST=allowed_host_ip_or_domain
   DB_USER=allowed_user
   DB_PASSWORD=correct_password
   ```

2. 确保目标PostgreSQL服务器允许该用户从您的新主机IP连接。

### 方案三：使用SSL连接

某些情况下，PostgreSQL可能要求使用SSL连接。可以在连接字符串中添加SSL参数：

```env
DB_SSLMODE=require
```

## 连接参数说明

在pg_hba.conf中，每行的格式为：
```
连接类型 数据库名 用户名 IP地址 CIDR掩码 认证方法
```

常见参数解释：
- 连接类型：`local`(本地Unix域套接字)、`host`(TCP/IP连接)
- 数据库名：要连接的数据库名，`all`表示所有数据库
- 用户名：数据库用户名，`all`表示所有用户
- IP地址/CIDR：允许连接的客户端IP范围
- 认证方法：常用的有`trust`(无密码)、`md5`(密码认证)、`peer`(操作系统认证)

## 安全建议

1. 生产环境中避免使用`0.0.0.0/0`这样的宽泛IP范围
2. 不要在生产环境中使用`trust`认证方法
3. 定期审查pg_hba.conf文件，移除不必要的条目
4. 使用强密码并定期更换
5. 考虑使用SSL连接保护数据传输安全