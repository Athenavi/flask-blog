# 微信支付配置说明

本文档介绍了如何配置微信支付功能，以便在系统中正常使用VIP购买功能。

## 1. 获取微信支付凭证

### 1.1 注册微信支付商户账号
1. 访问 [微信支付商户平台](https://pay.weixin.qq.com/)
2. 注册并完成企业认证

### 1.2 创建应用
1. 登录微信支付商户平台
2. 进入「产品中心」->「AppID账号管理」
3. 绑定现有的公众号或小程序，或者创建新的应用

### 1.3 获取必要信息
在微信支付商户平台获取以下信息：
- 商户号(MCHID)
- AppID(应用ID)
- APIv3密钥
- 证书序列号

## 2. 生成密钥对

### 2.1 生成商户私钥
使用OpenSSL生成商户私钥：

```bash
# 创建目录
mkdir -p keys/wechat

# 生成私钥
openssl genrsa -out keys/wechat/private_key.pem 2048
```

### 2.2 获取微信支付平台证书
1. 在微信支付商户平台进入「账户中心」->「API安全」
2. 下载平台证书并保存到 [cert](file:///D:/desket/GitClone/zb/cert) 目录

## 3. 配置环境变量

在 `.env` 文件中配置以下参数：

```env
# 微信支付配置
WECHAT_APPID=your_wechat_app_id              # 微信应用ID（公众号或小程序AppID）
WECHAT_MCHID=your_wechat_mchid               # 微信支付商户号
WECHAT_API_V3_KEY=your_wechat_api_v3_key     # APIv3密钥
WECHAT_CERT_SERIAL_NO=your_cert_serial_no    # 证书序列号
WECHAT_NOTIFY_URL=https://yourdomain.com/api/payment/wechat/notify  # 异步回调地址
WECHAT_CERT_DIR=./cert                       # 平台证书目录
```

## 4. 配置说明

### 4.1 配置项详解

| 配置项 | 说明 | 获取途径 |
|--------|------|---------|
| WECHAT_APPID | 微信应用ID | 微信公众平台或小程序平台 |
| WECHAT_MCHID | 商户号 | 微信支付商户平台 |
| WECHAT_API_V3_KEY | APIv3密钥 | 微信支付商户平台->账户中心->API安全 |
| WECHAT_CERT_SERIAL_NO | 证书序列号 | 微信支付商户平台->账户中心->API安全->查看证书 |
| WECHAT_NOTIFY_URL | 支付结果回调URL | 自定义，需公网可访问 |
| WECHAT_CERT_DIR | 平台证书目录 | 本地目录，存放下载的平台证书 |

### 4.2 文件结构

```
项目根目录/
├── keys/
│   └── wechat/
│       └── private_key.pem      # 商户私钥文件
├── cert/                        # 微信支付平台证书目录
│   ├── xxx.pem
│   └── yyy.pem
```

## 5. 测试配置

运行调试脚本检查配置是否正确：

```bash
python debug_wechat_pay.py
```

## 6. 常见问题

### 6.1 缺少配置项
确保 `.env` 文件中包含了所有必需的配置项

### 6.2 证书问题
- 确保证书文件放置在正确的目录下
- 确保证书文件是从微信支付商户平台下载的有效证书

### 6.3 回调地址不可达
- 确保回调地址是公网可访问的HTTPS地址
- 在开发环境中可以使用内网穿透工具进行测试

## 7. 安全注意事项

1. 保护好私钥文件，不要将其提交到代码仓库
2. 确保回调接口的安全性，防止恶意请求
3. 定期更换API密钥
4. 记录支付日志便于排查问题