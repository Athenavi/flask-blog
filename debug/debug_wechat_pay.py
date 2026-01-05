#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
微信支付配置调试脚本
用于检查微信支付相关配置是否正确加载
"""

import os
from pathlib import Path

# 加载环境变量
from dotenv import load_dotenv

load_dotenv()

def check_wechat_pay_config():
    """检查微信支付配置"""
    print("=== 微信支付配置检查 ===")
    
    # 必需的配置项
    required_configs = [
        'WECHAT_APPID',
        'WECHAT_MCHID', 
        'WECHAT_API_V3_KEY',
        'WECHAT_CERT_SERIAL_NO',
        'WECHAT_NOTIFY_URL',
        'WECHAT_CERT_DIR'
    ]
    
    # 检查环境变量配置
    print("\n1. 环境变量配置检查:")
    missing_configs = []
    for config in required_configs:
        value = os.getenv(config)
        if value:
            # 对于密钥等敏感信息，只显示部分信息
            if 'KEY' in config:
                print(f"  {config}: {'*' * len(value) if len(value) <= 10 else value[:5] + '*' * 10 + value[-5:]}")
            else:
                print(f"  {config}: {value}")
        else:
            print(f"  {config}: 未配置 ❌")
            missing_configs.append(config)
    
    # 检查私钥文件
    print("\n2. 私钥文件检查:")
    private_key_path = Path('../keys/wechat/private_key.pem')
    if private_key_path.exists():
        print(f"  私钥文件: 存在 ✅ ({private_key_path})")
        try:
            content = private_key_path.read_text()[:100]  # 只读取前100个字符
            print(f"  文件内容预览: {content}...")
        except Exception as e:
            print(f"  文件读取失败: {e} ❌")
    else:
        print(f"  私钥文件: 不存在 ❌ ({private_key_path})")
        missing_configs.append('WECHAT_PRIVATE_KEY')
    
    # 检查证书目录
    print("\n3. 证书目录检查:")
    cert_dir = os.getenv('WECHAT_CERT_DIR', '../cert')
    cert_path = Path(cert_dir)
    if cert_path.exists() and cert_path.is_dir():
        print(f"  证书目录: 存在 ✅ ({cert_path})")
        files = list(cert_path.iterdir())
        if files:
            print(f"  目录内容: {[f.name for f in files]}")
        else:
            print(f"  目录内容: 空目录")
    else:
        print(f"  证书目录: 不存在 ❌ ({cert_path})")
        missing_configs.append('WECHAT_CERT_DIR')
    
    # 总结
    print("\n4. 检查结果:")
    if missing_configs:
        print(f"  缺失配置项: {missing_configs} ❌")
        print("  请在 .env 文件中添加以上配置项")
        return False
    else:
        print("  所有配置项均已正确配置 ✅")
        return True

if __name__ == '__main__':
    success = check_wechat_pay_config()
    if not success:
        exit(1)
    else:
        print("\n✅ 微信支付配置检查通过")