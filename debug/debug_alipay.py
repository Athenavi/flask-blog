#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
支付宝配置调试脚本
用于检测支付宝配置是否正确
"""

import os
import sys
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.setting import AliPayConfig


def debug_alipay_config():
    """调试支付宝配置"""
    print("=" * 50)
    print("支付宝配置调试工具")
    print("=" * 50)
    
    # 检查环境变量
    print("1. 检查环境变量:")
    alipay_appid = os.getenv('ALIPAY_APPID')
    alipay_debug = os.getenv('ALIPAY_DEBUG')
    alipay_return_url = os.getenv('ALIPAY_RETURN_URL')
    alipay_notify_url = os.getenv('ALIPAY_NOTIFY_URL')
    
    print(f"   ALIPAY_APPID: {alipay_appid}")
    print(f"   ALIPAY_DEBUG: {alipay_debug}")
    print(f"   ALIPAY_RETURN_URL: {alipay_return_url}")
    print(f"   ALIPAY_NOTIFY_URL: {alipay_notify_url}")
    
    # 检查密钥文件
    print("\n2. 检查密钥文件:")
    private_key_path = Path('../keys/alipay/app_private_key.pem')
    public_key_path = Path('../keys/alipay/alipay_public_key.pem')
    
    print(f"   私钥文件路径: {private_key_path}")
    print(f"   私钥文件存在: {private_key_path.exists()}")
    if private_key_path.exists():
        try:
            private_key_content = private_key_path.read_text(encoding='utf-8')
            print(f"   私钥内容长度: {len(private_key_content)} 字符")
            print(f"   私钥开头: {private_key_content[:30].strip()}")
        except Exception as e:
            print(f"   读取私钥文件出错: {e}")
    
    print(f"   公钥文件路径: {public_key_path}")
    print(f"   公钥文件存在: {public_key_path.exists()}")
    if public_key_path.exists():
        try:
            public_key_content = public_key_path.read_text(encoding='utf-8')
            print(f"   公钥内容长度: {len(public_key_content)} 字符")
            print(f"   公钥开头: {public_key_content[:30].strip()}")
        except Exception as e:
            print(f"   读取公钥文件出错: {e}")
    
    # 初始化配置类
    print("\n3. 初始化支付宝配置类:")
    try:
        config = AliPayConfig()
        print(f"   ALIPAY_APPID: {config.ALIPAY_APPID}")
        print(f"   ALIPAY_DEBUG: {config.ALIPAY_DEBUG}")
        print(f"   ALIPAY_GATEWAY: {config.ALIPAY_GATEWAY}")
        print(f"   ALIPAY_RETURN_URL: {config.ALIPAY_RETURN_URL}")
        print(f"   ALIPAY_NOTIFY_URL: {config.ALIPAY_NOTIFY_URL}")
        print(f"   ALIPAY_PRIVATE_KEY_STRING 存在: {bool(config.ALIPAY_PRIVATE_KEY_STRING)}")
        print(f"   ALIPAY_PUBLIC_KEY_STRING 存在: {bool(config.ALIPAY_PUBLIC_KEY_STRING)}")
        
        if config.ALIPAY_PRIVATE_KEY_STRING:
            print(f"   私钥长度: {len(config.ALIPAY_PRIVATE_KEY_STRING)} 字符")
        if config.ALIPAY_PUBLIC_KEY_STRING:
            print(f"   公钥长度: {len(config.ALIPAY_PUBLIC_KEY_STRING)} 字符")
            
        print("   ✓ 支付宝配置初始化成功")
    except Exception as e:
        print(f"   ✗ 支付宝配置初始化失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    debug_alipay_config()