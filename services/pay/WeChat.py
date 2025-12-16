# services/pay/WeChat.py
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

from flask import json
from jd_wechatpay import WeChatPay, WeChatPayType  # 或使用 wechatpy

from src.models import db, VIPSubscription


class WeChatPayService:
    def __init__(self, app=None):
        self.wxpay = None
        self.is_configured = False
        if app:
            self.init_app(app)

    def init_app(self, app):
        """初始化微信支付实例:cite[1]"""
        # 检查必要的配置是否存在
        required_configs = ['WECHAT_MCHID', 'WECHAT_PRIVATE_KEY', 'WECHAT_CERT_SERIAL_NO', 
                          'WECHAT_APPID', 'WECHAT_API_V3_KEY', 'WECHAT_NOTIFY_URL', 'WECHAT_CERT_DIR']
        
        # 从环境变量或配置文件中获取配置
        wechat_config = {}
        missing_configs = []
        
        for config in required_configs:
            value = app.config.get(config) or os.getenv(config)
            if not value:
                missing_configs.append(config)
            else:
                wechat_config[config] = value
        
        if missing_configs:
            logging.warning(f"微信支付配置不完整，缺少配置项: {', '.join(missing_configs)}")
            self.is_configured = False
            return

        try:
            # 读取私钥文件
            private_key = wechat_config['WECHAT_PRIVATE_KEY']
            if private_key.endswith('.pem'):
                # 如果是文件路径，则读取文件内容
                private_key_path = Path(private_key)
                if private_key_path.exists():
                    try:
                        private_key = private_key_path.read_text(encoding='utf-8')
                    except UnicodeDecodeError:
                        # 尝试使用其他编码读取文件
                        try:
                            private_key = private_key_path.read_text(encoding='gbk')
                        except UnicodeDecodeError:
                            # 如果仍然失败，以二进制方式读取
                            private_key = private_key_path.read_bytes().decode('utf-8', errors='ignore')
                else:
                    logging.warning(f"微信支付私钥文件不存在: {private_key}")
                    self.is_configured = False
                    return
            
            self.wxpay = WeChatPay(
                WeChatPayType.NATIVE,  # 使用NATIVE支付类型
                mch_id=wechat_config['WECHAT_MCHID'],
                private_key=private_key,
                cert_serial_no=wechat_config['WECHAT_CERT_SERIAL_NO'],
                app_id=wechat_config['WECHAT_APPID'],
                api_v3_key=wechat_config['WECHAT_API_V3_KEY'],
                notify_url=wechat_config['WECHAT_NOTIFY_URL'],
                cert_dir=wechat_config['WECHAT_CERT_DIR'],
                logger=logging.getLogger('wechatpay'),
                partner_mode=False  # 直连模式，服务商模式设为True
            )
            self.is_configured = True
            logging.info("微信支付服务初始化成功")
        except Exception as e:
            logging.error(f"初始化微信支付失败: {str(e)}")
            self.is_configured = False

    def is_available(self):
        """检查微信支付服务是否可用"""
        return self.is_configured and self.wxpay is not None

    def create_payment(self, vip_subscription, user_openid=None):
        """创建微信支付预订单:cite[5]:cite[6]"""
        if not self.is_available():
            raise Exception("微信支付服务未正确配置，无法创建支付订单")

        out_trade_no = f"VIP{vip_subscription.id}{int(datetime.now().timestamp())}"  # 商户订单号
        description = f"购买VIP套餐: {vip_subscription.plan.name}"
        amount = int(float(vip_subscription.payment_amount) * 100)  # 金额(分)

        # 调用统一下单API
        code, message = self.wxpay.pay.pay(
            description=description,
            out_trade_no=out_trade_no,
            amount={'total': amount},
            payer={'openid': user_openid} if user_openid else None,  # JSAPI支付需传openid
            pay_type=WeChatPayType.NATIVE  # 使用NATIVE支付类型
        )

        if code == 200:
            # 返回前端所需的支付参数
            prepay_data = json.loads(message)
            return {
                'prepay_id': prepay_data.get('prepay_id'),
                'out_trade_no': out_trade_no,
                'payment_params': self._get_payment_params(prepay_data),  # 生成前端支付参数
                'qr_code_url': prepay_data.get('code_url')  # 二维码链接用于NATIVE支付
            }
        else:
            raise Exception(f"微信预支付失败: {message}")

    def _get_payment_params(self, prepay_data):
        """生成前端支付参数(APP/JSAPI):cite[6]"""
        if not self.is_available():
            raise Exception("微信支付服务未正确配置")

        timestamp = str(int(datetime.now().timestamp()))
        nonce_str = self.wxpay.generate_nonce_str()
        package = f"prepay_id={prepay_data['prepay_id']}"

        # 生成签名
        sign_data = {
            'appId': self.wxpay.app_id,
            'timeStamp': timestamp,
            'nonceStr': nonce_str,
            'package': package,
            'signType': 'RSA' if self.wxpay._sign_method == 'RSA' else 'HMAC-SHA256'
        }
        sign = self.wxpay.sign(sign_data)

        return {
            'appId': self.wxpay.app_id,
            'timeStamp': timestamp,
            'nonceStr': nonce_str,
            'package': package,
            'signType': sign_data['signType'],
            'paySign': sign,
            'out_trade_no': prepay_data.get('out_trade_no')
        }

    def handle_notify(self, data):
        """处理微信支付异步通知:cite[9]"""
        if not self.is_available():
            logging.error("微信支付服务未正确配置，无法处理支付通知")
            return False

        try:
            # 解析并验证通知数据
            result = self.wxpay.callback(data)
            if result and result.get('event_type') == 'TRANSACTION.SUCCESS':
                resource = result['resource']
                # 解密资源数据
                decrypt_data = self.wxpay.decrypt(
                    resource['ciphertext'],
                    resource['associated_data'],
                    resource['nonce']
                )
                notify_data = json.loads(decrypt_data)

                # 验证订单状态
                if notify_data['trade_state'] == 'SUCCESS':
                    return self._update_payment_status(notify_data)
            return False
        except Exception as e:
            logging.error(f"处理微信支付通知异常: {str(e)}")
            return False

    def _update_payment_status(self, notify_data):
        """更新支付状态"""
        out_trade_no = notify_data['out_trade_no']
        transaction_id = notify_data['transaction_id']

        # 根据out_trade_no找到对应订阅记录
        subscription = VIPSubscription.query.filter_by(transaction_id=out_trade_no).first()
        if subscription and subscription.status == 'active':
            return True  # 已处理过，防止重复通知

        # 更新订阅记录
        subscription.transaction_id = transaction_id
        subscription.status = 'active'
        subscription.starts_at = datetime.now()
        # 根据套餐时长设置过期时间
        subscription.expires_at = datetime.now() + timedelta(days=subscription.plan.duration_days)

        db.session.commit()
        return True