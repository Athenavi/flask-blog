# services/pay/Ali.py
import logging
from datetime import datetime, timedelta

from alipay import AliPay  # python-alipay-sdk==3.3.0

from src.models import VIPSubscription, db
from src.setting import AliPayConfig


class AlipayService:
    def __init__(self, app=None):
        self.alipay = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """初始化支付宝支付实例:cite[7]:cite[8]"""
        try:
            logging.info("开始初始化支付宝支付实例")
            
            # 从AliPayConfig获取配置
            alipay_config = AliPayConfig()
            
            appid = alipay_config.ALIPAY_APPID
            app_notify_url = alipay_config.ALIPAY_NOTIFY_URL
            app_private_key_string = alipay_config.ALIPAY_PRIVATE_KEY_STRING
            alipay_public_key_string = alipay_config.ALIPAY_PUBLIC_KEY_STRING
            debug = alipay_config.ALIPAY_DEBUG
            
            logging.info(f"ALIPAY_APPID: {appid}")
            logging.info(f"ALIPAY_DEBUG: {debug}")
            logging.info(f"ALIPAY_NOTIFY_URL: {app_notify_url}")
            
            # 检查密钥是否存在
            logging.info(f"私钥存在: {bool(app_private_key_string)}")
            logging.info(f"公钥存在: {bool(alipay_public_key_string)}")
            
            if not appid:
                raise ValueError("支付宝APPID未配置")
                
            if not app_private_key_string:
                raise ValueError("支付宝应用私钥未配置")
                
            if not alipay_public_key_string:
                raise ValueError("支付宝公钥未配置")
            
            # 清理私钥和公钥内容，确保正确的格式
            if app_private_key_string:
                app_private_key_string = app_private_key_string.strip()
            if alipay_public_key_string:
                alipay_public_key_string = alipay_public_key_string.strip()
            
            self.alipay = AliPay(
                appid=appid,
                app_notify_url=app_notify_url,
                app_private_key_string=app_private_key_string,
                alipay_public_key_string=alipay_public_key_string,
                sign_type="RSA2",
                debug=debug,
                verbose=True  # 增加调试信息
            )
            logging.info("支付宝支付实例初始化成功")
            logging.info(f"支付宝网关地址: {self.alipay._gateway}")
            app.logger.info("支付宝支付实例初始化成功")
            app.logger.info(f"支付宝网关地址: {self.alipay._gateway}")
        except Exception as e:
            logging.error(f"初始化支付宝支付失败: {str(e)}", exc_info=True)
            if hasattr(app, 'logger'):
                app.logger.error(f"初始化支付宝支付失败: {str(e)}", exc_info=True)
            raise

    def create_payment(self, vip_subscription, return_url=None):
        """创建支付宝支付订单:cite[7]:cite[8]"""
        try:
            logging.info("开始创建支付宝支付订单")
            out_trade_no = f"VIP{vip_subscription.id}{int(datetime.now().timestamp())}"
            subject = f"购买VIP套餐: {vip_subscription.plan.name}"
            total_amount = float(vip_subscription.payment_amount)
            
            logging.info(f"订单信息: out_trade_no={out_trade_no}, subject={subject}, total_amount={total_amount}")

            # 根据不同支付方式调用不同API
            logging.info("调用支付宝统一下单API")
            # 从配置中获取return_url
            from src.setting import AliPayConfig
            alipay_config = AliPayConfig()
            
            order_string = self.alipay.api_alipay_trade_page_pay(
                out_trade_no=out_trade_no,
                total_amount=total_amount,
                subject=subject,
                return_url=return_url or alipay_config.ALIPAY_RETURN_URL,
                notify_url=self.alipay._app_notify_url
            )
            logging.info("支付宝统一下单API调用成功")

            # 生成支付链接
            pay_url = f"{self.alipay._gateway}?{order_string}"
            logging.info(f"支付链接生成成功: {pay_url}")

            return {
                'out_trade_no': out_trade_no,
                'pay_url': pay_url,
                'order_string': order_string  # 用于APP支付
            }
        except Exception as e:
            logging.error(f"创建支付宝支付订单失败: {str(e)}", exc_info=True)
            # 更详细的错误信息
            if "RSA PRIVATE KEY" in str(e):
                raise Exception("支付宝私钥格式不正确，请检查密钥文件格式")
            elif "CERTIFICATE" in str(e) or "PUBLIC KEY" in str(e):
                raise Exception("支付宝公钥格式不正确，请检查密钥文件格式")
            elif "appid" in str(e).lower():
                raise Exception("支付宝APPID配置错误，请检查配置")
            else:
                raise Exception(f"创建支付宝支付订单失败: {str(e)}")

    def handle_notify(self, data):
        """处理支付宝异步通知:cite[2]:cite[7]"""
        try:
            logging.info(f"收到支付宝异步通知: {data}")
            # 验证签名
            signature = data.pop("sign", None)
            if not signature:
                logging.error("支付宝通知缺少签名")
                return False

            success = self.alipay.verify(data, signature)
            logging.info(f"支付宝签名验证结果: {success}")
            
            if success and data.get("trade_status") in ["TRADE_SUCCESS", "TRADE_FINISHED"]:
                return self._update_payment_status(data)
            return False
        except Exception as e:
            logging.error(f"处理支付宝支付通知异常: {str(e)}", exc_info=True)
            return False

    def _update_payment_status(self, notify_data):
        """更新支付状态"""
        try:
            logging.info(f"开始更新支付状态: {notify_data}")
            out_trade_no = notify_data['out_trade_no']
            trade_no = notify_data['trade_no']  # 支付宝交易号

            subscription = VIPSubscription.query.filter_by(transaction_id=out_trade_no).first()
            if subscription and subscription.status == 'active':
                logging.info("订单已处理过，无需重复处理")
                return True  # 已处理过

            subscription.transaction_id = trade_no
            subscription.status = 'active'
            subscription.starts_at = datetime.now()
            subscription.expires_at = datetime.now() + timedelta(days=subscription.plan.duration_days)

            db.session.commit()
            logging.info("支付状态更新成功")
            return True
        except Exception as e:
            logging.error(f"更新支付状态失败: {str(e)}", exc_info=True)
            db.session.rollback()
            return False