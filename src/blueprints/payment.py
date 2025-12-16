# src/blueprints/payment.py
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, current_app

from services.pay.Ali import AlipayService
from services.pay.WeChat import WeChatPayService
from src.models import VIPPlan, VIPSubscription, db

payment_bp = Blueprint('payment', __name__, url_prefix='/api/payment')


@payment_bp.route('/create', methods=['POST'])
def create_payment():
    """创建支付订单"""
    try:
        current_app.logger.info("开始处理支付请求")

        # 检查Content-Type头部
        content_type = request.headers.get('Content-Type', '')
        current_app.logger.info(f"请求 Content-Type: {content_type}")

        if 'application/json' in content_type:
            data = request.get_json()
        else:
            # 尝试从表单数据获取
            data = request.get_json() or {}
            # 如果还获取不到，手动解析
            if not data:
                try:
                    import json
                    data = json.loads(request.get_data(as_text=True))
                except Exception:
                    pass

        current_app.logger.info(f"接收到的数据: {data}")

        if not data:
            current_app.logger.error("无效的请求数据")
            return jsonify({'error': '无效的请求数据'}), 400

        user_id = data.get('user_id')
        plan_id = data.get('plan_id')
        payment_method = data.get('payment_method')  # 'wechat' 或 'alipay'

        current_app.logger.info(f"user_id: {user_id}, plan_id: {plan_id}, payment_method: {payment_method}")

        if not all([user_id, plan_id, payment_method]):
            current_app.logger.error("缺少必要的参数")
            return jsonify({'error': '缺少必要的参数'}), 400

        # 获取VIP套餐
        current_app.logger.info("开始查询VIP套餐")
        vip_plan = VIPPlan.query.filter_by(id=plan_id, is_active=True).first()
        if not vip_plan:
            current_app.logger.error(f"指定的VIP套餐不存在或已停用: {plan_id}")
            return jsonify({'error': '指定的VIP套餐不存在或已停用'}), 404

        current_app.logger.info(f"找到VIP套餐: {vip_plan.name}")

        # 创建订阅记录(初始状态为待支付)
        current_app.logger.info("创建订阅记录")
        subscription = VIPSubscription(
            user_id=user_id,
            plan_id=plan_id,
            starts_at=datetime.now(),
            expires_at=datetime.now(),  # 支付成功后更新
            status=0,  # pending_payment状态
            payment_amount=vip_plan.price
        )
        db.session.add(subscription)
        db.session.flush()  # 获取ID但不提交事务
        current_app.logger.info(f"订阅记录创建成功，ID: {subscription.id}")

        # 根据支付方式生成支付参数
        current_app.logger.info(f"开始处理支付方式: {payment_method}")
        if payment_method == 'wechat':
            current_app.logger.info("初始化微信支付服务")
            pay_service = WeChatPayService(current_app)
            
            # 检查微信支付是否已正确配置
            if not pay_service.is_available():
                current_app.logger.error("微信支付服务未正确配置，请检查相关配置项")
                return jsonify({'error': '微信支付服务未正确配置，请联系管理员'}), 503
                
            # 获取用户openid(需通过前端授权)
            openid = data.get('openid')
            current_app.logger.info("调用微信支付创建订单")
            payment_data = pay_service.create_payment(subscription, openid)
        elif payment_method == 'alipay':
            current_app.logger.info("初始化支付宝支付服务")
            pay_service = AlipayService(current_app)
            current_app.logger.info("调用支付宝支付创建订单")
            payment_data = pay_service.create_payment(subscription)
        else:
            current_app.logger.error(f"不支持的支付方式: {payment_method}")
            return jsonify({'error': '不支持的支付方式'}), 400

        current_app.logger.info(f"支付数据生成成功: {payment_data}")

        # 保存商户订单号到订阅记录
        current_app.logger.info("保存商户订单号")
        subscription.transaction_id = payment_data['out_trade_no']
        db.session.commit()
        current_app.logger.info("数据库提交成功")

        response_data = {
            'payment_method': payment_method,
            'payment_data': payment_data,
            'subscription_id': subscription.id
        }
        current_app.logger.info(f"返回响应: {response_data}")

        return jsonify(response_data)
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"创建支付订单失败: {str(e)}", exc_info=True)
        # 提供更具体的错误信息
        error_message = str(e)
        if "appid" in error_message.lower():
            return jsonify({'error': '支付宝配置错误：APPID不正确'}), 500
        elif "private key" in error_message.lower():
            return jsonify({'error': '支付宝配置错误：私钥格式不正确'}), 500
        elif "public key" in error_message.lower():
            return jsonify({'error': '支付宝配置错误：公钥格式不正确'}), 500
        elif "sign" in error_message.lower() or "verify" in error_message.lower():
            return jsonify({'error': '支付宝配置错误：签名验证失败'}), 500
        else:
            return jsonify({'error': f'创建支付订单失败，请稍后重试：{error_message}'}), 500


@payment_bp.route('/wechat/notify', methods=['POST'])
def wechat_notify():
    """微信支付异步通知回调:cite[9]"""
    try:
        data = request.get_data()
        pay_service = WeChatPayService(current_app)
        
        # 检查微信支付是否已正确配置
        if not pay_service.is_available():
            current_app.logger.error("微信支付服务未正确配置，无法处理回调")
            return '<xml><return_code><![CDATA[FAIL]]></return_code><return_msg><![CDATA[服务未配置]]></return_msg></xml>', 503
            
        success = pay_service.handle_notify(data)

        if success:
            return '<xml><return_code><![CDATA[SUCCESS]]></return_code></xml>'
        else:
            return '<xml><return_code><![CDATA[FAIL]]></return_code></xml>'
    except Exception as e:
        current_app.logger.error(f"微信支付回调处理异常: {str(e)}")
        return '<xml><return_code><![CDATA[FAIL]]></return_code></xml>'


@payment_bp.route('/alipay/notify', methods=['POST'])
def alipay_notify():
    """支付宝支付异步通知回调:cite[7]"""
    try:
        data = request.form.to_dict()
        current_app.logger.info(f"收到支付宝回调数据: {data}")
        pay_service = AlipayService(current_app)
        success = pay_service.handle_notify(data)

        if success:
            current_app.logger.info("支付宝回调处理成功")
            return 'success'
        else:
            current_app.logger.error("支付宝回调处理失败")
            return 'fail'
    except Exception as e:
        current_app.logger.error(f"支付宝支付回调处理异常: {str(e)}", exc_info=True)
        return 'fail'


@payment_bp.route('/alipay/return', methods=['GET'])
def alipay_return():
    """支付宝支付同步回调:return_url"""
    try:
        current_app.logger.info("收到支付宝同步回调请求")
        # 获取所有查询参数
        data = request.args.to_dict()
        current_app.logger.info(f"支付宝同步回调参数: {data}")

        # 验证签名
        sign = data.pop("sign", None)
        sign_type = data.pop("sign_type", None)

        if not sign:
            current_app.logger.error("支付宝同步回调缺少签名")
            return jsonify({"error": "缺少签名"}), 400

        # 验证签名
        pay_service = AlipayService(current_app)
        success = pay_service.alipay.verify(data, sign)

        if success:
            current_app.logger.info("支付宝同步回调签名验证成功")

            # 获取订单号并查找对应的订阅记录
            out_trade_no = data.get('out_trade_no')
            if out_trade_no:
                subscription = VIPSubscription.query.filter_by(transaction_id=out_trade_no).first()
                if subscription:
                    # 更新用户VIP状态
                    from src.models import User
                    user = User.query.get(subscription.user_id)
                    if user:
                        user.vip_level = subscription.plan.level
                        user.vip_expires_at = datetime.now() + timedelta(days=subscription.plan.duration_days)
                        subscription.status = 1  # active状态
                        subscription.starts_at = datetime.now()
                        subscription.expires_at = user.vip_expires_at
                        db.session.commit()
                        current_app.logger.info(f"用户 {user.id} VIP权限已开通")

            # 返回成功信息
            return jsonify({
                "message": "支付成功",
                "data": data,
                "success": True
            })
        else:
            current_app.logger.error("支付宝同步回调签名验证失败")
            return jsonify({"error": "签名验证失败"}), 400

    except Exception as e:
        current_app.logger.error(f"支付宝同步回调处理异常: {str(e)}", exc_info=True)
        return jsonify({"error": "处理异常"}), 500