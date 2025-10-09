# src/blueprints/payment.py
from datetime import datetime

from flask import Blueprint, request, jsonify, current_app

from services.pay.Ali import AlipayService
from services.pay.WeChat import WeChatPayService
from src.models import VIPPlan, VIPSubscription, db

payment_bp = Blueprint('payment', __name__, url_prefix='/api/payment')


@payment_bp.route('/create', methods=['POST'])
def create_payment():
    """创建支付订单"""
    data = request.get_json()
    user_id = data.get('user_id')
    plan_id = data.get('plan_id')
    payment_method = data.get('payment_method')  # 'wechat' 或 'alipay'

    # 获取VIP套餐
    vip_plan = VIPPlan.query.filter_by(id=plan_id, is_active=True).first_or_404()

    # 创建订阅记录(初始状态为待支付)
    subscription = VIPSubscription(
        user_id=user_id,
        plan_id=plan_id,
        starts_at=datetime.now(),
        expires_at=datetime.now(),  # 支付成功后更新
        status='pending_payment',  # 新增待支付状态
        payment_amount=vip_plan.price
    )
    db.session.add(subscription)
    db.session.commit()

    # 根据支付方式生成支付参数
    if payment_method == 'wechat':
        pay_service = WeChatPayService(current_app)
        # 获取用户openid(需通过前端授权)
        openid = data.get('openid')
        payment_data = pay_service.create_payment(subscription, openid)
    elif payment_method == 'alipay':
        pay_service = AlipayService(current_app)
        payment_data = pay_service.create_payment(subscription)
    else:
        return jsonify({'error': '不支持的支付方式'}), 400

    # 保存商户订单号到订阅记录
    subscription.transaction_id = payment_data['out_trade_no']
    db.session.commit()

    return jsonify({
        'payment_method': payment_method,
        'payment_data': payment_data,
        'subscription_id': subscription.id
    })


@payment_bp.route('/wechat/notify', methods=['POST'])
def wechat_notify():
    """微信支付异步通知回调:cite[9]"""
    try:
        data = request.get_data()
        pay_service = WeChatPayService(current_app)
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
        pay_service = AlipayService(current_app)
        success = pay_service.handle_notify(data)

        if success:
            return 'success'
        else:
            return 'fail'
    except Exception as e:
        current_app.logger.error(f"支付宝支付回调处理异常: {str(e)}")
        return 'fail'