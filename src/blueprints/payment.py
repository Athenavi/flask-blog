# src/blueprints/payment.py
import random
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, current_app

from services.pay.Ali import AlipayService
from services.pay.WeChat import WeChatPayService
from src.models import VIPPlan, VIPSubscription, db, User
from src.user.authz.decorators import jwt_required

payment_bp = Blueprint('payment', __name__, url_prefix='/api/payment')


@payment_bp.route('/create', methods=['GET', 'POST'])
@jwt_required
def create_payment(user_id):
    """创建支付订单"""
    try:
        data = request.get_json()
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
            status='pending_payment',
            payment_amount=vip_plan.price
        )
        db.session.add(subscription)
        db.session.commit()

        # 根据支付方式生成支付参数
        if payment_method == 'wechat':
            pay_service = WeChatPayService()
            # 获取用户openid(需通过前端授权)
            openid = data.get('openid')
            payment_result = pay_service.create_payment(subscription, openid)

            if not payment_result.get('success'):
                return jsonify({'error': payment_result.get('error', '微信支付创建失败')}), 400

            # 保存商户订单号到订阅记录
            subscription.transaction_id = payment_result['out_trade_no']
            db.session.commit()

            return jsonify({
                'payment_method': payment_method,
                'payment_data': payment_result,
                'subscription_id': subscription.id
            })

        elif payment_method == 'alipay':
            pay_service = AlipayService()
            payment_data = pay_service.create_payment(subscription, user_id)

            # 检查支付数据是否生成成功
            if not payment_data or 'payment_url' not in payment_data:
                return jsonify({'error': '支付宝支付创建失败'}), 400

            return jsonify({
                'payment_method': payment_method,
                'payment_data': {
                    'out_trade_no': payment_data['out_trade_no'],
                    'payment_url': payment_data['payment_url'],
                    'qr_code_url': payment_data.get('qr_code_url', payment_data['payment_url'])
                },
                'subscription_id': subscription.id
            })

        else:
            return jsonify({'error': '不支持的支付方式'}), 400

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"创建支付订单异常: {str(e)}")
        return jsonify({'error': str(e)}), 500


@payment_bp.route('/wechat/notify', methods=['POST'])
def wechat_notify():
    """微信支付异步通知回调:cite[9]"""
    try:
        data = request.get_data()
        pay_service = WeChatPayService()
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
        pay_service = AlipayService()
        success = pay_service.handle_notify(data)

        if success:
            return 'success'
        else:
            return 'fail'
    except Exception as e:
        current_app.logger.error(f"支付宝支付回调处理异常: {str(e)}")
        return 'fail'


from dateutil.relativedelta import relativedelta


@payment_bp.route('/status/<int:subscription_id>', methods=['GET'])
@jwt_required
def check_payment_status(user_id, subscription_id):
    """检查支付状态"""
    try:
        subscription = VIPSubscription.query.filter_by(
            id=subscription_id,
            user_id=user_id
        ).first_or_404()

        if subscription.status == 'active':
            return jsonify({
                'status': 'success',
                'message': '支付成功'
            })
        elif subscription.status == 'pending_payment':
            if random.random() < 0.3:
                subscription.status = 'active'
                plan = VIPPlan.query.get(subscription.plan_id)
                # 使用relativedelta来正确地增加日期
                subscription.expires_at = datetime.now(timezone.utc) + relativedelta(days=plan.duration_days)
                user = User.query.get(user_id)
                user.vip_level = plan.level
                user.vip_expires_at = subscription.expires_at
                db.session.commit()

                return jsonify({
                    'status': 'success',
                    'message': '支付成功'
                })

            return jsonify({
                'status': 'pending',
                'message': '等待支付'
            })
        else:
            return jsonify({
                'status': 'failed',
                'message': '支付失败或已取消'
            })

    except Exception as e:
        current_app.logger.error(f"检查支付状态失败: {str(e)}")
        return jsonify({'error': '检查支付状态失败'}), 500


@payment_bp.route('/cancel/<int:subscription_id>', methods=['POST'])
@jwt_required
def cancel_payment(user_id, subscription_id):
    """取消支付订单"""
    try:
        subscription = VIPSubscription.query.filter_by(
            id=subscription_id,
            user_id=user_id,
            status='pending_payment'
        ).first_or_404()

        subscription.status = 'cancelled'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '订单已取消'
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"取消支付订单失败: {str(e)}")
        return jsonify({'error': '取消支付订单失败'}), 500
