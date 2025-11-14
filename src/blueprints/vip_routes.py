from flask import Blueprint, render_template, jsonify, flash, redirect, url_for
from sqlalchemy import and_, or_

from src.auth import jwt_required
from src.extensions import cache
from src.models import VIPPlan, VIPSubscription, VIPFeature, User, db, Article

vip_bp = Blueprint('vip', __name__, template_folder='templates', url_prefix='/vip')
from datetime import datetime, timezone


@vip_bp.route('/')
@jwt_required
def index(user_id):
    """VIP会员中心首页"""
    try:
        _user = User.query.filter_by(id=user_id).first()
        if _user.vip_expires_at is None:
            active_status = False
        else:
            active_status = bool(_user.vip_level != 0 and _user.vip_expires_at > datetime.now())
        return render_template('vip/index.html',
                               current_user=_user,
                               activeStatus=active_status)

    except Exception as ex:
        print(f"Error in VIP index: {str(ex)}")
        return jsonify({'error': '服务器内部错误'}), 500


@vip_bp.route('/plans')
@jwt_required
def plans(user_id):
    """VIP套餐列表页面"""
    try:
        plans = VIPPlan.query.filter_by(is_active=True).order_by(VIPPlan.level).all()
        features = VIPFeature.query.filter_by(is_active=True).order_by(VIPFeature.required_level).all()
        current_user = User.query.filter_by(id=user_id).first()
        return render_template('vip/plans.html', plans=plans, features=features, current_user=current_user)
    except Exception as ex:
        return jsonify({'error': str(ex)})


@vip_bp.route('/plan/<int:plan_id>')
@jwt_required
def plan_detail(plan_id):
    """套餐详情页面"""
    try:
        plan = VIPPlan.query.get_or_404(plan_id)
        features = VIPFeature.query.filter(
            VIPFeature.required_level <= plan.level,
            VIPFeature.is_active == True
        ).all()

        return jsonify(features)
    except Exception as ex:
        return jsonify({'error': str(ex)})


@vip_bp.route('/subscribe/<int:plan_id>', methods=['POST'])
@jwt_required
def subscribe(user_id, plan_id):
    """订阅VIP套餐"""
    plan = VIPPlan.query.get_or_404(plan_id)

    # 检查用户是否已有有效订阅
    utc_now = datetime.now(timezone('UTC'))
    existing_subscription = VIPSubscription.query.filter(
        and_(
            VIPSubscription.user_id == user_id,
            VIPSubscription.status == 1,
            VIPSubscription.expires_at.astimezone(timezone('UTC')) > utc_now
        )
    ).first()

    if existing_subscription:
        flash('您已有有效的VIP订阅', 'warning')
        return redirect(url_for('vip.my_subscription'))

    # 创建新订阅
    starts_at = datetime.now(timezone('UTC'))
    expires_at = starts_at.replace(
        day=starts_at.day + plan.duration_days
    ) if plan.duration_days > 0 else None

    subscription = VIPSubscription(
        user_id=user_id,
        plan_id=plan.id,
        starts_at=starts_at,
        expires_at=expires_at,
        status=1,
        payment_amount=plan.price
    )

    # 更新用户VIP状态
    current_user = User.query.filter_by(id=user_id).first()
    current_user.vip_level = plan.level
    current_user.vip_expires_at = expires_at

    db.session.add(subscription)
    db.session.commit()

    flash('VIP订阅成功！', 'success')
    return redirect(url_for('vip.my_subscription'))


@vip_bp.route('/my-subscription')
@jwt_required
def my_subscription(user_id):
    """我的订阅页面"""
    try:
        # 获取当前用户
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': '用户不存在'}), 404

        # 获取最新的有效订阅记录
        latest_subscription = VIPSubscription.query.filter(
            VIPSubscription.user_id == user_id,
            VIPSubscription.status == 1
        ).order_by(VIPSubscription.id.desc()).first()

        # 初始化 active_subscription
        active_subscription = None

        if latest_subscription:
            # 设置时区并检查订阅状态
            latest_subscription.expires_at = latest_subscription.expires_at.replace(tzinfo=timezone.utc)
            current_time = datetime.now(timezone.utc)

            # 更新过期状态
            if latest_subscription.expires_at <= current_time:
                latest_subscription.status = -1
                db.session.commit()
            else:
                active_subscription = latest_subscription

        # 检查是否有无效的 latest_subscription 记录
        if not latest_subscription:
            latest_subscription = VIPSubscription.query.filter(
                VIPSubscription.user_id == user_id,
                VIPSubscription.status == -1
            ).order_by(VIPSubscription.id.desc()).first() or None

        # 设置用户VIP级别和过期时间
        if latest_subscription is not None:
            plan = VIPPlan.query.filter_by(id=latest_subscription.plan_id).first() or None
            if plan is not None:
                user.vip_level = plan.level
                user.vip_expires_at = latest_subscription.expires_at
            else:
                user.vip_level = 0  # 如果计划不存在，将用户的 VIP 级别设为 0
                user.vip_expires_at = None
        else:
            user.vip_level = 0  # 如果没有找到任何订阅记录，将用户的 VIP 级别设为 0
            user.vip_expires_at = None

        db.session.commit()

        # 获取订阅历史
        subscription_history = VIPSubscription.query.filter(
            VIPSubscription.user_id == user_id
        ).order_by(VIPSubscription.id.desc()).all()

        return render_template('vip/my_subscription.html',
                               active_subscription=active_subscription,
                               current_user=user,
                               subscription_history=subscription_history)

    except Exception as ex:
        return jsonify({'error': str(ex)}), 500


@cache.cached(timeout=60 * 60 * 24, key_prefix='vip_features')
@vip_bp.route('/features')
@jwt_required
def features(user_id):
    """VIP特权介绍页面"""
    features = VIPFeature.query.filter_by(is_active=True).order_by(VIPFeature.required_level).all()

    # 按等级分组
    features_by_level = {}
    for feature in features:
        if feature.required_level not in features_by_level:
            features_by_level[feature.required_level] = []
        features_by_level[feature.required_level].append(feature)

    current_user = User.query.filter_by(id=user_id).first()
    return render_template('vip/features.html', current_user=current_user, features_by_level=features_by_level,
                           features=features)


@vip_bp.route('/premium-content')
@jwt_required
def premium_content(user_id):
    """VIP专属内容页面"""
    try:
        user = User.query.filter_by(id=user_id).first()
        premium_articles = Article.query.filter(
            or_(
                Article.is_vip_only == True,  # 直接使用 True
                Article.required_vip_level != 0
            ),
            Article.status == 1,
            Article.hidden == False  # 直接使用 False
        ).filter(
            Article.required_vip_level <= user.vip_level
        ).order_by(Article.created_at.desc()).all() or []

        # 检查 user.vip_expires_at 是否为 None
        if user.vip_expires_at is not None:
            active_status = bool(user.vip_level != 0 and user.vip_expires_at > datetime.now())
        else:
            active_status = False

        return render_template('vip/premium_content.html', current_user=user, activeStatus=active_status,
                               articles=premium_articles)
    except Exception as ex:
        return jsonify({'error': str(ex)})


@vip_bp.route('/payment/<int:plan_id>', methods=['GET'])
@jwt_required
def payment_page(user_id, plan_id):
    """支付页面"""
    try:
        plan = VIPPlan.query.filter_by(id=plan_id, is_active=True).first_or_404()
        current_user = User.query.filter_by(id=user_id).first()
        # 检查用户是否已有有效订阅
        if current_user.vip_expires_at is not None:
            existing_subscription = bool(current_user.vip_level != 0 and current_user.vip_expires_at > datetime.now())
        else:
            existing_subscription = False

        if existing_subscription:
            flash('您已有有效的VIP订阅', 'warning')
            return redirect(url_for('vip.my_subscription'))
        return render_template('vip/payment.html', plan=plan, current_user=current_user)
    except Exception as ex:
        return jsonify({'error': str(ex)})
