from datetime import datetime, timezone
from flask import Blueprint, render_template, jsonify, flash, redirect, url_for
from sqlalchemy import and_, or_

from src.models import VIPPlan, VIPSubscription, VIPFeature, User, db, Article
from src.user.authz.decorators import jwt_required

vip_bp = Blueprint('vip', __name__, template_folder='templates', url_prefix='/vip')


@vip_bp.route('/')
@jwt_required
def index(user_id):
    """VIP会员中心首页"""
    try:
        active_subscription = VIPSubscription.query.filter(
            VIPSubscription.user_id == user_id,
            VIPSubscription.status == 'active'
        ).first()
        plans = VIPPlan.query.filter_by(is_active=True).order_by(VIPPlan.level).all()
        features = VIPFeature.query.filter_by(is_active=True).order_by(VIPFeature.required_level).all()
        current_user = User.query.filter_by(id=user_id).first()
        return render_template('vip/index.html',
                               active_subscription=active_subscription,
                               current_user=current_user,
                               plans=plans,
                               features=features)

    except Exception as ex:
        # 记录错误日志（实际项目中应该使用logging）
        print(f"Error in VIP index: {str(ex)}")


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
            VIPSubscription.status == 'active',
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
        status='active',
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
    # 当前有效订阅
    utc_now = datetime.now(timezone('UTC'))
    active_subscription = VIPSubscription.query.filter(
        and_(
            VIPSubscription.user_id == user_id,
            VIPSubscription.status == 'active',
            VIPSubscription.expires_at.astimezone(timezone('UTC')) > utc_now
        )
    ).first()

    # 历史订阅记录
    subscription_history = VIPSubscription.query.filter(
        VIPSubscription.user_id == user_id
    ).order_by(VIPSubscription.created_at.desc()).all()
    current_user = User.query.filter_by(id=user_id).first()

    return render_template('vip/my_subscription.html',
                           active_subscription=active_subscription,
                           current_user=current_user,
                           subscription_history=subscription_history)


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
    return render_template('vip/features.html', current_user=current_user, features_by_level=features_by_level)


@vip_bp.route('/premium-content')
@jwt_required
def premium_content(user_id):
    """VIP专属内容页面"""
    user = User.query.filter_by(id=user_id).first()

    if not user.is_vip():
        flash('此内容仅对VIP会员开放', 'warning')
        return redirect(url_for('vip.plans'))

    # 获取VIP专属文章
    premium_articles = Article.query.filter(
        or_(
            Article.is_vip_only == True,
            Article.required_vip_level > 0
        ),
        Article.status == 'Published',
        Article.hidden == False
    ).filter(
        Article.required_vip_level <= user.vip_level
    ).order_by(Article.created_at.desc()).all()

    return render_template('vip/premium_content.html', current_user=user, articles=premium_articles)


@vip_bp.route('/api/check-access/<int:article_id>')
@jwt_required
def check_article_access(article_id):
    """API：检查用户对文章的访问权限"""
    article = Article.query.get_or_404(article_id)
    user = User.query.filter_by(id=article.user_id).first()

    if article.is_vip_only and not user.is_vip():
        return jsonify({
            'has_access': False,
            'message': '此文章仅对VIP会员开放',
            'required_level': article.required_vip_level
        })

    if user.is_vip() and user.vip_level >= article.required_vip_level:
        return jsonify({'has_access': True})

    return jsonify({'has_access': True})  # 默认允许访问
