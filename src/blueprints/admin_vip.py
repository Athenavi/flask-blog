from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, render_template
from sqlalchemy import desc, and_

from src.models import VIPPlan, db, VIPSubscription, VIPFeature

# 创建蓝图
admin_vip_bp = Blueprint('admin_vip', __name__, url_prefix='/admin/vip')


# 辅助函数：检查用户权限
def is_admin():
    return True


@admin_vip_bp.route('/index', methods=['GET'])
def admin_vip_index():
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403
    return render_template('dashboard/vip.html')


# VIP套餐管理路由
@admin_vip_bp.route('/plans', methods=['GET'])
def get_vip_plans():
    """获取所有VIP套餐（分页）"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    pagination = VIPPlan.query.paginate(page=page, per_page=per_page, error_out=False)
    plans = pagination.items

    return jsonify({
        'plans': [{
            'id': plan.id,
            'name': plan.name,
            'description': plan.description,
            'price': float(plan.price) if plan.price else None,
            'duration_days': plan.duration_days,
            'level': plan.level,
            'features': plan.features,
            'is_active': plan.is_active,
            'created_at': plan.created_at.isoformat() if plan.created_at else None,
            'updated_at': plan.updated_at.isoformat() if plan.updated_at else None
        } for plan in plans],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@admin_vip_bp.route('/plans/<int:plan_id>', methods=['GET'])
def get_vip_plan(plan_id):
    """获取指定VIP套餐"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    plan = VIPPlan.query.get_or_404(plan_id)
    return jsonify({
        'id': plan.id,
        'name': plan.name,
        'description': plan.description,
        'price': float(plan.price) if plan.price else None,
        'duration_days': plan.duration_days,
        'level': plan.level,
        'features': plan.features,
        'is_active': plan.is_active,
        'created_at': plan.created_at.isoformat() if plan.created_at else None,
        'updated_at': plan.updated_at.isoformat() if plan.updated_at else None
    })


@admin_vip_bp.route('/plans', methods=['POST'])
def create_vip_plan():
    """创建VIP套餐"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    data = request.get_json()

    # 验证必需字段
    required_fields = ['name', 'price', 'duration_days']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({'error': f'缺少必需字段: {field}'}), 400

    try:
        plan = VIPPlan(
            name=data['name'],
            description=data.get('description'),
            price=data['price'],
            duration_days=data['duration_days'],
            level=data.get('level', 1),
            features=data.get('features'),
            is_active=data.get('is_active', True)
        )

        db.session.add(plan)
        db.session.commit()

        return jsonify({
            'message': 'VIP套餐创建成功',
            'plan': {
                'id': plan.id,
                'name': plan.name,
                'description': plan.description,
                'price': float(plan.price) if plan.price else None,
                'duration_days': plan.duration_days,
                'level': plan.level,
                'features': plan.features,
                'is_active': plan.is_active
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'创建失败: {str(e)}'}), 500


@admin_vip_bp.route('/plans/<int:plan_id>', methods=['PUT'])
def update_vip_plan(plan_id):
    """更新VIP套餐"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    plan = VIPPlan.query.get_or_404(plan_id)
    data = request.get_json()

    try:
        if 'name' in data:
            plan.name = data['name']
        if 'description' in data:
            plan.description = data['description']
        if 'price' in data:
            plan.price = data['price']
        if 'duration_days' in data:
            plan.duration_days = data['duration_days']
        if 'level' in data:
            plan.level = data['level']
        if 'features' in data:
            plan.features = data['features']
        if 'is_active' in data:
            plan.is_active = data['is_active']

        plan.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        return jsonify({
            'message': 'VIP套餐更新成功',
            'plan': {
                'id': plan.id,
                'name': plan.name,
                'description': plan.description,
                'price': float(plan.price) if plan.price else None,
                'duration_days': plan.duration_days,
                'level': plan.level,
                'features': plan.features,
                'is_active': plan.is_active,
                'updated_at': plan.updated_at.isoformat()
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'更新失败: {str(e)}'}), 500


@admin_vip_bp.route('/plans/<int:plan_id>', methods=['DELETE'])
def delete_vip_plan(plan_id):
    """删除VIP套餐"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    plan = VIPPlan.query.get_or_404(plan_id)

    # 检查是否有活跃的订阅
    active_subscriptions = VIPSubscription.query.filter_by(
        plan_id=plan_id,
        status='active'
    ).count()

    if active_subscriptions > 0:
        return jsonify({'error': '无法删除，该套餐仍有活跃订阅'}), 400

    try:
        db.session.delete(plan)
        db.session.commit()
        return jsonify({'message': 'VIP套餐删除成功'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'删除失败: {str(e)}'}), 500


# VIP订阅管理路由
@admin_vip_bp.route('/subscriptions', methods=['GET'])
def get_vip_subscriptions():
    """获取VIP订阅列表"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    # 查询参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    user_id = request.args.get('user_id', type=int)
    status = request.args.get('status')

    query = VIPSubscription.query

    if user_id:
        query = query.filter_by(user_id=user_id)
    if status:
        query = query.filter_by(status=status)

    pagination = query.order_by(desc(VIPSubscription.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )

    subscriptions = pagination.items

    return jsonify({
        'subscriptions': [{
            'id': sub.id,
            'user_id': sub.user_id,
            'plan_id': sub.plan_id,
            'plan_name': sub.plan.name if sub.plan else None,
            'starts_at': sub.starts_at.isoformat() if sub.starts_at else None,
            'expires_at': sub.expires_at.isoformat() if sub.expires_at else None,
            'status': sub.status,
            'payment_amount': float(sub.payment_amount) if sub.payment_amount else None,
            'transaction_id': sub.transaction_id,
            'created_at': sub.created_at.isoformat() if sub.created_at else None
        } for sub in subscriptions],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@admin_vip_bp.route('/subscriptions/<int:subscription_id>', methods=['GET'])
def get_vip_subscription(subscription_id):
    """获取指定订阅详情"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    subscription = VIPSubscription.query.get_or_404(subscription_id)

    return jsonify({
        'id': subscription.id,
        'user_id': subscription.user_id,
        'plan_id': subscription.plan_id,
        'plan_name': subscription.plan.name if subscription.plan else None,
        'starts_at': subscription.starts_at.isoformat() if subscription.starts_at else None,
        'expires_at': subscription.expires_at.isoformat() if subscription.expires_at else None,
        'status': subscription.status,
        'payment_amount': float(subscription.payment_amount) if subscription.payment_amount else None,
        'transaction_id': subscription.transaction_id,
        'created_at': subscription.created_at.isoformat() if subscription.created_at else None
    })


@admin_vip_bp.route('/subscriptions/<int:subscription_id>', methods=['PUT'])
def update_vip_subscription(subscription_id):
    """更新VIP订阅"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    subscription = VIPSubscription.query.get_or_404(subscription_id)
    data = request.get_json()

    try:
        if 'status' in data:
            subscription.status = data['status']
        if 'expires_at' in data:
            subscription.expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
        if 'payment_amount' in data:
            subscription.payment_amount = data['payment_amount']
        if 'transaction_id' in data:
            subscription.transaction_id = data['transaction_id']

        db.session.commit()

        return jsonify({
            'message': '订阅更新成功',
            'subscription': {
                'id': subscription.id,
                'status': subscription.status,
                'expires_at': subscription.expires_at.isoformat() if subscription.expires_at else None,
                'payment_amount': float(subscription.payment_amount) if subscription.payment_amount else None,
                'transaction_id': subscription.transaction_id
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'更新失败: {str(e)}'}), 500


# VIP功能管理路由
@admin_vip_bp.route('/features', methods=['GET'])
def get_vip_features():
    """获取所有VIP功能（分页）"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    pagination = VIPFeature.query.paginate(page=page, per_page=per_page, error_out=False)
    features = pagination.items

    return jsonify({
        'features': [{
            'id': feature.id,
            'code': feature.code,
            'name': feature.name,
            'description': feature.description,
            'required_level': feature.required_level,
            'is_active': feature.is_active,
            'created_at': feature.created_at.isoformat() if feature.created_at else None
        } for feature in features],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@admin_vip_bp.route('/features', methods=['POST'])
def create_vip_feature():
    """创建VIP功能"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    data = request.get_json()

    # 验证必需字段
    required_fields = ['code', 'name']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({'error': f'缺少必需字段: {field}'}), 400

    # 检查功能代码是否已存在
    existing_feature = VIPFeature.query.filter_by(code=data['code']).first()
    if existing_feature:
        return jsonify({'error': '功能代码已存在'}), 400

    try:
        feature = VIPFeature(
            code=data['code'],
            name=data['name'],
            description=data.get('description'),
            required_level=data.get('required_level', 1),
            is_active=data.get('is_active', True)
        )

        db.session.add(feature)
        db.session.commit()

        return jsonify({
            'message': 'VIP功能创建成功',
            'feature': {
                'id': feature.id,
                'code': feature.code,
                'name': feature.name,
                'description': feature.description,
                'required_level': feature.required_level,
                'is_active': feature.is_active
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'创建失败: {str(e)}'}), 500


@admin_vip_bp.route('/features/<int:feature_id>', methods=['PUT'])
def update_vip_feature(feature_id):
    """更新VIP功能"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    feature = VIPFeature.query.get_or_404(feature_id)
    data = request.get_json()

    try:
        if 'code' in data:
            # 检查功能代码是否与其他功能冲突
            existing = VIPFeature.query.filter(
                and_(VIPFeature.code == data['code'], VIPFeature.id != feature_id)
            ).first()
            if existing:
                return jsonify({'error': '功能代码已存在'}), 400
            feature.code = data['code']

        if 'name' in data:
            feature.name = data['name']
        if 'description' in data:
            feature.description = data['description']
        if 'required_level' in data:
            feature.required_level = data['required_level']
        if 'is_active' in data:
            feature.is_active = data['is_active']

        db.session.commit()

        return jsonify({
            'message': 'VIP功能更新成功',
            'feature': {
                'id': feature.id,
                'code': feature.code,
                'name': feature.name,
                'description': feature.description,
                'required_level': feature.required_level,
                'is_active': feature.is_active
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'更新失败: {str(e)}'}), 500


@admin_vip_bp.route('/features/<int:feature_id>', methods=['DELETE'])
def delete_vip_feature(feature_id):
    """删除VIP功能"""
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403

    feature = VIPFeature.query.get_or_404(feature_id)

    try:
        db.session.delete(feature)
        db.session.commit()
        return jsonify({'message': 'VIP功能删除成功'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'删除失败: {str(e)}'}), 500
