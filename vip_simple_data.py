from datetime import datetime, timezone
from src.models import VIPPlan, VIPFeature, db


def create_vip_sample_data():
    """创建VIP套餐和特权的示例数据"""

    # 清空现有数据（可选）
    VIPPlan.query.delete()
    VIPFeature.query.delete()

    # 创建VIP套餐
    plans = [
        VIPPlan(
            id=1,
            name="基础版",
            description="适合初尝VIP体验的用户",
            price=9.90,
            duration_days=30,
            level=1,
            features='{"ad_free": true, "premium_content": true}',
            is_active=True
        ),
        VIPPlan(
            id=2,
            name="进阶版",
            description="最受欢迎的选择，性价比最高",
            price=19.90,
            duration_days=30,
            level=2,
            features='{"ad_free": true, "premium_content": true, "early_access": true, "custom_profile": true}',
            is_active=True
        ),
        VIPPlan(
            id=3,
            name="尊享版",
            description="极致体验，尊享所有特权",
            price=29.90,
            duration_days=30,
            level=3,
            features='{"ad_free": true, "premium_content": true, "early_access": true, "custom_profile": true, "priority_support": true, "exclusive_events": true}',
            is_active=True
        ),
        VIPPlan(
            id=4,
            name="年度基础版",
            description="年度订阅，更优惠",
            price=99.00,
            duration_days=365,
            level=1,
            features='{"ad_free": true, "premium_content": true}',
            is_active=True
        ),
        VIPPlan(
            id=5,
            name="年度进阶版",
            description="年度订阅，节省更多",
            price=199.00,
            duration_days=365,
            level=2,
            features='{"ad_free": true, "premium_content": true, "early_access": true, "custom_profile": true}',
            is_active=True
        ),
        VIPPlan(
            id=6,
            name="年度尊享版",
            description="年度订阅，享受尊贵特权",
            price=299.00,
            duration_days=365,
            level=3,
            features='{"ad_free": true, "premium_content": true, "early_access": true, "custom_profile": true, "priority_support": true, "exclusive_events": true}',
            is_active=False
        )
    ]

    # 创建VIP特权功能
    features = [
        VIPFeature(
            id=1,
            code="ad_free",
            name="去广告体验",
            description="享受无广告的纯净阅读环境",
            required_level=1
        ),
        VIPFeature(
            id=2,
            code="premium_content",
            name="专属内容访问",
            description="解锁VIP专属文章、教程和分析报告",
            required_level=1
        ),
        VIPFeature(
            id=3,
            code="early_access",
            name="提前访问权限",
            description="优先体验新功能和内容",
            required_level=2
        ),
        VIPFeature(
            id=4,
            code="custom_profile",
            name="个性化资料",
            description="自定义个人主页和专属标识",
            required_level=2
        ),
        VIPFeature(
            id=5,
            code="priority_support",
            name="优先技术支持",
            description="享受快速响应的问题解答服务",
            required_level=3
        ),
        VIPFeature(
            id=6,
            code="exclusive_events",
            name="专属活动参与",
            description="参加VIP专属的线上/线下活动",
            required_level=3
        ),
        VIPFeature(
            id=7,
            code="download_content",
            name="内容下载权限",
            description="下载文章和资料供离线阅读",
            required_level=2
        ),
        VIPFeature(
            id=8,
            code="advanced_analytics",
            name="高级数据分析",
            description="查看详细的内容阅读数据分析",
            required_level=3
        )
    ]

    # 添加到数据库
    for plan in plans:
        db.session.add(plan)

    for feature in features:
        db.session.add(feature)

    try:
        db.session.commit()
        print("VIP示例数据创建成功！")
        print(f"创建了 {len(plans)} 个VIP套餐")
        print(f"创建了 {len(features)} 个VIP特权")

        # 打印创建的数据概览
        print("\nVIP套餐列表:")
        for plan in VIPPlan.query.all():
            print(f"- {plan.name} (等级{plan.level}): ¥{plan.price} - {plan.duration_days}天")

        print("\nVIP特权列表:")
        for feature in VIPFeature.query.order_by(VIPFeature.required_level).all():
            print(f"- {feature.name} (VIP{feature.required_level}): {feature.description}")

    except Exception as e:
        db.session.rollback()
        print(f"创建示例数据时出错: {e}")


def create_sample_articles():
    """创建一些VIP专属文章的示例数据"""
    from src.models import Article, User

    # 确保有测试用户
    test_user = User.query.first()
    if not test_user:
        print("请先创建用户数据")
        return

    # 创建VIP专属文章
    vip_articles = [
        {
            'title': '深度分析：人工智能在内容创作中的应用',
            'slug': 'ai-content-creation-deep-analysis',
            'excerpt': '本文深入探讨AI如何改变内容创作行业，包含独家数据和案例分析',
            'is_vip_only': True,
            'required_vip_level': 2,
            'tags': 'AI,内容创作,技术分析'
        },
        {
            'title': 'VIP专属：2024年技术趋势预测报告',
            'slug': '2024-tech-trends-vip-report',
            'excerpt': '基于内部数据的独家趋势分析，帮助您把握技术发展方向',
            'is_vip_only': True,
            'required_vip_level': 1,
            'tags': '技术趋势,预测,报告'
        },
        {
            'title': '高级教程：构建可扩展的微服务架构',
            'slug': 'microservices-architecture-advanced',
            'excerpt': '详细讲解微服务架构的最佳实践和高级技巧',
            'is_vip_only': True,
            'required_vip_level': 3,
            'tags': '微服务,架构,教程'
        },
        {
            'title': '独家访谈：行业领袖的成功经验分享',
            'slug': 'industry-leader-exclusive-interview',
            'excerpt': '与知名企业CTO的深度对话，揭示成功背后的秘密',
            'is_vip_only': True,
            'required_vip_level': 2,
            'tags': '访谈,成功经验,领导力'
        }
    ]

    for article_data in vip_articles:
        article = Article(
            title=article_data['title'],
            slug=article_data['slug'],
            user_id=test_user.id,
            excerpt=article_data['excerpt'],
            is_vip_only=article_data['is_vip_only'],
            required_vip_level=article_data['required_vip_level'],
            tags=article_data['tags'],
            status='Published',
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.session.add(article)

    try:
        db.session.commit()
        print(f"创建了 {len(vip_articles)} 篇VIP专属文章")
    except Exception as e:
        db.session.rollback()
        print(f"创建文章时出错: {e}")


if __name__ == "__main__":
    from src.app import create_app

    # 创建应用实例
    app = create_app()

    with app.app_context():
        create_vip_sample_data()
        create_sample_articles()
