create table vip_features
(
    id             serial
        primary key,
    code           varchar(50)  not null
        unique,
    name           varchar(100) not null,
    description    text,
    required_level integer,
    is_active      boolean,
    created_at     timestamp
);

INSERT INTO vip_features (id, code, name, description, required_level, is_active, created_at)
VALUES (2, 'premium_content', '专属内容访问', '解锁VIP专属文章、教程和分析报告', 1, true, '2025-09-27 16:15:43.037687');
INSERT INTO vip_features (id, code, name, description, required_level, is_active, created_at)
VALUES (3, 'early_access', '提前访问权限', '优先体验新功能和内容', 2, true, '2025-09-27 16:15:43.037688');
INSERT INTO vip_features (id, code, name, description, required_level, is_active, created_at)
VALUES (4, 'custom_profile', '个性化资料', '自定义个人主页和专属标识', 2, true, '2025-09-27 16:15:43.037689');
INSERT INTO vip_features (id, code, name, description, required_level, is_active, created_at)
VALUES (5, 'priority_support', '优先技术支持', '享受快速响应的问题解答服务', 3, true, '2025-09-27 16:15:43.037690');
INSERT INTO vip_features (id, code, name, description, required_level, is_active, created_at)
VALUES (6, 'exclusive_events', '专属活动参与', '参加VIP专属的线上/线下活动', 3, true, '2025-09-27 16:15:43.037690');
INSERT INTO vip_features (id, code, name, description, required_level, is_active, created_at)
VALUES (7, 'download_content', '内容下载权限', '下载文章和资料供离线阅读', 2, true, '2025-09-27 16:15:43.037691');
INSERT INTO vip_features (id, code, name, description, required_level, is_active, created_at)
VALUES (8, 'advanced_analytics', '高级数据分析', '查看详细的内容阅读数据分析', 3, true, '2025-09-27 16:15:43.037692');
INSERT INTO vip_features (id, code, name, description, required_level, is_active, created_at)
VALUES (9, 'additional_cloud_storage', '额外云空间', '提供基础媒体空间的额外50GB空间', 3, true,
        '2025-09-27 19:03:27.000000');
INSERT INTO vip_features (id, code, name, description, required_level, is_active, created_at)
VALUES (1, 'ad_free', '去广告体验', '无广告的纯净阅读环境', 1, true, '2025-09-27 16:15:43.037682');
