create table vip_plans
(
    id            serial
        primary key,
    name          varchar(100)   not null,
    description   text,
    price         numeric(10, 2) not null,
    original_price numeric(10, 2) not null,
    duration_days integer        not null,
    level         integer        not null,
    features      text,
    is_active     boolean,
    created_at    timestamp,
    updated_at    timestamp
);

INSERT INTO vip_plans (id, name, description, price, original_price, duration_days, level, features, is_active, created_at, updated_at)
VALUES (2, '进阶版', '最受欢迎的选择，性价比最高', 19.90, 29.90, 30, 2,
        '{"ad_free": true, "premium_content": true, "early_access": true, "custom_profile": true}', true,
        '2025-09-27 16:15:43.039755', '2025-09-27 16:15:43.039756');
INSERT INTO vip_plans (id, name, description, price, original_price, duration_days, level, features, is_active, created_at, updated_at)
VALUES (3, '尊享版', '极致体验，尊享所有特权', 29.90, 49.90, 30, 3,
        '{"ad_free": true, "premium_content": true, "early_access": true, "custom_profile": true, "priority_support": true, "exclusive_events": true}',
        true, '2025-09-27 16:15:43.039757', '2025-09-27 16:15:43.039757');
INSERT INTO vip_plans (id, name, description, price, original_price, duration_days, level, features, is_active, created_at, updated_at)
VALUES (1, '基础版', '适合初尝VIP体验的用户', 7.90, 9.90, 31, 1, '{"ad_free": true, "premium_content": true}', true,
        '2025-09-27 16:15:43.039751', '2025-10-09 15:08:39.137751');
INSERT INTO vip_plans (id, name, description, price, original_price, duration_days, level, features, is_active, created_at, updated_at)
VALUES (4, '年度基础版', '年度订阅，更优惠', 89.00, 199.00, 365, 1, '{"ad_free": true, "premium_content": true}', true,
        '2025-09-27 16:15:43.039758', '2025-10-09 15:09:43.400970');
INSERT INTO vip_plans (id, name, description, price, original_price, duration_days, level, features, is_active, created_at, updated_at)
VALUES (6, '年度尊享版', '年度订阅，尊享体验', 288.88, 399.00, 372, 3,
        '{"ad_free": true, "premium_content": true, "early_access": true, "custom_profile": true, "priority_support": true, "exclusive_events": true,"additional_cloud_storage": true}',
        true, '2025-09-27 18:58:08.000000', '2025-10-09 15:22:03.225280');