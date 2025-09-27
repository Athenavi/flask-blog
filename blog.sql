-- 创建枚举类型
CREATE TYPE article_status AS ENUM ('Draft', 'Published', 'Deleted');
CREATE TYPE report_content_type AS ENUM ('Article', 'Comment');
CREATE TYPE vip_status AS ENUM ('active', 'expired', 'cancelled');

create table if not exists users
(
    id              serial
        primary key,
    username        varchar(255) not null unique,
    password        varchar(255) not null,
    email           varchar(255) not null unique,
    created_at      timestamp default CURRENT_TIMESTAMP,
    updated_at      timestamp default CURRENT_TIMESTAMP,
    profile_picture varchar(255),
    bio             text,
    register_ip     varchar(45)  not null,
    is_2fa_enabled  boolean   default false,
    totp_secret     varchar(32),
    backup_codes    text,
    vip_level       Integer   default 0,
    vip_expires_at  timestamp
);

create table if not exists roles
(
    id          serial
        primary key,
    name        varchar(50)  not null
        unique,
    description varchar(255) not null
);

create table if not exists permissions
(
    id          serial
        primary key,
    code        varchar(50)  not null
        unique,
    description varchar(255) not null
);

create table if not exists user_roles
(
    user_id integer not null
        references users
            on delete cascade,
    role_id integer not null
        references roles
            on delete cascade,
    primary key (user_id, role_id)
);


create index if not exists idx_role_id
    on user_roles (role_id);

create table if not exists role_permissions
(
    role_id       integer not null
        references roles
            on delete cascade,
    permission_id integer not null
        references permissions
            on delete cascade,
    primary key (role_id, permission_id)
);

create index if not exists permission_id
    on role_permissions (permission_id);

create table if not exists categories
(
    id          serial
        primary key,
    name        varchar(255) not null unique,
    description text,
    created_at  timestamp default CURRENT_TIMESTAMP,
    updated_at  timestamp default CURRENT_TIMESTAMP
);

create table if not exists articles
(
    article_id         serial
        primary key,
    title              varchar(255)                 not null,
    slug               varchar(255)                 not null
        unique,
    user_id            integer                      not null
        references users
            on delete cascade,
    hidden             boolean        default false not null,
    views              bigint         default 0     not null,
    likes              bigint         default 0     not null,
    status             article_status default 'Draft'::article_status,
    cover_image        varchar(255),
    excerpt            text,
    is_featured        boolean        default false,
    tags               varchar(255)                 not null,
    created_at         timestamp      default CURRENT_TIMESTAMP,
    updated_at         timestamp      default CURRENT_TIMESTAMP,
    category_id        integer
        references categories,
    article_ad         text,
    is_vip_only        Boolean        default false,
    required_vip_level Integer        default 0
);

create table if not exists article_content
(
    aid           integer                                        not null
        primary key,
    passwd        varchar(128),
    content       text,
    updated_at    timestamp   default CURRENT_TIMESTAMP,
    language_code varchar(10) default 'zh-CN'::character varying not null
);

create table if not exists article_i18n
(
    i18n_id       serial
        primary key,
    article_id    integer      not null
        references articles
            on delete cascade,
    language_code varchar(10)  not null,
    title         varchar(255) not null,
    slug          varchar(255) not null,
    content       text         not null,
    excerpt       text,
    created_at    timestamp default CURRENT_TIMESTAMP,
    updated_at    timestamp default CURRENT_TIMESTAMP,
    unique (article_id, language_code),
    unique (article_id, language_code, slug)
);

create table if not exists comments
(
    id         serial
        primary key,
    article_id integer not null
        references articles
            on delete cascade,
    user_id    integer not null
        references users
            on delete cascade,
    parent_id  integer
        references comments
            on delete cascade,
    content    text    not null,
    ip         varchar(50),
    user_agent varchar(255),
    created_at timestamp default CURRENT_TIMESTAMP,
    updated_at timestamp default CURRENT_TIMESTAMP
);

create index if not exists idx_article_created
    on comments (article_id, created_at);

create index if not exists idx_parent_created
    on comments (parent_id, created_at);

create index if not exists user_id_comments
    on comments (user_id);

create table if not exists file_hashes
(
    id              bigserial
        primary key,
    hash            varchar(64)  not null
        unique,
    filename        varchar(255) not null,
    created_at      timestamp default CURRENT_TIMESTAMP,
    reference_count integer   default 1,
    file_size       bigint       not null,
    mime_type       varchar(100) not null,
    storage_path    varchar(512) not null
);

create table if not exists media
(
    id                serial
        primary key,
    user_id           integer      not null
        references users
            on delete cascade,
    created_at        timestamp default CURRENT_TIMESTAMP,
    updated_at        timestamp default CURRENT_TIMESTAMP,
    hash              varchar(64)  not null
        references file_hashes (hash)
            on delete cascade,
    original_filename varchar(255) not null
);

create table if not exists category_subscriptions
(
    id            serial
        primary key,
    subscriber_id integer not null
        references users
            on delete cascade,
    category_id   integer not null
        references categories
            on delete cascade,
    created_at    timestamp default CURRENT_TIMESTAMP
);

create index if not exists idx_subscriber
    on category_subscriptions (subscriber_id);

create index if not exists idx_category
    on category_subscriptions (category_id);

create table if not exists notifications
(
    id         serial
        primary key,
    user_id    integer                 not null
        references users
            on delete cascade,
    type       varchar(100)            not null,
    message    text                    not null,
    is_read    boolean   default false not null,
    created_at timestamp default CURRENT_TIMESTAMP,
    updated_at timestamp default CURRENT_TIMESTAMP
);

create index if not exists idx_user_id_noti
    on notifications (user_id);

create table if not exists user_subscriptions
(
    id                 serial
        primary key,
    subscriber_id      integer not null
        references users
            on delete cascade,
    subscribed_user_id integer not null
        references users
            on delete cascade,
    created_at         timestamp default CURRENT_TIMESTAMP
);

create index if not exists idx_subscriber_user
    on user_subscriptions (subscriber_id);

create index if not exists idx_subscribed_user_sui
    on user_subscriptions (subscribed_user_id);

create table if not exists events
(
    id          serial
        primary key,
    title       varchar(255) not null,
    description text         not null,
    event_date  timestamp    not null,
    created_at  timestamp default CURRENT_TIMESTAMP
);

create table if not exists reports
(
    id           serial
        primary key,
    reported_by  integer             not null
        references users
            on delete cascade,
    content_type report_content_type not null,
    content_id   integer             not null,
    reason       text                not null,
    created_at   timestamp default CURRENT_TIMESTAMP
);

create index if not exists idx_reported_by
    on reports (reported_by);

create table if not exists urls
(
    id         serial
        primary key,
    long_url   varchar(255) not null,
    short_url  varchar(10)  not null
        unique,
    created_at timestamp default CURRENT_TIMESTAMP,
    user_id    integer      not null
        references users
            on delete cascade
);

create table if not exists oauth_connections
(
    id               serial
        primary key,
    user_id          integer      not null
        references users
            on delete cascade,
    provider         varchar(50)  not null,
    provider_user_id varchar(255) not null,
    access_token     varchar(512),
    refresh_token    varchar(512),
    expires_at       timestamp,
    unique (provider, provider_user_id)
);

create index if not exists idx_oauth_user
    on oauth_connections (user_id, provider);

create table if not exists custom_fields
(
    id          serial
        primary key,
    user_id     integer      not null
        references users
            on delete cascade,
    field_name  varchar(100) not null,
    field_value text         not null
);

create index if not exists idx_user_id_cf
    on custom_fields (user_id);

create table if not exists email_subscriptions
(
    id         serial
        primary key,
    user_id    integer                not null
        unique
        references users
            on delete cascade,
    subscribed boolean   default true not null,
    created_at timestamp default CURRENT_TIMESTAMP
);

create index if not exists idx_user_id_es
    on email_subscriptions (user_id);

-- 插入默认数据
INSERT INTO users (username, password, email, created_at, updated_at, profile_picture, bio, register_ip)
VALUES ('test', '$2b$12$kF4nZn6kESHtj0cjNeaoZugUlWXSgXp27iKAXHepyzSwUxrrhVTz2', 'support@7trees.cn',
        '2025-09-10 17:09:13', '2025-04-16 07:38:59', NULL, NULL, '');

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

create table vip_plans
(
    id            serial
        primary key,
    name          varchar(100)   not null,
    description   text,
    price         numeric(10, 2) not null,
    duration_days integer        not null,
    level         integer        not null,
    features      text,
    is_active     boolean,
    created_at    timestamp,
    updated_at    timestamp
);

create table vip_subscriptions
(
    id             serial
        primary key,
    user_id        integer   not null
        references users,
    plan_id        integer   not null
        references vip_plans,
    starts_at      timestamp not null,
    expires_at     timestamp not null,
    status         vip_status,
    payment_amount numeric(10, 2),
    transaction_id varchar(255),
    created_at     timestamp
);

create index idx_vip_subscriptions_expires_at
    on vip_subscriptions (expires_at);

create index idx_vip_subscriptions_user_id
    on vip_subscriptions (user_id);

