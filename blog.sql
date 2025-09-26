-- 创建枚举类型
CREATE TYPE article_status AS ENUM ('Draft', 'Published', 'Deleted');
CREATE TYPE report_content_type AS ENUM ('Article', 'Comment');

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
    backup_codes    text
);

comment on table users is '用户基本信息表';

comment on column users.username is '用户名，唯一标识';

comment on column users.password is '用户密码（加密存储）';

comment on column users.email is '邮箱地址，唯一标识';

comment on column users.created_at is '账户创建时间';

comment on column users.updated_at is '最后更新时间';

comment on column users.profile_picture is '头像图片路径';

comment on column users.bio is '个人简介';

comment on column users.register_ip is '注册IP地址';

comment on column users.is_2fa_enabled is '是否启用双因子认证';

comment on column users.totp_secret is 'TOTP密钥';

comment on column users.backup_codes is '备份代码';

create table if not exists roles
(
    id          serial
        primary key,
    name        varchar(50)  not null
        unique,
    description varchar(255) not null
);

comment on table roles is '系统角色表';

comment on column roles.name is '角色名称';

comment on column roles.description is '角色描述';

create table if not exists permissions
(
    id          serial
        primary key,
    code        varchar(50)  not null
        unique,
    description varchar(255) not null
);

comment on table permissions is '系统权限表';

comment on column permissions.code is '权限代码';

comment on column permissions.description is '权限描述';

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

comment on table user_roles is '用户角色关联表';

comment on column user_roles.user_id is '用户ID';

comment on column user_roles.role_id is '角色ID';

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

comment on table role_permissions is '角色权限关联表';

comment on column role_permissions.role_id is '角色ID';

comment on column role_permissions.permission_id is '权限ID';

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

comment on table categories is '文章分类表';

comment on column categories.name is '分类名称';

comment on column categories.created_at is '创建时间';

comment on column categories.updated_at is '更新时间';

create table if not exists articles
(
    article_id  serial
        primary key,
    title       varchar(255)                 not null,
    slug        varchar(255)                 not null
        unique,
    user_id     integer                      not null
        references users
            on delete cascade,
    hidden      boolean        default false not null,
    views       bigint         default 0     not null,
    likes       bigint         default 0     not null,
    status      article_status default 'Draft'::article_status,
    cover_image varchar(255),
    excerpt     text,
    is_featured boolean        default false,
    tags        varchar(255)                 not null,
    created_at  timestamp      default CURRENT_TIMESTAMP,
    updated_at  timestamp      default CURRENT_TIMESTAMP,
    category_id integer
        references categories,
    article_ad  text
);

comment on table articles is '文章基本信息表';

comment on column articles.title is '文章标题';

comment on column articles.slug is '文章URL别名';

comment on column articles.user_id is '作者用户ID';

comment on column articles.hidden is '是否隐藏';

comment on column articles.views is '浏览次数';

comment on column articles.likes is '点赞次数';

comment on column articles.status is '文章状态：草稿/已发布/已删除';

comment on column articles.cover_image is '封面图片路径';

comment on column articles.article_type is '文章类型';

comment on column articles.excerpt is '文章摘要';

comment on column articles.is_featured is '是否置顶推荐';

comment on column articles.tags is '文章标签（逗号分隔）';

comment on column articles.created_at is '创建时间';

comment on column articles.updated_at is '最后更新时间';

create table if not exists article_content
(
    aid           integer                                        not null
        primary key,
    passwd        varchar(128),
    content       text,
    updated_at    timestamp   default CURRENT_TIMESTAMP,
    language_code varchar(10) default 'zh-CN'::character varying not null
);

comment on table article_content is '文章内容表';

comment on column article_content.aid is '文章ID';

comment on column article_content.passwd is '文章访问密码';

comment on column article_content.content is '文章正文内容';

comment on column article_content.updated_at is '内容更新时间';

comment on column article_content.language_code is '语言代码';

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

comment on table article_i18n is '文章国际化翻译表';

comment on column article_i18n.i18n_id is '国际化翻译ID';

comment on column article_i18n.article_id is '原始文章ID';

comment on column article_i18n.language_code is '语言代码';

comment on column article_i18n.title is '翻译后标题';

comment on column article_i18n.slug is '翻译后URL别名';

comment on column article_i18n.content is '翻译后内容';

comment on column article_i18n.excerpt is '翻译后摘要';

comment on column article_i18n.created_at is '创建时间';

comment on column article_i18n.updated_at is '更新时间';

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

comment on table comments is '文章评论表';

comment on column comments.id is '评论ID';

comment on column comments.article_id is '所属文章ID';

comment on column comments.user_id is '评论者用户ID';

comment on column comments.parent_id is '父评论ID（用于回复）';

comment on column comments.content is '评论内容';

comment on column comments.ip is '评论者IP地址';

comment on column comments.user_agent is '用户代理信息';

comment on column comments.created_at is '评论时间';

comment on column comments.updated_at is '更新时间';

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

comment on table file_hashes is '文件哈希表（用于文件去重存储）';

comment on column file_hashes.id is '文件哈希ID';

comment on column file_hashes.hash is '文件哈希值（用于去重）';

comment on column file_hashes.filename is '原始文件名';

comment on column file_hashes.created_at is '创建时间';

comment on column file_hashes.reference_count is '引用计数';

comment on column file_hashes.file_size is '文件大小（字节）';

comment on column file_hashes.mime_type is '文件MIME类型';

comment on column file_hashes.storage_path is '文件存储路径';

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

comment on table media is '媒体文件信息表';

comment on column media.id is '媒体ID';

comment on column media.user_id is '上传用户ID';

comment on column media.created_at is '上传时间';

comment on column media.updated_at is '更新时间';

comment on column media.hash is '文件哈希值';

comment on column media.original_filename is '原始文件名';

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

comment on table category_subscriptions is '分类订阅关系表';

comment on column category_subscriptions.id is '订阅关系ID';

comment on column category_subscriptions.subscriber_id is '订阅者用户ID';

comment on column category_subscriptions.category_id is '被订阅分类ID';

comment on column category_subscriptions.created_at is '订阅时间';

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

comment on table notifications is '用户通知表';

comment on column notifications.id is '通知ID';

comment on column notifications.user_id is '接收用户ID';

comment on column notifications.type is '通知类型';

comment on column notifications.message is '通知内容';

comment on column notifications.is_read is '是否已读';

comment on column notifications.created_at is '创建时间';

comment on column notifications.updated_at is '更新时间';

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

comment on table user_subscriptions is '用户间订阅关系表';

comment on column user_subscriptions.id is '用户间订阅关系ID';

comment on column user_subscriptions.subscriber_id is '订阅者用户ID';

comment on column user_subscriptions.subscribed_user_id is '被订阅用户ID';

comment on column user_subscriptions.created_at is '订阅时间';

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

comment on table events is '系统事件记录表';

comment on column events.id is '事件ID';

comment on column events.title is '事件标题';

comment on column events.description is '事件描述';

comment on column events.event_date is '事件日期';

comment on column events.created_at is '创建时间';

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

comment on table reports is '内容举报记录表';

comment on column reports.id is '举报记录ID';

comment on column reports.reported_by is '举报人用户ID';

comment on column reports.content_type is '举报内容类型';

comment on column reports.content_id is '举报内容ID';

comment on column reports.reason is '举报原因';

comment on column reports.created_at is '举报时间';

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

comment on table urls is '短链接映射表';

comment on column urls.id is '短链接映射ID';

comment on column urls.long_url is '原始长链接';

comment on column urls.short_url is '短链接代码';

comment on column urls.created_at is '创建时间';

comment on column urls.user_id is '创建用户ID';

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

comment on table oauth_connections is 'OAuth第三方登录关联表';

comment on column oauth_connections.id is 'OAuth关联ID';

comment on column oauth_connections.user_id is '关联用户ID';

comment on column oauth_connections.provider is 'OAuth提供商';

comment on column oauth_connections.provider_user_id is '提供商用户ID';

comment on column oauth_connections.access_token is '访问令牌';

comment on column oauth_connections.refresh_token is '刷新令牌';

comment on column oauth_connections.expires_at is '令牌过期时间';

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

comment on table custom_fields is '用户自定义字段表';

comment on column custom_fields.id is '自定义字段ID';

comment on column custom_fields.user_id is '用户ID';

comment on column custom_fields.field_name is '自定义字段名';

comment on column custom_fields.field_value is '自定义字段值';

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

comment on table email_subscriptions is '邮件订阅设置表';

comment on column email_subscriptions.id is '邮件订阅ID';

comment on column email_subscriptions.user_id is '用户ID';

comment on column email_subscriptions.subscribed is '是否订阅邮件';

comment on column email_subscriptions.created_at is '订阅时间';

create index if not exists idx_user_id_es
    on email_subscriptions (user_id);

-- 插入默认数据
INSERT INTO users (username, password, email, created_at, updated_at, profile_picture, bio, register_ip)
VALUES ('test', '$2b$12$kF4nZn6kESHtj0cjNeaoZugUlWXSgXp27iKAXHepyzSwUxrrhVTz2', 'support@7trees.cn',
        '2025-09-10 17:09:13', '2025-04-16 07:38:59', NULL, NULL, '');
