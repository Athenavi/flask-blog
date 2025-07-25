create table categories
(
    id         int auto_increment
        primary key,
    name       varchar(255)                        not null,
    created_at timestamp default CURRENT_TIMESTAMP null,
    updated_at timestamp default CURRENT_TIMESTAMP null on update CURRENT_TIMESTAMP
)
    comment '内容分类表';

create table events
(
    id          int auto_increment
        primary key,
    title       varchar(255)                        not null comment '事件标题',
    description text                                not null comment '事件描述',
    event_date  datetime                            not null comment '事件日期',
    created_at  timestamp default CURRENT_TIMESTAMP not null comment '创建时间'
);

create table file_hashes
(
    id              bigint unsigned auto_increment
        primary key,
    hash            varchar(64)                            not null,
    filename        varchar(255)                           not null,
    created_at      timestamp    default CURRENT_TIMESTAMP null,
    reference_count int unsigned default '1'               null,
    file_size       bigint unsigned                        not null comment '文件大小（字节）',
    mime_type       varchar(100)                           not null comment 'MIME 类型',
    storage_path    varchar(255)                           not null comment '实际存储路径',
    constraint hash
        unique (hash)
);

create table permissions
(
    id          int auto_increment
        primary key,
    code        varchar(50)  not null comment '权限代码（如 manage_users）',
    description varchar(255) not null comment '权限描述',
    constraint code
        unique (code)
);

create table roles
(
    id          int auto_increment
        primary key,
    name        varchar(50)  not null comment '角色名称',
    description varchar(255) not null comment '角色描述',
    constraint name
        unique (name)
);

create table role_permissions
(
    role_id       int not null,
    permission_id int not null,
    primary key (role_id, permission_id),
    constraint role_permissions_ibfk_1
        foreign key (role_id) references roles (id)
            on delete cascade,
    constraint role_permissions_ibfk_2
        foreign key (permission_id) references permissions (id)
            on delete cascade
);

create index permission_id
    on role_permissions (permission_id);

create table users
(
    id              int auto_increment
        primary key,
    username        varchar(255)                        not null comment '用户名',
    password        varchar(255)                        not null comment '用户密码',
    email           varchar(255)                        not null comment '用户邮箱',
    created_at      timestamp default CURRENT_TIMESTAMP not null,
    updated_at      timestamp default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP,
    profile_picture varchar(255)                        null comment '用户头像',
    bio             text                                null comment '用户个人简介',
    register_ip     varchar(45)                         not null comment '注册时IP',
    constraint email
        unique (email),
    constraint username
        unique (username)
);

create table articles
(
    article_id   int auto_increment
        primary key,
    title        varchar(255)                                                     not null comment '文章标题',
    user_id      int                                                              null comment '作者用户ID',
    hidden       tinyint(1)                             default 0                 not null comment '是否隐藏 1 隐藏 0 不隐藏',
    views        bigint unsigned                        default '0'               not null comment '浏览次数',
    likes        bigint unsigned                        default '0'               not null comment '点赞数',
    status       enum ('Draft', 'Published', 'Deleted') default 'Draft'           null comment '文章状态: 草稿/已发布/已删除',
    cover_image  varchar(255)                                                     null comment '封面图片路径',
    article_type varchar(50)                                                      null comment '文章类型',
    excerpt      text                                                             null comment '文章摘要',
    is_featured  tinyint(1)                             default 0                 null comment '是否为推荐文章',
    tags         varchar(255)                                                     not null,
    created_at   timestamp                              default CURRENT_TIMESTAMP null comment '创建时间',
    updated_at   timestamp                              default CURRENT_TIMESTAMP null on update CURRENT_TIMESTAMP comment '更新时间',
    constraint fk_article_user
        foreign key (user_id) references users (id)
            on delete set null
);

create table article_content
(
    aid        int        not null
        primary key,
    pass       varchar(128) null,
    content    text       null,
    updated_at timestamp default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
    constraint article_content_ibfk_1
        foreign key (aid) references articles (article_id)
            on delete cascade
);

create index idx_views
    on articles (views);

create table category_subscriptions
(
    id            int auto_increment
        primary key,
    subscriber_id int                                 not null comment '订阅者ID',
    category_id   int                                 not null comment '被订阅分类ID',
    created_at    timestamp default CURRENT_TIMESTAMP null,
    constraint fk_subscriber_category
        foreign key (subscriber_id) references users (id)
            on delete cascade,
    constraint fk_target_category
        foreign key (category_id) references categories (id)
            on delete cascade
)
    comment '分类订阅关系';

create index idx_category
    on category_subscriptions (category_id);

create index idx_subscriber
    on category_subscriptions (subscriber_id);

create table comments
(
    id         int auto_increment
        primary key,
    article_id int                                 not null comment '关联的文章ID',
    user_id    int                                 not null comment '评论者用户ID',
    content    text                                not null comment '评论内容',
    created_at timestamp default CURRENT_TIMESTAMP not null comment '评论时间',
    updated_at timestamp default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP comment '更新时间',
    constraint comments_ibfk_1
        foreign key (article_id) references articles (article_id)
            on delete cascade,
    constraint comments_ibfk_2
        foreign key (user_id) references users (id)
            on delete cascade
);

create index idx_article_id
    on comments (article_id);

create index idx_created_at
    on comments (created_at);

create index idx_user_id
    on comments (user_id);

create table custom_fields
(
    id          int auto_increment
        primary key,
    user_id     int          not null comment '用户ID',
    field_name  varchar(100) not null comment '自定义字段名称',
    field_value text         not null comment '自定义字段值',
    constraint custom_fields_ibfk_1
        foreign key (user_id) references users (id)
            on delete cascade
);

create index idx_user_id
    on custom_fields (user_id);

create table email_subscriptions
(
    id         int auto_increment
        primary key,
    user_id    int                                  not null comment '用户ID',
    subscribed tinyint(1) default 1                 not null comment '是否订阅邮件',
    created_at timestamp  default CURRENT_TIMESTAMP not null comment '订阅时间',
    constraint unique_user_subscription
        unique (user_id),
    constraint email_subscriptions_ibfk_1
        foreign key (user_id) references users (id)
            on delete cascade
);

create index idx_user_id
    on email_subscriptions (user_id);

create table media
(
    id                int auto_increment
        primary key,
    user_id           int                                 not null comment '上传用户ID',
    created_at        timestamp default CURRENT_TIMESTAMP not null comment '创建时间',
    updated_at        timestamp default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP comment '更新时间',
    hash              varchar(64)                         not null comment '文件哈希',
    original_filename varchar(255)                        not null comment '原始文件名',
    constraint fk_media_file_hash
        foreign key (hash) references file_hashes (hash),
    constraint media_ibfk_1
        foreign key (user_id) references users (id)
            on delete cascade
);

create index idx_user_id
    on media (user_id);

create table notifications
(
    id         int auto_increment
        primary key,
    user_id    int                                  not null comment '接收者用户ID',
    type       varchar(100)                         not null comment '通知类型',
    message    text                                 not null comment '通知内容',
    is_read    tinyint(1) default 0                 not null comment '是否已阅读',
    created_at timestamp  default CURRENT_TIMESTAMP not null comment '创建时间',
    updated_at timestamp  default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP comment '更新时间',
    constraint notifications_ibfk_1
        foreign key (user_id) references users (id)
            on delete cascade
);

create index idx_user_id
    on notifications (user_id);

create table reports
(
    id           int auto_increment
        primary key,
    reported_by  int                                 not null comment '举报用户ID',
    content_type enum ('Article', 'Comment')         not null comment '内容类型: 文章/评论',
    content_id   int                                 not null comment '内容ID',
    reason       text                                not null comment '举报理由',
    created_at   timestamp default CURRENT_TIMESTAMP not null comment '举报时间',
    constraint reports_ibfk_1
        foreign key (reported_by) references users (id)
            on delete cascade
);

create index idx_reported_by
    on reports (reported_by);

create table urls
(
    id         int auto_increment
        primary key,
    long_url   varchar(255)                        not null comment '长链接',
    short_url  varchar(10)                         not null comment '短链接',
    created_at timestamp default CURRENT_TIMESTAMP not null comment '创建时间',
    user_id    int                                 not null comment '用户ID',
    constraint uniq_short_url
        unique (short_url),
    constraint fk_urls_user
        foreign key (user_id) references users (id)
            on delete cascade
);

create table user_roles
(
    user_id int not null,
    role_id int not null,
    primary key (user_id, role_id),
    constraint user_roles_ibfk_1
        foreign key (user_id) references users (id)
            on delete cascade,
    constraint user_roles_ibfk_2
        foreign key (role_id) references roles (id)
            on delete cascade
);

create index idx_role_id
    on user_roles (role_id);

create table user_subscriptions
(
    id                 int auto_increment
        primary key,
    subscriber_id      int                                 not null comment '订阅者ID',
    subscribed_user_id int                                 not null comment '被订阅用户ID',
    created_at         timestamp default CURRENT_TIMESTAMP null,
    constraint fk_subscribed_user
        foreign key (subscribed_user_id) references users (id)
            on delete cascade,
    constraint fk_subscriber_user
        foreign key (subscriber_id) references users (id)
            on delete cascade
)
    comment '用户订阅关系';

create index idx_subscribed_user
    on user_subscriptions (subscribed_user_id);

create index idx_subscriber
    on user_subscriptions (subscriber_id);
-- --------------------------------------------------------
--
-- 转存表中的数据 `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `email`, `created_at`, `updated_at`, `profile_picture`, `bio`,
                     `register_ip`)
VALUES (1, 'test', '$2b$12$kF4nZn6kESHtj0cjNeaoZugUlWXSgXp27iKAXHepyzSwUxrrhVTz2', 'support@7trees.cn',
        '2025-04-16 07:38:59', '2025-04-16 07:38:59', NULL, NULL, '');
