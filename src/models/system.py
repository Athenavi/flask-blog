from . import db


class SystemSettings(db.Model):
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    key = db.Column(db.String(255), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    updated_at = db.Column(db.TIMESTAMP, default='CURRENT_db.TIMESTAMP')
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'))


class Menus(db.Model):
    __tablename__ = 'menus'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.TIMESTAMP, default='CURRENT_db.TIMESTAMP')
    updated_at = db.Column(db.TIMESTAMP, default='CURRENT_db.TIMESTAMP')


class MenuItems(db.Model):
    __tablename__ = 'menu_items'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    menu_id = db.Column(db.Integer, db.ForeignKey('menus.id'))
    parent_id = db.Column(db.Integer, db.ForeignKey('menu_items.id'))
    title = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(500))
    target = db.Column(db.String(20), default='_self')
    order_index = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.TIMESTAMP, default='CURRENT_db.TIMESTAMP')


class Pages(db.Model):
    __tablename__ = 'pages'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False)
    content = db.Column(db.Text)
    excerpt = db.Column(db.Text)
    template = db.Column(db.String(100))
    status = db.Column(db.Integer, default=0)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    parent_id = db.Column(db.Integer, db.ForeignKey('pages.id'))
    order_index = db.Column(db.Integer, default=0)
    meta_title = db.Column(db.String(255))
    meta_description = db.Column(db.Text)
    meta_keywords = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default='CURRENT_db.TIMESTAMP')
    updated_at = db.Column(db.TIMESTAMP, default='CURRENT_db.TIMESTAMP')
    published_at = db.Column(db.TIMESTAMP)
