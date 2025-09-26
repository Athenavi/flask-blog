from . import db

report_type = db.Enum('Article', 'Comment', name='report_content_type', create_type=False)


class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())


class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    reported_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_type = db.Column(report_type, nullable=False)
    content_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    # 关系定义
    reporter = db.relationship('User', back_populates='reports')

    __table_args__ = (
        db.Index('idx_reports_reported_by', 'reported_by'),
    )


class Url(db.Model):
    __tablename__ = 'urls'
    id = db.Column(db.Integer, primary_key=True)
    long_url = db.Column(db.String(255), nullable=False)
    short_url = db.Column(db.String(10), nullable=False, unique=True)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # 关系定义
    user = db.relationship('User', back_populates='urls')

    __table_args__ = (
        db.Index('idx_user_id_url', 'user_id'),
        db.UniqueConstraint('user_id', 'long_url', name='uq_user_long_url')
    )

