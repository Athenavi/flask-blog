from . import db

class FileHash(db.Model):
    __tablename__ = 'file_hashes'
    id = db.Column(db.BigInteger, primary_key=True)
    hash = db.Column(db.String(64), nullable=False, unique=True)
    filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    reference_count = db.Column(db.Integer, default=1)
    file_size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    storage_path = db.Column(db.String(512), nullable=False)

    media = db.relationship('Media', back_populates='file_hash')


class Media(db.Model):
    __tablename__ = 'media'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    hash = db.Column(db.String(64), db.ForeignKey('file_hashes.hash'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    user = db.relationship('User', back_populates='media')
    file_hash = db.relationship('FileHash', back_populates='media')