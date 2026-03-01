from flask import Blueprint, jsonify

from src.auth_utils import jwt_required
# from src.database import get_db
from src.models import Notification, db
from src.notification import mark_notification_as_read, get_user_notifications, mark_all_notifications_as_read

noti_bp = Blueprint('noti', __name__, url_prefix='/noti')

from flask import request


@noti_bp.route('/api/messages/read', methods=['POST'])
@jwt_required
def read_notification(user_id):
    nid = int(request.args.get('nid'))
    return mark_notification_as_read(user_id, nid)


@noti_bp.route('/api/messages', methods=['GET'])
@jwt_required
def fetch_message(user_id):
    return get_user_notifications(user_id)


@noti_bp.route('/api/messages/read_all', methods=['POST'])
@jwt_required
def mark_all_as_read(user_id):
    return mark_all_notifications_as_read(user_id)


@noti_bp.route('/api/messages/clean', methods=['DELETE'])
@jwt_required
def clean_notification(user_id):
    nid = request.args.get('nid', 'all')
    if nid == 'all':
        db.session.query(Notification).filter_by(user_id=user_id).delete()
    else:
        db.session.query(Notification).filter_by(user_id=user_id, id=int(nid)).delete()
    db.session.commit()
    return jsonify({"success": True})
