from flask import request, jsonify

from src.database import get_db
from src.models import Report


def report_add(user_id, reported_type, reported_id, reason):
    reported = False
    with get_db() as session:
        try:
            new_report = Report(reported_by=int(user_id), content_type=reported_type, content_id=reported_id,
                                reason=reason)
            session.add(new_report)
            reported = True
        except Exception as e:
            print(f'Error: {e}')
            session.rollback()
        finally:
            return reported


def report_back(user_id):
    try:
        report_id = int(request.json.get('report-id'))
        report_type = request.json.get('report-type') or ''
        report_reason = request.json.get('report-reason') or ''
        reason = report_type + report_reason
    except (TypeError, ValueError):
        return jsonify({"message": "Invalid Report ID"}), 400

    if report_add(user_id, "Comment", report_id, reason):
        return jsonify({'report-id': report_id, 'info': '举报已记录'}), 201
    else:
        return jsonify({"message": "举报失败"}), 500
