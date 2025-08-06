from flask import request, jsonify

from src.database import get_db_connection


def report_add(user_id, reported_type, reported_id, reason):
    reported = False
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            query = ("INSERT INTO `reports` (`reported_by`, `content_type`, `content_id`,`reason`) VALUES (%s, %s, %s,"
                     "%s);")
            cursor.execute(query, (int(user_id), reported_type, reported_id, reason))
            db.commit()
            reported = True
    except Exception as e:
        print(f'Error: {e}')
    finally:
        db.close()
        return reported


def report_back(user_id):
    try:
        report_id = int(request.json.get('report-id'))
        report_type = request.json.get('report-type') or ''
        report_reason = request.json.get('report-reason') or ''
        reason = report_type + report_reason
    except (TypeError, ValueError):
        return jsonify({"message": "Invalid Report ID"}), 400
    result = report_add(user_id, "Comment", report_id, reason)

    if result:
        return jsonify({'report-id': report_id, 'info': '举报已记录'}), 201
    else:
        return jsonify({"message": "举报失败"}), 500
