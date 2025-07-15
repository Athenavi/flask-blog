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
