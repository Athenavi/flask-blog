import string
import random

#from pymysql.err import DatabaseError

from src.database import get_db_connection


def generate_short_url():
    characters = string.ascii_letters + string.digits
    short_url = ''.join(random.choice(characters) for _ in range(6))
    return short_url


# 专属
def create_special_url(long_url, user_id):
    db = get_db_connection()
    cursor = db.cursor()

    try:
        query = "SELECT short_url FROM urls WHERE long_url = %s AND user_id = %s"
        cursor.execute(query, (long_url, user_id))
        result = cursor.fetchone()

        if result:
            short_url = result[0]
        else:
            short_url = generate_short_url()

            insert_query = "INSERT INTO urls (long_url, short_url, user_id) VALUES (%s, %s, %s)"
            cursor.execute(insert_query, (long_url, short_url, user_id))
            db.commit()

        return short_url
    except Exception as e:
        return "Not Found {e}".format(e=e)
    finally:
        cursor.close()
        db.close()


def redirect_to_long_url(short_url):
    db = get_db_connection()
    cursor = db.cursor()

    try:
        query = "SELECT long_url FROM urls WHERE short_url = %s"
        cursor.execute(query, (short_url,))
        result = cursor.fetchone()

        if result:
            long_url = result[0]
            return long_url
        else:
            return None
    #except (ValueError, DatabaseError) as e:
    #    print(f"An error occurred: {e}")
    #    return None
    finally:
        cursor.close()
        db.close()


def delete_link(short_url):
    db = get_db_connection()
    cursor = db.cursor()

    try:
        query = "DELETE FROM urls WHERE short_url = %s"
        cursor.execute(query, (short_url,))
        db.commit()

        return True
    except Exception as e:
        return "Not Found {e}".format(e=e)
    finally:
        cursor.close()
        db.close()
