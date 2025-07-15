from src.database import get_db_connection


def update_article_password(aid, passwd):
    db = get_db_connection()
    aid = int(aid)
    try:
        with db.cursor() as cursor:
            query = "SELECT * FROM article_pass WHERE aid = %s;"
            cursor.execute(query, (aid,))
            result = cursor.fetchone()
            if result:
                query = "UPDATE `article_pass` SET `pass` = %s WHERE `article_pass`.`aid` = %s;"
                cursor.execute(query, (passwd, aid,))
            else:
                query = "INSERT INTO `article_pass` (`aid`, `pass`) VALUES (%s, %s);"
                cursor.execute(query, (aid, passwd,))
    except Exception as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        db.commit()
        try:
            cursor.close()
        except NameError:
            pass
        db.close()
        return True