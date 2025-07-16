from src.database import get_db_connection


def set_article_password(aid, passwd):
    db = get_db_connection()
    aid = int(aid)
    try:
        with db.cursor() as cursor:
            query = "SELECT * FROM article_content WHERE aid = %s;"
            cursor.execute(query, (aid,))
            result = cursor.fetchone()
            if result:
                query = "UPDATE `article_content` SET `pass` = %s WHERE `article_content`.`aid` = %s;"
                cursor.execute(query, (passwd, aid,))
            else:
                query = "INSERT INTO `article_content` (`aid`, `pass`) VALUES (%s, %s);"
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

def get_article_password(aid):
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            query = "SELECT `pass` FROM article_content WHERE aid = %s"
            cursor.execute(query, (int(aid),))
            result = cursor.fetchone()
            if result:
                return result[0]
    except ValueError as e:
        #app.logger.error(f"Value error: {e}")
        pass
    except Exception as e:
        #app.logger.error(f"Unexpected error: {e}")
        pass
    finally:
        db.close()