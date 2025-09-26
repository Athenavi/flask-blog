from src.database import get_db
from src.models import Media


def get_media_db(user_id, page=1, per_page=20):
    with get_db() as session:
        try:
            offset = (page - 1) * per_page
            query = session.query(Media.id, Media.original_filename, Media.hash).filter(
                Media.user_id == user_id).order_by(
                Media.id.desc()).offset(offset).limit(per_page)
            files = query.all()

            count_query = session.query(Media).filter(Media.user_id == user_id).count()
            total_pages = (count_query + per_page - 1) // per_page
            return files, total_pages
        except Exception as e:
            print(f"An error occurred: {e}")
            return [], 0
