import re
import uuid
from pathlib import Path

from flask import jsonify

from src.user.entities import db_save_avatar, db_save_bio, check_user_conflict, db_change_username


def edit_profile(request,change_type ,user_id):
    if change_type == 'avatar':
        if 'avatar' not in request.files:
            return jsonify({'error': 'Avatar is required'}), 400
        avatar_file = request.files['avatar']
        if avatar_file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # 生成UUID
        avatar_uuid = uuid.uuid4()
        save_path = Path('avatar') / f'{avatar_uuid}.webp'

        # 确保目录存在
        save_path.parent.mkdir(parents=True, exist_ok=True)

        # 使用with语句保存文件
        with save_path.open('wb') as avatar_path:
            avatar_file.save(avatar_path)
            db_save_avatar(user_id, str(avatar_uuid))

        return jsonify({'message': 'Avatar updated successfully', 'avatar_id': str(avatar_uuid)}), 200
    if change_type == 'bio':
        bio = request.json.get('bio')
        db_save_bio(user_id, bio)
        return jsonify({'message': 'Bio updated successfully'}), 200


    return None