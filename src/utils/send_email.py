import uuid

from src.extensions import mail
from src.setting import app_config


def request_email_change(user_id, cache_instance, domain, new_email):
    # 生成唯一令牌
    token = str(uuid.uuid4())
    temp_email_value = {
        'token': token,
        'new_email': new_email
    }

    cache_instance.set(f"temp_email_{user_id}", temp_email_value, timeout=600)

    # 生成临时访问链接 (实际应用中应通过邮件发送)
    temp_link = f'{domain}api/change-email/confirm/{token}'
    if api_mail(user_id=user_id,
                body_content=f'您可以通过点击如下的链接来完成邮箱更新\n\n{temp_link}\n\n如果不是您发起的请求，请忽略该邮件'):
        print(temp_link)


from flask_mail import Message


def api_mail(user_id, body_content, site_name='系统通知'):
    subject = f'{site_name} - 通知邮件'
    body = body_content + "\n\n\n此邮件为系统自动发送，请勿回复。"
    # 创建邮件消息
    msg = Message(
        subject=subject,  # 邮件主题
        recipients=[app_config.MAIL_USERNAME],
        body=body
    )

    # 发送邮件
    mail.send(msg)
    print(f"邮件派送人: {user_id if user_id != 0 else '系统'}")
    return True
