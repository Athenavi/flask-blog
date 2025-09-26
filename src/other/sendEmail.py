import uuid

from src.config.mail import get_mail_conf


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


def api_mail(user_id, body_content, site_name='系统通知'):
    from src.notification import send_email
    subject = f'{site_name} - 通知邮件'

    smtp_server, stmp_port, sender_email, password = get_mail_conf()
    receiver_email = sender_email
    body = body_content + "\n\n\n此邮件为系统自动发送，请勿回复。"
    send_email(sender_email, password, receiver_email, smtp_server, int(stmp_port), subject=subject,
               body=body)
    # logger.info(f'{user_id} sendMail')
    return True
