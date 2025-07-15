from dotenv import load_dotenv
import os


def zy_mail_conf():
    load_dotenv('.env')  # 加载.env文件

    mail_host = os.getenv('MAIL_HOST', 'error').strip("'")
    mail_port = os.getenv('MAIL_PORT', 'error').strip("'")
    mail_user = os.getenv('MAIL_USER', 'error').strip("'")
    mail_password = os.getenv('MAIL_PASSWORD', 'error').strip("'")

    # 确保mail_port是整数
    try:
        mail_port = int(mail_port)
    except ValueError:
        mail_port = 'error'

    return mail_host, mail_port, mail_user, mail_password
