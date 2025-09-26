
def get_client_ip(req):
    if 'X-Forwarded-For' in req.headers:
        ip = req.headers['X-Forwarded-For'].split(',')[0].strip()
    elif 'X-Real-IP' in req.headers:
        ip = req.headers['X-Real-IP'].strip()
    else:
        ip = req.remote_addr

    return ip


def anonymize_ip_address(ip):
    # 将 IP 地址分割成四个部分
    parts = ip.split('.')
    if len(parts) == 4:
        # 隐藏最后两个部分
        masked_ip = f"{parts[0]}.{parts[1]}.xxx.xxx"
        return masked_ip
    return ip
