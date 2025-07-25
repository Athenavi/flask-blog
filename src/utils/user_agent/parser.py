from user_agents import parse
import re

def parse_user_agent(user_agent):
    # 解析 User-Agent 字符串
    user_agent_parsed = parse(user_agent)

    # 初始化值得转换后的 User-Agent 描述
    converted_ua = "Unknown Device"

    # 根据解析结果构造转换后的描述
    if user_agent_parsed.is_pc:
        converted_ua = f"PC / {user_agent_parsed.browser.family} / {user_agent_parsed.os.family}"
    elif user_agent_parsed.is_mobile:
        converted_ua = f"Mobile / {user_agent_parsed.device.family} / {user_agent_parsed.os.family}"
    elif user_agent_parsed.is_tablet:
        converted_ua = f"Tablet / {user_agent_parsed.device.family} / {user_agent_parsed.os.family}"

    return converted_ua


def sanitize_user_agent(user_agent):
    if user_agent is None:
        return None
    sanitized_agent = re.sub(r'[.;,()/\s]', '', user_agent)
    return sanitized_agent