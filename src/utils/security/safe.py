import hashlib
import random
import re
import string

import requests

from src.config.general import cloudflare_turnstile_conf


def run_security_checks(url):
    pattern = r"^(https?://)?([a-zA-Z0-9-]+\.)*[a-zA-Z]{2,}(\/)$"
    if re.match(pattern, url):
        return True
    else:
        return False


def clean_html_format(text):
    clean_text = re.sub('<.*?>', '', str(text))
    return clean_text


def load_sensitive_words(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            sensitive_words = set(word.strip().lower() for word in file)
        return sensitive_words
    except FileNotFoundError:
        return set()
    except Exception as e:
        return set()


def filter_sensitive_words(comment_content, file_path='sensitive_words.txt', full_match=False, use_regex=False):
    sensitive_words = load_sensitive_words(file_path)

    comment_content_lower = comment_content.lower()
    if full_match:
        for word in sensitive_words:
            if word in comment_content_lower:
                return False
    elif use_regex:
        for word in sensitive_words:
            if re.search(word, comment_content_lower):
                return False
    else:
        # 部分匹配，查找包含敏感词的子串
        for word in sensitive_words:
            if any(word in token for token in comment_content_lower.split()):
                return False

    return True


def random_string(param):
    return ''.join(random.sample(string.ascii_letters + string.digits, param))


def is_valid_hash(length, f_hash):
    """
    验证哈希值是否为指定长度的十六进制字符串
    :param length: 哈希值的预期长度
    :param f_hash: 哈希值字符串
    :return: 如果哈希值有效则返回 True，否则返回 False
    """
    if f_hash is None or not isinstance(f_hash, str) or len(f_hash) != length or not all(
            c in '0123456789abcdef' for c in f_hash.lower()):
        return False
    return True


def verify_api_request(request):
    site_key, turnstile_secret_key = cloudflare_turnstile_conf()
    if site_key is None:
        return 'success'
    token = request.form.get('cf-turnstile-response')
    if not token:
        return ['missing-input-response']
    client_ip = request.headers.get('CF-Connecting-IP') or request.remote_addr
    verify_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = {
        'secret': turnstile_secret_key,
        'response': token,
        'remoteip': client_ip
    }

    try:
        response = requests.post(verify_url, data=data, timeout=10)
        result = response.json()
    except requests.exceptions.RequestException as e:
        print(f"请求失败: {e}")
        return ['internal-error']
    if not result.get('success'):
        error_codes = result.get('error-codes', ['unknown-error'])
        print(f"验证失败，错误代码: {error_codes}")
        return error_codes

    return "success"


def gen_qr_token(input_string, current_time, sys_version, encoding='utf-8'):
    ct = current_time
    rd_num = random.randint(617, 1013)
    input_string = sys_version + ct + input_string + str(rd_num)
    # print(input_string)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode(encoding))
    return sha256_hash.hexdigest()


def is_valid_iso_language_code(iso_code: str) -> bool:
    """
    验证给定的ISO语言代码是否有效

    参数:
        iso_code (str): 要验证的语言代码(如zh-CN, en-US)

    返回:
        bool: 如果代码有效返回True，否则False
    """
    # 所有有效的语言代码集合(基于提供的对照表)
    VALID_LANGUAGE_CODES = {
        'af', 'af-ZA', 'sq', 'sq-AL', 'ar', 'ar-DZ', 'ar-BH', 'ar-EG', 'ar-IQ',
        'ar-JO', 'ar-KW', 'ar-LB', 'ar-LY', 'ar-MA', 'ar-OM', 'ar-QA', 'ar-SA',
        'ar-SY', 'ar-TN', 'ar-AE', 'ar-YE', 'hy', 'hy-AM', 'az', 'az-AZ-Cyrl',
        'az-AZ-Latn', 'eu', 'eu-ES', 'be', 'be-BY', 'bg', 'bg-BG', 'ca', 'ca-ES',
        'zh-HK', 'zh-MO', 'zh-CN', 'zh-CHS', 'zh-SG', 'zh-TW', 'zh-CHT', 'hr',
        'hr-HR', 'cs', 'cs-CZ', 'da', 'da-DK', 'div', 'div-MV', 'nl', 'nl-BE',
        'nl-NL', 'en', 'en-AU', 'en-BZ', 'en-CA', 'en-CB', 'en-IE', 'en-JM',
        'en-NZ', 'en-PH', 'en-ZA', 'en-TT', 'en-GB', 'en-US', 'en-ZW', 'et',
        'et-EE', 'fo', 'fo-FO', 'fa', 'fa-IR', 'fi', 'fi-FI', 'fr', 'fr-BE',
        'fr-CA', 'fr-FR', 'fr-LU', 'fr-MC', 'fr-CH', 'gl', 'gl-ES', 'ka', 'ka-GE',
        'de', 'de-AT', 'de-DE', 'de-LI', 'de-LU', 'de-CH', 'el', 'el-GR', 'gu',
        'gu-IN', 'he', 'he-IL', 'hi', 'hi-IN', 'hu', 'hu-HU', 'is', 'is-IS',
        'id', 'id-ID', 'it', 'it-IT', 'it-CH', 'ja', 'ja-JP', 'kn', 'kn-IN',
        'kk', 'kk-KZ', 'kok', 'kok-IN', 'ko', 'ko-KR', 'ky', 'ky-KZ', 'lv',
        'lv-LV', 'lt', 'lt-LT', 'mk', 'mk-MK', 'ms', 'ms-BN', 'ms-MY', 'mr',
        'mr-IN', 'mn', 'mn-MN', 'no', 'nb-NO', 'nn-NO', 'pl', 'pl-PL', 'pt',
        'pt-BR', 'pt-PT', 'pa', 'pa-IN', 'ro', 'o-RO', 'ru', 'ru-RU', 'sa',
        'sa-IN', 'sr-SP-Cyrl', 'sr-SP-Latn', 'sk', 'sk-SK', 'sl', 'sl-SI', 'es',
        'es-AR', 'es-BO', 'es-CL', 'es-CO', 'es-CR', 'es-DO', 'es-EC', 'es-SV',
        'es-GT', 'es-HN', 'es-MX', 'es-NI', 'es-PA', 'es-PY', 'es-PE', 'es-PR',
        'es-ES', 'es-UY', 'es-VE', 'sw', 'sw-KE', 'sv', 'sv-FI', 'sv-SE', 'syr',
        'syr-SY', 'ta', 'ta-IN', 'tt', 'tt-RU', 'te', 'te-IN', 'th', 'th-TH',
        'tr', 'tr-TR', 'uk', 'uk-UA', 'ur', 'ur-PK', 'uz', 'uz-UZ-Cyrl',
        'uz-UZ-Latn', 'vi', 'vi-VN', 'zh-cn', 'zh-tw', 'zh-hk', 'en-hk', 'en-us',
        'en-gb', 'en-ww', 'en-ca', 'en-au', 'en-ie', 'en-fi', 'fi-fi', 'en-dk',
        'da-dk', 'en-il', 'he-il', 'en-za', 'en-in', 'en-no', 'en-sg', 'en-nz',
        'en-id', 'en-ph', 'en-th', 'en-my', 'en-xa', 'ko-kr', 'ja-jp', 'nl-nl',
        'nl-be', 'pt-pt', 'pt-br', 'fr-fr', 'fr-lu', 'fr-ch', 'fr-be', 'fr-ca',
        'es-la', 'es-es', 'es-ar', 'es-us', 'es-mx', 'es-co', 'es-pr', 'de-de',
        'de-at', 'de-ch', 'ru-ru', 'it-it', 'el-gr', 'no-no', 'hu-hu', 'tr-tr',
        'cs-cz', 'sl-sl', 'pl-pl', 'sv-se', 'es-cl'
    }

    # 检查代码是否在有效集合中
    return iso_code in VALID_LANGUAGE_CODES
