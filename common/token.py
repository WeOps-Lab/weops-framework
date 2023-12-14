from django.core.cache import cache

from utils.app_log import logger
from utils.token import generate_bk_token, set_bk_token_to_open_pass_db


def set_bk_token_to_cache(bk_token):
    # 两个小时自动过期
    cache.set("bk_token", bk_token, 60 * 60 * 2)


def get_bk_token():
    bk_token = cache.get("bk_token")
    if not bk_token:
        bk_token = set_bk_token()
    return bk_token


def set_bk_token():
    # 生成token
    bk_token, expire_time = generate_bk_token()
    # bk_token为空时，不进行存库和缓存操作
    if not bk_token:
        logger.warning("bk_token 初始化设置失败！")
        return None
    # token入库
    set_bk_token_to_open_pass_db(bk_token, expire_time)
    # token放入缓存
    set_bk_token_to_cache(bk_token)

    return bk_token
