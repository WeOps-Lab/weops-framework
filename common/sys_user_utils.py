# -- coding: utf-8 --

# @File : sys_user_utils.py
# @Time : 2023/2/6 11:26
# @Author : windyzhao
from django.core.cache import cache

from constants.apps_constants import USER_CACHE_KEY
from utils.app_log import logger
from utils.app_utils import AppUtils

SysUser = AppUtils.get_model("apps.system_mgmt.models", "SysUser")


def user_cache():
    """
    初始化时，加载用户缓存
    """
    cache_data = cache.get(USER_CACHE_KEY)
    if cache_data:
        return cache_data
    logger.info("==初始化用户中英名称缓存==")
    data = SysUser.objects.all().values("bk_username", "chname")
    data = {i["bk_username"]: i["chname"] for i in data}
    cache.set(USER_CACHE_KEY, data, 60 * 60 * 24)
    logger.info("==用户中英名称缓存初始化完成==")

    return data


def bk_username_to_username(bk_username_dict, data=None):
    """
    转换用户名
    bk_username_list: ["admin,windyzhao", "windyzhao"]
    """
    try:
        result = {}
        if not bk_username_dict:
            return result

        if data is None:
            data = user_cache()

        for field, bk_usernames in bk_username_dict.items():
            if not bk_usernames:
                result[field] = ""
                continue

            bk_username_chname = []
            bk_username = bk_usernames.split(",")
            for _bk_username in bk_username:
                bk_username_chname.append("{}({})".format(_bk_username, data.get(_bk_username, "")))

            result[field] = ",".join(bk_username_chname)

        return result

    except Exception as err:
        logger.exception("转换用户名失败！error={}".format(err))
        return bk_username_dict
