from utils import exceptions
from utils.app_log import logger


class BKUserApiCCUtils(object):
    @staticmethod
    def list_users(client, **kwargs):
        resp = client.usermanage.list_users(kwargs)
        if not resp["result"]:
            logger.exception("用户管理-list_users-查询用户列表出错, 详情: %s" % resp["message"])
            raise exceptions.GetDateError("查询用户列表出错, 详情: %s" % resp["message"])
        count = resp["data"]["count"]
        search_object_instances = resp["data"]["results"]
        return count, search_object_instances

    @staticmethod
    def retrieve_user(client, **kwargs):
        resp = client.usermanage.retrieve_user(kwargs)
        if not resp["result"]:
            logger.exception("用户管理-retrieve_user-查询单用户出错, 详情: %s" % resp["message"])
            raise exceptions.GetDateError("查询单用户出错, 详情: %s" % resp["message"])
        data = resp["data"]
        return data
