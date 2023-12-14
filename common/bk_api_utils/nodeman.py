from utils import constants, exceptions
from utils.app_log import logger
from utils.decorators import get_all_page_v2


class BKNodeManApiCCUtils(object):
    @staticmethod
    @get_all_page_v2(constants.SEARCH_AGENT_MAX_NUM)
    def get_agent_status_info(client, **kwargs):
        """查询节点管理agent列表"""
        resp = client.nodeman.get_agent_status_info(kwargs)
        if not resp["result"]:
            logger.exception("节点管理-get_agent_status_info-查询节点agent状态列表出错, 详情: %s" % resp["message"])
            raise exceptions.GetDateError("查询节点agent状态列表出错, 详情: %s" % resp["message"])
        count = resp["data"]["total"]
        search_agent_info = resp["data"]["list"]
        return count, search_agent_info

    @staticmethod
    @get_all_page_v2(constants.SEARCH_AGENT_MAX_NUM)
    def get_nodeman_host_list(client, **kwargs):
        """查询节点管理主机列表"""
        resp = client.nodeman.get_agent_status_info(kwargs)
        if not resp["result"]:
            logger.exception("节点管理-get_nodeman_host_list-查询节点管理主机列表出错, 详情: %s" % resp["message"])
            raise exceptions.GetDateError("查询节点管理主机列表出错, 详情: %s" % resp["message"])
        count = resp["data"]["total"]
        search_agent_info = resp["data"]["list"]
        return count, search_agent_info

    @staticmethod
    def action_agent(client, **kwargs):
        """操作主机agent"""
        resp = client.nodeman.action_agent(kwargs)
        if not resp["result"]:
            logger.exception("节点管理-action_agent-操作主机agent出错，详情：%s" % resp["message"])
            raise exceptions.GetDateError("操作主机agent出错，详情：%s" % resp["message"])
        return resp["data"]

    @staticmethod
    def get_agent_action_detail(client, **kwargs):
        """查询操作详情"""
        resp = client.nodeman.get_agent_action_detail(kwargs)
        if not resp["result"]:
            logger.exception("节点管理-get_agent_action_detail-查询操作详情出错，详情：%s" % resp["message"])
            raise exceptions.GetDateError("查询操作详情出错，详情：%s" % resp["message"])
        return resp["data"]

    @staticmethod
    def get_agent_cation_log(client, **kwargs):
        """查询操作执行日志"""
        resp = client.nodeman.get_agent_cation_log(kwargs)
        if not resp["result"]:
            logger.exception("节点管理-get_agent_cation_log-查询操作执行日志出错，详情：%s" % resp["message"])
            raise exceptions.GetDateError("查询操作执行日志出错，详情：%s" % resp["message"])
        return resp["data"]

    @staticmethod
    def get_ap(client, **kwargs):
        """查询接入点列表"""
        resp = client.nodeman.get_ap(kwargs)
        if not resp["result"]:
            logger.exception("节点管理-get_ap-查询接入点列表出错，详情：%s" % resp["message"])
            raise exceptions.GetDateError("查询接入点列表出错，详情：%s" % resp["message"])
        return resp["data"]

    @staticmethod
    def get_cloud(client, **kwargs):
        """查询云区域"""
        resp = client.nodeman.gent_cloud(kwargs)
        if not resp["result"]:
            logger.exception("节点管理-get_cloud-查询云区域出错，详情：%s" % resp["message"])
            raise exceptions.GetDateError("查询云区域出错，详情：%s" % resp["message"])
        return resp["data"]
