from blueking.component.client import BaseComponentClient
from common.performance import fn_performance
from utils import exceptions
from utils.app_log import logger


class BkApiGSEUtils(object):
    """蓝鲸管控平台接口管理"""

    @staticmethod
    def _parse_host(ip_clouds):
        """解析主机的ip和cloud"""
        host = []
        if ip_clouds:
            host = [dict(bk_cloud_id=int(ip_cloud.split(":")[0]), ip=ip_cloud.split(":")[1]) for ip_cloud in ip_clouds]
        return host

    @staticmethod
    @fn_performance()
    def get_agent_status(client: BaseComponentClient, ip_clouds, **kwargs):
        """获取主机的ip的agent状态"""
        hosts = BkApiGSEUtils._parse_host(ip_clouds)
        if not hosts:
            return {}
        kwargs.update(hosts=hosts)
        resp = client.gse.get_agent_status(kwargs)
        if not resp["result"]:
            logger.exception("管控平台-get_agent_status-获取主机的ip的agent状态出错, 详情: %s" % resp["message"])
            raise exceptions.GetDateError("获取主机的ip的agent状态出错, 详情: %s" % resp["message"])

        agent_status = resp["data"]
        return agent_status

    @staticmethod
    def get_agent_info(client: BaseComponentClient, ip_clouds, **kwargs):
        """获取主机的ip的agent心跳"""
        hosts = BkApiGSEUtils._parse_host(ip_clouds)
        if not hosts:
            return {}
        kwargs.update(hosts=hosts)
        resp = client.gse.get_agent_info(kwargs)
        if not resp["result"]:
            logger.exception("管控平台-get_agent_info-获取主机的ip的agent心跳出错, 详情: %s" % resp["message"])
            raise exceptions.GetDateError("获取主机的ip的agent心跳出错, 详情: %s" % resp["message"])
        agent_info = resp["data"]
        return agent_info

    @staticmethod
    def get_agent_status_new(client: BaseComponentClient, hosts):
        """获取主机的ip的agent心跳"""
        if not hosts:
            return {}
        resp = client.gse.get_agent_status({"hosts": hosts})
        if not resp["result"]:
            logger.exception("管控平台-get_agent_status_new-获取主机的ip的agent心跳出错, 详情: %s" % resp["message"])
            raise exceptions.GetDateError("获取主机的ip的agent心跳出错, 详情: %s" % resp["message"])
        agent_info = resp["data"]
        return agent_info
