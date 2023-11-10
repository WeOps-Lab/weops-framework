# -- coding: utf-8 --

# @File : weops_proxy.py
# @Time : 2023/1/11 11:20
# @Author : windyzhao
import os

from weopsproxy import WeOpsProxyClient

from utils.app_log import logger

# WeOpsProxyClient的环境变量


class ProxyClient(object):
    """
    proxy 的 client
    """

    def __new__(cls, *args, **kwargs):
        WEOPS_PROXY_CLIENT_HOST = os.getenv("BKAPP_WEOPS_PROXY_CLIENT_HOST", "proxy.weops.com")
        WEOPS_PROXY_CLIENT_PORT = os.getenv("BKAPP_WEOPS_PROXY_CLIENT_PORT", "80")
        client = WeOpsProxyClient(consul_host=WEOPS_PROXY_CLIENT_HOST, consul_port=int(WEOPS_PROXY_CLIENT_PORT))
        return client


proxy_client = ProxyClient()


def get_access_point():
    """
    获取接入点
    """
    try:
        res = proxy_client.get_access_points()
    except Exception as err:
        logger.exception("调用接入点失败！error={}".format(err))
        res = []

    return res


def get_first_access_point():
    """
    获取第一个接入点
    """
    res = get_access_point()
    if not res:
        raise Exception("查询不到接入点！请联系管理员！")
    return res[0]
