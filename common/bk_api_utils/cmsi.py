from blueapps.core.exceptions import ServerBlueException
from utils.app_log import logger


class BkApiCMSIUtils(object):
    """蓝鲸消息管理 CMSI"""

    @staticmethod
    def send_mail(client, **kwargs):
        """发送邮件"""
        resp = client.cmsi.send_mail(kwargs)
        if not resp["result"]:
            logger.exception("消息管理-send_mail-发送邮件出错，详情：%s" % resp.get("message", ""))
            raise ServerBlueException("发送邮件出错，详情：%s" % resp.get("message", ""))
        return resp["result"]
