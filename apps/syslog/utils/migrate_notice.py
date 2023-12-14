import uuid

from apps.syslog.constants import ALARM_API, ALARM_SECRET, COLLECTORS, NOTICE_NAME, NOTICE_TYPE
from apps.syslog.utils.api import graylog_api
from blueapps.core.exceptions import ServerBlueException
from utils.app_log import logger


def get_notifications():
    resp = graylog_api.get_notifications(params=dict(query=NOTICE_NAME))
    if not resp["result"]:
        msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
        raise ServerBlueException(f"查询失败，详情：{msg}")
    return resp["data"]["notifications"]


def create_notifications(**kwargs):
    resp = graylog_api.create_notifications(**kwargs)
    if not resp["result"]:
        msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
        raise ServerBlueException(f"执行失败，详情：{msg}")


def update_notifications(**kwargs):
    resp = graylog_api.update_notifications(**kwargs)
    if not resp["result"]:
        msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
        raise ServerBlueException(f"执行失败，详情：{msg}")


def migrate_notice():
    notifications = get_notifications()
    data = {
        "title": NOTICE_NAME,
        "description": "",
        "config": {"url": ALARM_API, "secret": ALARM_SECRET, "type": NOTICE_TYPE},
    }
    if len(notifications) == 0:
        create_notifications(json=data)
    else:
        data.update(id=notifications[0]["id"])
        update_notifications(url_param_dict=dict(notificationId=data["id"]), json=data)


def get_urlwhitelist():
    resp = graylog_api.get_urlwhitelist()
    if not resp["result"]:
        msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
        raise ServerBlueException(f"查询失败，详情：{msg}")
    return resp["data"]


def update_urlwhitelist(**kwargs):
    resp = graylog_api.update_urlwhitelist(**kwargs)
    if not resp["result"]:
        msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
        raise ServerBlueException(f"执行失败，详情：{msg}")


def migrate_urlwhitelist():
    urlwhitelist = get_urlwhitelist()
    if ALARM_API not in {i["value"] for i in urlwhitelist["entries"]}:
        urlwhitelist["entries"].append(
            {"id": str(uuid.uuid4()), "type": "literal", "title": f"{NOTICE_NAME}-api", "value": ALARM_API}
        )
        update_urlwhitelist(json=urlwhitelist)


def init_migrate_notice(**kwargs):
    try:
        logger.info("初始化日志告警通知！")

        # 初始化告警通知api白名单
        migrate_urlwhitelist()
        # 初始化告警通知
        migrate_notice()
    except Exception as e:
        logger.error(getattr(e, "message", e))


def init_delete_collectors():
    """
    删除多余的nxlog
    """
    result = graylog_api.get_collectors_summary(params={"page": 1, "per_page": 10, "query": "nxlog"})
    if not result["result"]:
        logger.info("graylog初始化删除nxlog采集器失败！resp={}".format(result))
        return

    for collector in result["data"]["collectors"]:
        if collector["name"] == "nxlog":
            resp = graylog_api.delete_collectors(url_param_dict={"id": collector["id"]})
            logger.info("初始化时删除nxlog. id={}, resp={}".format(collector["id"], resp))

    logger.info("graylog初始化删除nxlog采集器完成")


def init_create_collectors():
    """
    内置采集器
    """
    result = graylog_api.get_collectors_summary(params={"page": 1, "per_page": 99999, "query": ""})
    if not result["result"]:
        logger.info("graylog内置采集器失败！resp={}".format(result))
        return

    name_set = {i["name"] for i in result["data"]["collectors"]}

    for collector in COLLECTORS:
        if collector["name"] in name_set:
            continue
        resp = graylog_api.create_collectors(json=collector)
        if not resp["result"]:
            logger.warning("内置采集器【{}】失败！resp={}".format(collector["name"], resp))

    logger.info("graylog内置采集器完成")


def init_syslog(**kwargs):
    try:
        init_create_collectors()
        init_delete_collectors()
    except Exception as e:
        logger.exception(e)
