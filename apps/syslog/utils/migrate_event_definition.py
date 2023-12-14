from apps.syslog.constants import PAGE_INFO
from apps.syslog.models import AlarmStrategy
from apps.syslog.utils.api import graylog_api
from blueapps.core.exceptions import ServerBlueException
from utils.app_log import logger


def init_syslog_event_definitions(**kwargs):
    try:
        resp = graylog_api.get_event_definitions(params=PAGE_INFO)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")

        scheduler_map = resp["data"]["context"]["scheduler"]
        title_map = {i["id"]: i["title"] for i in resp["data"]["event_definitions"]}

        graylog_set = {i["id"] for i in resp["data"]["event_definitions"]}
        db_set = set(AlarmStrategy.objects.all().values_list("event_definition_id", flat=True))

        update_set = graylog_set & db_set
        delete_set = db_set - graylog_set

        update_objs = AlarmStrategy.objects.filter(event_definition_id__in=update_set)
        for obj in update_objs:
            obj.title = title_map[obj.event_definition_id]
            obj.is_scheduled = scheduler_map[obj.event_definition_id]["is_scheduled"]

        AlarmStrategy.objects.bulk_update(update_objs, ["title", "is_scheduled"], batch_size=200)

        AlarmStrategy.objects.filter(event_definition_id__in=delete_set).delete()

    except Exception as e:
        logger.exception(getattr(e, "message", e))
