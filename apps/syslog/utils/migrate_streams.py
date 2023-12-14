from apps.syslog.constants import PAGE_INFO
from apps.syslog.models import Stream
from apps.syslog.utils.api import graylog_api
from utils.app_log import logger


def init_streams(**kwargs):
    """将graylog的数据流同步到库，过滤所有事件、系统事件"""
    try:

        resp = graylog_api.get_streams(params=PAGE_INFO)
        stream_set = set(Stream.objects.all().values_list("id", flat=True))
        stream_set.update({"000000000000000000000002", "000000000000000000000003"})  # 所有事件ID、系统事件ID
        add_streams = [
            Stream(id=i["id"], title=i["title"])
            for i in resp["data"]["streams"]
            if i["id"] not in stream_set and i["title"] not in {"所有事件", "系统事件"}
        ]
        graylog_stream_set = {i["id"] for i in resp["data"]["streams"]}
        delete_stream_set = stream_set - graylog_stream_set
        Stream.objects.filter(id__in=delete_stream_set).delete()  # 删除不存在的数据流
        Stream.objects.bulk_create(add_streams, batch_size=100)  # 批量插入新增的数据流

    except Exception as e:
        logger.exception(getattr(e, "message", e))
