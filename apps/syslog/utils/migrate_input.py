from apps.syslog.constants import LOCAL_INPUT
from apps.syslog.utils.api import graylog_api
from blueapps.core.exceptions import ServerBlueException
from utils.app_log import logger


def init_local_log_input(**kwargs):
    try:
        imputs = graylog_api.search_inputs()
        if not imputs["result"]:
            msg = f"错误类型{imputs.get('type')}，详情{imputs.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        inputs_set = {f"{i['title']}-{i['type']}-{i['global']}" for i in imputs["data"]["inputs"]}

        if f"{LOCAL_INPUT['title']}-{LOCAL_INPUT['type']}-{LOCAL_INPUT['global']}" not in inputs_set:
            resp = graylog_api.create_inputs(json=LOCAL_INPUT)
            if not resp["result"]:
                msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
                raise ServerBlueException(f"查询失败，详情：{msg}")

    except Exception as e:
        logger.exception(getattr(e, "message", e))
