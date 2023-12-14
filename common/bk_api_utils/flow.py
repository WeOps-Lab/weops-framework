"""运维流程管理接口"""
from common.bk_api_utils.main import ApiManager
from utils import constants, exceptions
from utils.app_log import logger
from utils.decorators import get_all_page_v2


class FlowApiUtils:
    VIEW_TYPE_MAPPING = {
        "my_todo": "我的待办",
        "my_created": "我的申请",
        "my_draft": "我的草稿",
        "my_attention": "我的关注",
        "my_history": "我的历史单",
    }

    @staticmethod
    @get_all_page_v2(constants.SEARCH_WORK_ORDER_MAX_NUM)
    def get_tickets(username, **kwargs):
        """获取工单"""
        resp = ApiManager.flow.over_get_tickets(username=username, **kwargs)
        if not resp["result"]:
            logger.exception("运维流程管理-get_tickets-获取工单出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("运维流程管理-获取工单出错, 详情: %s" % resp.get("message", ""))
        order_data = resp["data"].get("items", [])
        count = resp["data"].get("count", 0)
        return count, order_data
