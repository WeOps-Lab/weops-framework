from blueking.component.shortcuts import get_client_by_user
from common.bk_api_utils.cc import BkApiCCUtils
from constants.apps_constants import FILTER_CLASSIFICATIONS
from utils.app_utils import AppUtils
from utils.exceptions import GetDateError


class Menus(object):
    """
    菜单的拆分
    """

    @classmethod
    def get_menus_classification_list(cls):
        """
        查询模型分类 除了主机，数据库，业务拓扑，组织架构
        """
        client = get_client_by_user("admin")
        try:
            classification_list = BkApiCCUtils.search_classifications(client)
        except GetDateError:
            return []

        # remove_list = FILTER_CLASSIFICATIONS + MENUS_REMOVE_CLASSIFICATIONS
        remove_list = FILTER_CLASSIFICATIONS
        result = [i for i in classification_list if i["bk_classification_id"] not in remove_list]

        return result

    @classmethod
    def get_monitor_group_dict(cls):
        """
        获取告警对象组成员 OTHER
        """
        util = AppUtils()
        data = util.class_call(
            "apps.monitor_mgmt.utils.monitor_sql_helper",
            "MonitorSQLClient",
            "execute_fun",
            {},
            {"fun_name": "get_all_other_groups"},
        )
        res = {} if not data else {i["group_id"]: i["group_name"] for i in data}
        return res
