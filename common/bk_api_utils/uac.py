"""统一告警中心接口"""
from common.bk_api_utils.main import ApiManager, logger
from utils import exceptions


class UACApiUtils:
    ABNORMAL = "abnormal"
    CONVERGED = "converged"
    SHIELDED = "shielded"
    DISPATCHED = "dispatched"
    PENDING_EXECUTE = "pending_execute"
    EXECUTING = "executing"
    AUTOORDER_EXECUTING = "autoorder_executing"
    AUTOEXECUTE_EXECUTING = "autoexecute_executing"
    AUTOEXECUTING_FAILURE = "autoexecuting_failure"
    RESTORED = "restored"
    CLOSED = "closed"
    AUTO_CLOSED = "auto_closed"
    AUTOORDER_CLOSED = "autoorder_closed"
    AUTOEXECUTE_CLOSED = "autoexecute_closed"
    STATUS_CHOICES = (
        (ABNORMAL, "未分派"),
        (CONVERGED, "被抑制"),
        (SHIELDED, "被屏蔽"),
        (DISPATCHED, "待响应"),
        (PENDING_EXECUTE, "待审批"),
        (EXECUTING, "手动处理中"),
        (AUTOORDER_EXECUTING, "工单处理中"),
        (AUTOEXECUTE_EXECUTING, "自愈处理中"),
        (AUTOEXECUTING_FAILURE, "自愈处理失败"),
        (RESTORED, "自动恢复"),
        (CLOSED, "手动关闭"),
        (AUTO_CLOSED, "自动关闭"),
        (AUTOORDER_CLOSED, "工单关闭"),
        (AUTOEXECUTE_CLOSED, "自愈关闭"),
    )
    PROCESSING = "processing"
    PROCESSED = "processed"
    UNPROCESSED = "unprocessed"
    PROCESS_STATUS_CHOICES = ((PROCESSING, "处理中"), (PROCESSED, "已处理"), (UNPROCESSED, "未处理"))
    PROCESS_STATUS_MAPPING = {
        PROCESSED: [CLOSED, AUTO_CLOSED, AUTOORDER_CLOSED, AUTOEXECUTE_CLOSED, RESTORED],
        PROCESSING: [EXECUTING, AUTOORDER_EXECUTING, AUTOEXECUTE_EXECUTING, AUTOEXECUTING_FAILURE],
        UNPROCESSED: [ABNORMAL, DISPATCHED, PENDING_EXECUTE],
    }
    QUERY_ACTIVE_LIST = [
        "abnormal",
        "executing",
        "pending_execute",
        "dispatched",
        "autoorder_executing",
        "autoexecute_executing",
        "autoexecuting_failure",
    ]

    REMAIN = "remain"
    WARNING = "warning"
    FATAL = "fatal"
    LEVEL_CHOICES = ((REMAIN, "提醒"), (WARNING, "预警"), (FATAL, "致命"))
    LEVEL_DICT = dict(LEVEL_CHOICES)

    @staticmethod
    def get_dict_list_by_fields(_list, fields):
        """从字典列表过滤字段"""
        fields = fields or []
        if not fields:
            return []
        new_fields_data = []
        for item in _list:
            new_item = {}
            for field in fields:
                new_item[field] = item.get(field)
            new_fields_data.append(new_item)
        return new_fields_data

    @classmethod
    def get_active_alarm(cls, biz_ids):
        """获取大屏告警详情信息"""
        query = {"bk_biz_id": biz_ids, "status": UACApiUtils.QUERY_ACTIVE_LIST}
        actives = ApiManager.uac.get_actives(sort="-alarm_time", query=query)
        actives = actives["data"]
        actives_status_count = UACApiUtils._get_actives_status_count(actives.get("alarm_status_num_count_dict", {}))
        actives_level_count = UACApiUtils._get_actives_level_count(actives.get("items", []))
        abnormal_actives_data = cls.get_dict_list_by_fields(
            actives.get("data", {}).get("items", []),
            ["bk_biz_name", "bk_biz_id", "name", "status_display", "level_display", "alarm_time", "alarm_id"],
        )
        # abnormal_actives_data = UACApiUtils._add_biz_name(abnormal_actives_data, UACApiUtils._get_biz_mapping())
        # 暂时加上排序,后面告警中心排序生效后可取消
        abnormal_actives_data.sort(key=lambda x: x["alarm_time"], reverse=True)

        return {
            "actives_status_count": actives_status_count,
            "actives_level_count": actives_level_count,
            "abnormal_actives_data": abnormal_actives_data,
        }

    @staticmethod
    def _get_actives_status_count(alarm_status_num_count_dict: dict):
        """获取告警状态统计"""
        actives_status_count = [{"key": i, "value": v, "count": 0} for i, v in UACApiUtils.PROCESS_STATUS_CHOICES]
        for process_info in actives_status_count:
            process_status = process_info["key"]
            status_list = UACApiUtils.PROCESS_STATUS_MAPPING[process_status]
            for status, count in alarm_status_num_count_dict.items():
                if status in status_list:
                    process_info["count"] += count
        return actives_status_count

    @staticmethod
    def _get_actives_level_count(items: list):
        """获取告警级别统计"""
        level_count = {i: 0 for i, _ in UACApiUtils.LEVEL_CHOICES}
        for item in items:
            level = item["level"]
            status = item["status"]
            # 只统计状态是未处理的
            if status in UACApiUtils.PROCESS_STATUS_MAPPING[UACApiUtils.UNPROCESSED]:
                level_count[level] += 1
        actives_level_count = [{"key": i, "value": v, "count": level_count[i]} for i, v in UACApiUtils.LEVEL_CHOICES]
        return actives_level_count

    @staticmethod
    def get_active_list(**kwargs):
        """获取所有告警列表"""
        active_alarm_info = ApiManager.uac.get_actives(**kwargs)
        if not active_alarm_info["result"]:
            logger.exception("统一告警中心-get_active_list-查询业务下的活动告警出错, 详情: %s" % active_alarm_info.get("message"))
            raise exceptions.GetDateError("查询业务下的活动告警出错, 详情: %s" % active_alarm_info.get("message"))
        alarm_items = active_alarm_info.get("data").get("items", [])
        alarm_count = active_alarm_info.get("data").get("count", 0)
        return alarm_count, alarm_items

    @staticmethod
    def get_active_detail(url_params: dict):
        active_alarm_detail = ApiManager.uac.get_active_detail(url_params=url_params)
        if not active_alarm_detail["result"]:
            logger.exception("统一告警中心-get_active_detail-查询活动告警详情出错, 详情: %s" % active_alarm_detail.get("message"))
            raise exceptions.GetDateError("查询活动告警详情出错, 详情: %s" % active_alarm_detail.get("message"))
        alarm_detail_data = active_alarm_detail.get("data", [])
        return alarm_detail_data
