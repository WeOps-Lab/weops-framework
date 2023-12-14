# -- coding: utf-8 --

# @File : permission.py
# @Time : 2023/7/21 14:24
# @Author : windyzhao
from apps.system_mgmt.casbin_package.permissions import BaseInstPermission


class MonitorPolicyLogInstPermission(BaseInstPermission):
    """
    监控策略-日志
    """

    INSTANCE_TYPE = "监控策略"
    INST_PERMISSION = "manage"
    BASIC_MONITOR_POLICY = "log"

    def get_instance_id(self, request, view):
        if view.action in ["batch_unschedule_event_definitions", "batch_schedule_event_definitions"]:
            return request.data.get("definitionids", [])
        return view.kwargs["definitionId"]

    def instance_type(self, request, view):
        result = f"{self.INSTANCE_TYPE}{self.BASIC_MONITOR_POLICY}"
        return result
