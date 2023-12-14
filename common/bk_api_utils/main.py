import json
import logging
import os
from urllib.parse import urljoin

import requests
from django.conf import settings

from common.performance import fn_performance
from common.weops_proxy import get_first_access_point
from utils.exceptions import CustomApiException
from utils.tools import combomethod

logger = logging.getLogger("api")


class SiteConfig(object):
    WEOPS = os.getenv("BKAPP_WEOPS_SAAS_APP_ID", "weops_saas")
    UAC = os.getenv("BKAPP_UAC_SAAS_APP_ID", "cw_uac_saas")  # 统一告警中心
    MONITOR = os.getenv("BKAPP_MONITOR_SAAS_APP_ID", "monitorcenter_saas")  # 统一监控中心
    FLOW = os.getenv("BKAPP_FLOW_SAAS_APP_ID", "bk_itsm")  # 流程管理
    PATCH = os.getenv("BKAPP_PATCH_SAAS_APP_ID", "patch_install_saas")  # 一键补丁安装
    OPS = os.getenv("BKAPP_OPS_SAAS_APP_ID", "ops-digital_saas")  # 数字运营中心
    AUTOMATION = os.getenv("BKAPP_AUTOMATION_SAAS_APP_ID", "cc-automation_saas")  # 配置发现
    BK_MONITOR = os.getenv("BKAPP_BK_MONITOR_SAAS_APP_ID", "bk_monitorv3")  # 监控平台
    BK_SOPS = os.getenv("BKAPP_SOPS_APP_ID", "bk_sops")  # 标准运维
    BK_PATCH_MGMT = os.getenv("BKAPP_PATCH_MGMT_APP_ID", "patch-mgmt")  # 一键补丁
    AUTO_MATE = os.getenv("AUTO_MATE", "auto-mate")
    NODE_MAN = os.getenv("BKAPP_NODE_MAN_APP_ID", "bk_nodeman")  # 节点管理


class LinkConfig(object):
    config_args_key = "config_args"
    config_kwargs_key = "config_kwargs"

    @combomethod
    def add_config(cls, *args, **kwargs):
        setattr(cls, cls.config_args_key, args)
        setattr(cls, cls.config_kwargs_key, kwargs)
        for k, v in cls.__dict__.items():
            if isinstance(v, (BaseAPIOperation, ApiDefine)):
                setattr(v, cls.config_args_key, args)
                setattr(v, cls.config_kwargs_key, kwargs)
                v.has_config = True
        setattr(cls, "has_config", True)
        return cls

    def __getattribute__(self, item):
        value = super().__getattribute__(item)
        if not getattr(value, "has_config", False) and isinstance(value, (BaseAPIOperation, ApiDefine)):
            value.add_config(*getattr(self, self.config_args_key, ()), **getattr(self, self.config_kwargs_key, {}))
        return value


class ApiDefine(LinkConfig):
    HTTP_STATUS_OK_LIST = [200, 201, 204]

    def __init__(self, site, path, method, description="", is_json=True, is_file=False):
        host = settings.BK_PAAS_INNER_HOST
        # Do not use join, use '+' because path may starts with '/'
        self.headers = {"AUTH_APP": "WEOPS"}  # CSRF认证取消
        self.site = site
        self.host = host.rstrip("/")
        self.path = path
        self.url = ""
        self.method = method
        self.description = description
        self.is_json = is_json
        self.is_file = is_file

    @property
    def total_url(self):
        if os.getenv("BK_ENV") == "testing" and self.site in [SiteConfig.UAC, SiteConfig.MONITOR, SiteConfig.FLOW]:
            env_ = "t"
        else:
            env_ = "o"
        path = f"/{env_}/{self.site}{self.path}"
        return urljoin(self.host, path)

    def __call__(self, **kwargs):
        if kwargs.get("headers"):
            kwargs["headers"].update(self.headers)
        else:
            kwargs["headers"] = self.headers
        return self._call(**kwargs)

    def http_request(self, total_url, headers, cookies, params, data):
        try:
            if self.is_file:
                resp = requests.request(
                    self.method, total_url, headers=headers, cookies=cookies, params=params, files=data, verify=False
                )
            else:
                resp = requests.request(
                    self.method, total_url, headers=headers, cookies=cookies, params=params, json=data, verify=False
                )
        except Exception as e:
            raise CustomApiException(self, f"请求地址[{total_url}]失败，请求方式[{self.method}]，异常原因[{e}]")
        # Parse result
        if resp.status_code not in self.HTTP_STATUS_OK_LIST:
            logger.exception(
                "请求{}返回异常，请求参数:params【{}】，body【{}】, 状态码: {}".format(total_url, params, data, resp.status_code)
            )
        try:
            return resp.json() if self.is_json else resp
        except Exception:
            msg = f"""请求参数：params【{params}】，body【{data}】
        失败原因：返回数据无法json化"""
            raise CustomApiException(self, msg, resp=resp)

    def http_get(self, headers, cookies, params, total_url):
        params = {i: json.dumps(v) if isinstance(v, (dict, list)) else v for i, v in params.items()}
        return self.http_request(total_url, headers, cookies, params, {})

    def http_post(self, headers, cookies, params, total_url):
        data = params
        params = None
        return self.http_request(total_url, headers, cookies, params, data)

    @fn_performance
    def _call(self, **kwargs):
        url_params = kwargs.pop("url_params", {})
        headers = kwargs.pop("headers", {})
        headers.update(self.headers)
        cookies = kwargs.pop("cookies", {})
        params = {}
        params.update(kwargs)
        total_url = self.total_url.format(**url_params)
        http_map = {
            "GET": self.http_get,
            "POST": self.http_post,
            "PUT": self.http_post,
            "PATCH": self.http_post,
            "DELETE": self.http_post,
        }
        fun = http_map.get(self.method, self.http_get)
        return fun(headers, cookies, params, total_url)  # noqa


class OpenApiDefine(ApiDefine):
    def __init__(self, path, method, site="", description="", is_json=True, is_file=False):
        super().__init__(site, path, method, description, is_json, is_file)

    def __call__(self, **kwargs):
        result = super(OpenApiDefine, self).__call__(**kwargs)
        data = result.get("data", {})
        return data

    @property
    def total_url(self):
        url = self.config_kwargs.get("url")

        if settings.DEBUG:
            open_port = 8081
            open_host = "127.0.0.1"
        else:
            if self.config_kwargs:
                open_port = self.config_kwargs.get("port", 8081)
                open_host = self.config_kwargs.get("path", "127.0.0.1")
            else:
                access_point = get_first_access_point()
                open_host = access_point["ip"]
                open_port = access_point.get("port", 8081)

        if not url:
            url = "http://{}:{}".format(open_host, open_port)
        path = urljoin(url, self.path)
        return path


class WebApiDefine(ApiDefine):
    def __init__(self, site, path, method, description="", is_json=True, is_file=False):
        super(WebApiDefine, self).__init__(site, path, method, description, is_json, is_file)


class BaseAPIOperation(LinkConfig):
    def __init__(self):
        # self.get_demo = ApiDefine(self.SITE, '/test_get/', 'get', description=
        # "查询用户列表")
        self.site = None


class UacApiOperation(BaseAPIOperation):
    def __init__(self):
        super().__init__()
        self.site = SiteConfig.UAC
        self.get_users = ApiDefine(self.site, "/alarm/api/user/", "GET", description="查询用户列表")
        self.create_user = ApiDefine(self.site, "/alarm/api/user/", "POST", description="创建用户")
        self.delete_user = ApiDefine(self.site, "/alarm/api/user/{user_id}/", "DELETE", description="删除用户")
        self.update_user = ApiDefine(self.site, "/alarm/api/user/{user_id}/", "PUT", description="修改用户")
        self.patch_update_user = ApiDefine(self.site, "/alarm/api/user/{user_id}/", "PATCH", description="局部修改用户")
        self.get_groups = ApiDefine(self.site, "/alarm/api/group/", "GET", description="查看用户组")
        self.update_group = ApiDefine(self.site, "/alarm/api/group/{group_id}/", "PUT", description="更新用户组")
        self.get_group_detail = ApiDefine(self.site, "/alarm/api/group/{group_id}/", "GET", description="查询用户详情")
        self.get_actives = ApiDefine(self.site, "/alarm/api/active/list/", "GET", description="查询活动告警列表")
        # 告警查询接口
        self.search_my_alarm_list = WebApiDefine(self.site, "/alarm/mine/list/", "GET", description="查询我的告警列表")
        self.search_actives = WebApiDefine(self.site, "/alarm/active/list/", "GET", "查询活动告警列表")
        self.search_active_count = WebApiDefine(self.site, "/alarm/active/count/", "POST", "查询活动告警数目")
        self.search_history_alarm_list = WebApiDefine(self.site, "/alarm/retrieval/weops_history/", "GET", "查询历史告警列表")
        # 认领接口
        self.only_response = WebApiDefine(self.site, "/alarm/operation/{alarm_id}/only_response/", "POST", "仅响应")
        self.auto_execute = WebApiDefine(self.site, "/alarm/operation/{alarm_id}/auto_execute/", "POST", "自愈处理")
        self.get_execute_list = WebApiDefine(self.site, "/system/mgmt/autoexecute/list/", "GET", "获取自愈流程")
        self.get_execute_params = WebApiDefine(self.site, "/system/mgmt/template/info/{biz_id}/", "GET", "获取流程参数")
        self.set_execute_status = WebApiDefine(self.site, "/system/mgmt/autoexecute/{execute_id}/", "PATCH", "更改流程状态")
        self.delete_execute = WebApiDefine(self.site, "/system/mgmt/autoexecute/{execute_id}/", "DELETE", "删除流程")
        self.modify_execute = WebApiDefine(self.site, "/system/mgmt/autoexecute/{execute_id}/", "PUT", "更改流程")
        self.add_execute = WebApiDefine(self.site, "/system/mgmt/autoexecute/list/", "POST", "创建流程")
        self.sync_user = WebApiDefine(self.site, "/system/mgmt/syncuser/", "PUT", "同步用户")
        self.get_execute_template_list = WebApiDefine(
            self.site, "/system/mgmt/template/list/{biz_id}/", "GET", "获取流程模板列表"
        )
        # 分派接口
        self.transmit = WebApiDefine(self.site, "/alarm/operation/{alarm_id}/transmit/", "POST", "分派")
        # 操作接口
        self.approval = WebApiDefine(self.site, "/alarm/operation/{alarm_id}/approval/", "POST", "审批")
        self.close = WebApiDefine(self.site, "/alarm/operation/{alarm_id}/close/", "POST", "关闭")
        # 告警详情
        self.get_active_detail = ApiDefine(self.site, "/alarm/api/active/{alarm_id}/", "GET", description="查询告警详情")
        self.metric = WebApiDefine(self.site, "/alarm/active/{alarm_id}/metric/", "GET", "指标视图")
        self.lifecycle = WebApiDefine(self.site, "/alarm/lifecycle/{alarm_id}/", "GET", "流转记录")
        self.get_obj_alarm_count = WebApiDefine(self.site, "/alarm/report/cmdb/{obj_id}/info/", "GET", "统计告警次数")
        self.get_monitor_group = WebApiDefine(self.site, "/system/mgmt/alarmobjectgroup/", "GET", "获取告警对象组")
        self.create_monitor_group = WebApiDefine(self.site, "/system/mgmt/alarmobjectgroup/", "POST", "创建告警对象组")
        self.update_monitor_obj = WebApiDefine(self.site, "/system/mgmt/alarmobject/", "PUT", "修改告警对象")
        self.create_monitor_obj = WebApiDefine(self.site, "/system/mgmt/alarmobject/", "POST", "修改告警对象")
        self.get_biz_info = WebApiDefine(self.site, "/alarm/report/cmdb/bizs/info/", "GET", "获取业务告警数据")
        self.get_alarm_count = ApiDefine(self.site, "/alarm/get_alarm_count/", "POST", "获取告警数目汇总")
        self.batch_create_alarm_group = ApiDefine(
            self.site, "/alarm/api/batch_create_alarm_group/", "POST", description="批量创建监控对象组"
        )
        self.batch_create_alarm_obj = ApiDefine(
            self.site, "/alarm/api/batch_create_alarm_obj/", "POST", description="批量创建监控对象"
        )
        self.create_alarm_object = WebApiDefine(
            self.site, "/alarm/api/create_alarm_object/", "POST", description="创建监控对象"
        )
        self.modify_alarm_object = WebApiDefine(
            self.site, "/alarm/api/modify_alarm_object/", "POST", description="修改监控对象"
        )
        self.delete_alarm_object = WebApiDefine(
            self.site, "/alarm/api/delete_alarm_object/", "POST", description="删除监控对象"
        )
        self.search_obj_alarms_by_inst_ids = WebApiDefine(
            self.site, "/alarm/open_api/search_obj_alarms_by_inst_ids/", "POST", description="查询模型实例告警信息"
        )
        self.create_alarmcenter_data = WebApiDefine(self.site, "/system/mgmt/group/", "POST", description="新增告警中心用户组")
        self.sync_alarmcenter_user = WebApiDefine(self.site, "/system/mgmt/syncuser/", "PUT", description="同步告警中心用户")
        self.set_alarm_group_user = WebApiDefine(
            self.site, "/system/mgmt/group/{group_id}/", "PUT", description="修改告警中心用户组的用户"
        )
        self.accord_name_search_info = WebApiDefine(
            self.site, "/system/mgmt/group/accord_name_search_info/", "POST", description="通过用户组名拿到用户组信息"
        )
        self.accord_name_search_userid = WebApiDefine(
            self.site, "/system/mgmt/group/accord_name_search_userid/", "POST", description="通过用户名拿到用户id"
        )
        self.sync_alarm_center_group = WebApiDefine(
            self.site, "/system/mgmt/group/sync_system_group/", "POST", description="将角色同步到告警中心"
        )


class MonitorApiOperation(BaseAPIOperation):
    def __init__(self):
        super().__init__()
        self.site = SiteConfig.MONITOR
        self.get_users = ApiDefine(self.site, "/open_api/get_exist_user/", "GET", description="获取已添加的用户列表")
        self.create_user = ApiDefine(self.site, "/open_api/create_user/", "POST", description="创建用户")
        self.delete_user = ApiDefine(self.site, "/open_api/delete_user/", "POST", description="删除用户")
        self.get_all_user_group = ApiDefine(self.site, "/open_api/get_all_user_group/", "GET", description="获取用户组列表")
        self.update_user_group = ApiDefine(self.site, "/open_api/update_user_group/", "POST", description="修改用户组")
        self.search_topology_graph_by_level = ApiDefine(
            self.site, "/open_api/search_topology_graph_by_level/", "GET", description="根据级数查询拓扑"
        )
        self.get_application_overview = ApiDefine(
            self.site, "/open_api/get_application_overview/", "GET", description="业务告警汇总"
        )
        self.metric_points = WebApiDefine(self.site, "/event/{event_id}/metric_points/", "PUT", description="指标视图")
        self.event_detail = WebApiDefine(self.site, "/event/{event_id}/", "GET", description="告警详情")
        self.search_monitor_obj_list = WebApiDefine(
            self.site, "/monitor_view/get_monitor_obj_list/", "GET", description="获取监控对象列表"
        )
        self.metric_list = WebApiDefine(self.site, "/monitor/{obj_id}/metric_list/", "GET", description="获取指标列表")
        self.cloud_metric_list = WebApiDefine(
            self.site, "/cloud/clouddefine/cloud_resource_metrics/", "GET", description="获取云指标列表"
        )
        self.get_monitor_obj_list = WebApiDefine(
            self.site, "/monitor_view/get_monitor_obj_list/", "GET", description="获取监控对象列表"
        )
        self.get_monitor_metric_point = WebApiDefine(
            self.site, "/monitor_view/get_monitor_metric_point/", "GET", description="获取单个指标视图"
        )
        self.get_monitor_inst_detail = WebApiDefine(
            self.site, "/monitor_view/get_monitor_obj/", "GET", description="获取监控对象详情"
        )

        self.get_process_task_list_by_inst = WebApiDefine(
            self.site, "/monitor_view/get_process_task_list_by_inst/", "GET", description="获取实例进程列表"
        )
        self.get_monitor_metric = WebApiDefine(
            self.site, "/monitor_view/get_monitor_metric/", "GET", description="获取对象实例指标列表"
        )

        self.get_tab_by_monitor_group_id = WebApiDefine(
            self.site, "/monitor_view/get_tab_by_monitor_group_id/", "GET", description="获取监控对象组下的监控对象"
        )
        self.task_graph_and_map = WebApiDefine(
            self.site, "/uptime_check_task/task_graph_and_map/", "POST", description="获取拨测任务视图"
        )

        self.get_monitor_group = WebApiDefine(self.site, "/monitor_group/", "GET", description="获取监控对象组")
        self.create_monitor_group = WebApiDefine(self.site, "/monitor_group/", "POST", description="创建监控对象组")
        self.get_monitor_obj = WebApiDefine(self.site, "/monitor/", "GET", description="获取监控对象")
        self.create_monitor_obj = WebApiDefine(self.site, "/monitor/", "POST", description="创建监控对象")
        self.update_monitor_obj = WebApiDefine(self.site, "/monitor/{obj_id}/", "PUT", description="修改监控对象")
        self.search_task_list = WebApiDefine(self.site, "/task1/", "GET", description="获取采集上报任务")

        self.get_cloud_auth_fields = WebApiDefine(
            self.site, "/cloud/clouddefine/cloud_auth_fields/", "GET", description="获取虚拟化采集字段"
        )
        self.get_cloud_collect_hosts = WebApiDefine(
            self.site, "/cloud/monitormgmt/clouds/bk_hosts/", "GET", description="获取采集主机"
        )

        self.search_vm_task_list = WebApiDefine(
            self.site, "/cloud/monitormgmt/clouds/", "GET", description="获取虚拟化采集上报任务"
        )
        self.change_vm_task_status = WebApiDefine(
            self.site, "/cloud/monitormgmt/clouds/{task_id}/", "PATCH", description="修改虚拟化采集任务状态"
        )
        self.update_vm_task = WebApiDefine(
            self.site, "/cloud/monitormgmt/clouds/{task_id}/", "PUT", description="修改虚拟化采集任务"
        )
        self.delete_vm_task = WebApiDefine(
            self.site, "/cloud/monitormgmt/clouds/{task_id}/", "DELETE", description="删除虚拟化采集任务"
        )

        self.auto_discovery_plug_retry = WebApiDefine(
            self.site, "/cloud/monitormgmt/clouds/{task_id}/auto_discovery_plug_retry/", "PUT", description="自动发现重试"
        )
        self.collection_plug_retry = WebApiDefine(
            self.site, "/cloud/monitormgmt/clouds/{task_id}/collection_plug_retry/", "PUT", description="采集重试"
        )
        self.create_vm_task = WebApiDefine(self.site, "/cloud/monitormgmt/clouds/", "POST", description="创建虚拟化采集任务")

        # 网站监测
        self.search_uptimecheck_list = WebApiDefine(self.site, "/uptime_check_task/", "GET", description="获取网站监测任务列表")
        self.get_uptimecheck_detail = WebApiDefine(
            self.site, "/uptime_check_task/{task_id}/", "GET", description="获取网站监测任务详情"
        )
        self.change_uptimecheck_status = WebApiDefine(
            self.site, "/uptime_check_task/{task_id}/change_status/?super=True", "POST", description="修改网站监测采集任务状态"
        )
        self.update_uptimecheck_task = WebApiDefine(
            self.site, "/uptime_check_task/{task_id}/?super=True", "PUT", description="修改网站监测采集任务"
        )
        self.delete_uptimecheck_task = WebApiDefine(
            self.site, "/uptime_check_task/{task_id}/?super=True", "DELETE", description="删除网站监测采集任务"
        )
        self.create_uptimecheck_task = WebApiDefine(self.site, "/uptime_check_task/", "POST", description="创建网站监测采集任务")
        self.test_uptimecheck_task = WebApiDefine(
            self.site, "/uptime_check_task/test/", "POST", description="测试网站监测采集任务"
        )
        self.get_topo_tree = WebApiDefine(self.site, "/get_topo_tree/", "GET", description="获取拓扑树")
        self.get_uptime_check_node = WebApiDefine(self.site, "/uptime_check_node/", "GET", description="获取网站监测节点")
        self.create_uptime_check_node = WebApiDefine(self.site, "/uptime_check_node/", "POST", description="新增网站监测节点")
        self.get_check_node_server = WebApiDefine(
            self.site, "/uptime_check_node/select_uptime_check_node/", "GET", description="获取节点服务器"
        )

        self.get_host_instance_by_ip = WebApiDefine(
            self.site, "/get_host_instance_by_ip/", "POST", description="获取IP列表"
        )

        # 进程采集
        self.search_process_list = WebApiDefine(self.site, "/process_collect/", "GET", description="获取进程任务列表")
        self.get_process_detail = WebApiDefine(
            self.site, "/process_collect/{task_id}/?super=True", "GET", description="获取进程任务详情"
        )
        self.update_process_task = WebApiDefine(
            self.site, "/process_collect/{task_id}/?super=True", "PUT", description="修改进程采集任务"
        )
        self.delete_process_task = WebApiDefine(
            self.site, "/process_collect/{task_id}/?super=True", "DELETE", description="删除进程采集任务"
        )
        self.create_process_task = WebApiDefine(self.site, "/process_collect/", "POST", description="创建进程采集任务")

        self.add_task = WebApiDefine(self.site, "/task1/", "POST", description="新增采集上报任务")
        self.get_task_info = WebApiDefine(self.site, "/task1/{task_id}/", "GET", description="采集上报任务详情")
        self.delete_task = WebApiDefine(self.site, "/task1/{task_id}/?super=True", "DELETE", description="删除采集上报任务")
        self.update_task = WebApiDefine(self.site, "/task1/{task_id}/?super=True", "PUT", description="修改采集上报任务")
        self.get_collect_task_status = WebApiDefine(
            self.site, "/task1/{task_id}/get_collect_task_status/", "GET", description="获取采集任务状态"
        )
        self.bulk_stop_task = WebApiDefine(self.site, "/task1/bulk_stop_task/?super=True", "POST", description="批量停止任务")
        self.bulk_start_task = WebApiDefine(
            self.site, "/task1/bulk_start_task/?super=True", "POST", description="批量启动任务"
        )
        self.bulk_retry_task = WebApiDefine(
            self.site, "/task1/bulk_retry_task/?super=True", "POST", description="批量启动任务"
        )
        self.get_plugins_by_monitor_obj = WebApiDefine(
            self.site, "/task1/get_plugins_by_monitor_obj/", "GET", description="获取对象采集插件"
        )
        self.obj_member = WebApiDefine(self.site, "/monitor/{obj_id}/obj_member/", "POST", description="获取对象列表")
        self.get_topo_data = WebApiDefine(self.site, "/monitor/get_topo_data/", "GET", description="静态拓扑")
        self.get_topo_target = WebApiDefine(self.site, "/monitor/get_topo_target/", "POST", description="静态拓扑实例")
        self.get_obj_property_list = WebApiDefine(
            self.site, "/monitor/{obj_id}/property_list/", "GET", description="获取对象展示字段"
        )

        self.get_collect_host_list = WebApiDefine(
            self.site, "/task1/get_collect_host_list/?super=True", "GET", description="获取远程采集主机"
        )
        self.get_collect_variables = WebApiDefine(
            self.site, "/task1/get_collect_variables/?super=True", "GET", description="获取字段变量"
        )
        self.search_object_attribute = WebApiDefine(
            self.site, "bk/search_object_attribute/", "GET", description="获取监控对象标识展示字段"
        )

        self.get_strategy = WebApiDefine(self.site, "/strategy/", "GET", description="获取配置策略数据")
        self.get_cloud_resource_types = WebApiDefine(
            self.site, "/cloud/clouddefine/cloud_resource_types/", "GET", description="获取策略组类型"
        )
        self.get_notice = WebApiDefine(self.site, "/notice/", "GET", description="获取告警组")
        self.get_cloud_resources = WebApiDefine(
            self.site, "/cloud/monitormgmt/cloudresources/", "GET", description="获取监控目标"
        )

        self.get_cloud_resource_events = WebApiDefine(
            self.site, "/cloud/clouddefine/cloud_resource_events/", "GET", description="具体云资源下的可监控事件列表"
        )

        self.get_event_metric_list = WebApiDefine(
            self.site, "/monitor/{id}/event_metric_list/", "GET", description="具体云资源下的可监控事件列表"
        )

        self.get_monitor_inst_metric = WebApiDefine(
            self.site, "/monitor_view/get_monitor_inst_metric/", "GET", description="获取对象实例指标列表"
        )
        self.get_strategy_instance = WebApiDefine(
            self.site, "/cloud/monitormgmt/alarmstrategygroups/{strategy_id}/", "GET", description="获取配置策略数据"
        )

        self.get_strategy_group_details = WebApiDefine(
            self.site, "/strategy/{strategy_id}/strategy_group_details/", "GET", description="获取基础监控数据详情"
        )

        self.get_all_monitor_obj = WebApiDefine(self.site, "/monitor/all_monitor_obj/", "GET", description="获取所有的监控对象")

        self.get_variable_value = WebApiDefine(
            self.site, "/monitor/get_variable_value/", "POST", description="获取所有的监控对象"
        )

        self.create_alarm_strategy_groups = WebApiDefine(
            self.site, "/cloud/monitormgmt/alarmstrategygroups/", "POST", description="创建虚拟化模版"
        )

        self.create_strategy = WebApiDefine(self.site, "/strategy/?super=True", "POST", description="创建配置策略数据")

        self.bulk_switch_strategy_status = WebApiDefine(
            self.site, "/strategy/bulk_switch_strategy_status/?super=True", "POST", description="基础监控启/停修改"
        )

        self.update_alarm_strategy_groups_status = WebApiDefine(
            self.site,
            "/cloud/monitormgmt/alarmstrategygroups/{strategy_id}/?super=True",
            "PATCH",
            description="获取配置策略数据",
        )

        self.delete_alarm_strategy_groups = WebApiDefine(
            self.site,
            "/cloud/monitormgmt/alarmstrategygroups/{strategy_id}/?super=True",
            "DELETE",
            description="删除虚拟化策略组",
        )

        self.delete_strategy = WebApiDefine(
            self.site, "/strategy/{strategy_id}/?super=True", "DELETE", description="基础监控删除"
        )

        self.update_strategy = WebApiDefine(
            self.site, "/strategy/{strategy_id}/?super=True", "PUT", description="基础监控修改"
        )

        self.update_alarm_strategy_groups = WebApiDefine(
            self.site, "/cloud/monitormgmt/alarmstrategygroups/{strategy_id}/?super=True", "PUT", description="修改虚拟化策略组"
        )

        self.update_strategy_targets = WebApiDefine(
            self.site, "/strategy/{strategy_id}/?super=True", "PATCH", description="基础监控修改目标"
        )
        self.batch_create_monitor_group = ApiDefine(
            self.site, "/open_api/batch_create_monitor_group/", "POST", description="批量创建监控对象组"
        )
        self.create_monitor_obj = ApiDefine(self.site, "/open_api/create_monitor_obj/", "POST", description="批量创建监控对象")

        self.get_obj_table_id = ApiDefine(self.site, "/open_api/get_obj_table_id/", "GET", description="获取K8S表ID")
        self.get_device_table_id = ApiDefine(
            self.site, "/open_api/get_device_table_id/", "GET", description="获取网络设备表ID"
        )
        # 动态分组
        self.pre_view_inst_list = WebApiDefine(self.site, "/dynamic_groups/pre_view/", "POST", description="动态分组实例列表预览")
        self.create_dynamic_group = WebApiDefine(self.site, "/dynamic_groups/", "POST", description="新增动态分组")
        self.update_dynamic_group = WebApiDefine(self.site, "/dynamic_groups/{group_id}/", "PUT", description="修改动态分组")
        self.delete_dynamic_group = WebApiDefine(
            self.site, "/dynamic_groups/{group_id}/", "DELETE", description="删除动态分组"
        )
        self.search_dynamic_group = WebApiDefine(self.site, "/dynamic_groups/", "GET", description="查询动态分组")
        self.list_dynamic_group_by_bk_obj_id = WebApiDefine(
            self.site, "/dynamic_groups/list_by_bk_obj_id/", "GET", description="查询指定模型动态分组"
        )
        self.get_obj_display_fields = WebApiDefine(
            self.site, "/monitor/{obj_id}/property_list/", "GET", description="获取对象展示字段列表"
        )
        self.update_obj_plugin_obj = WebApiDefine(
            self.site, "/open_api/update_obj_plugin_obj/", "POST", description="更新对象插件列表"
        )
        self.delete_obj_plugin_obj = WebApiDefine(
            self.site, "/open_api/delete_obj_plugin_obj/", "POST", description="删除对象插件列表"
        )

        self.batch_delete_uptimecheck_task = WebApiDefine(
            self.site, "/uptime_check_task/batch_delete_uptimecheck_task/", "POST", description="删除对象插件列表"
        )
        self.import_uptime_check_task = WebApiDefine(
            self.site, "/open_api/import_uptime_check_task/", "POST", description="上传文件"
        )
        self.create_monitor_object = WebApiDefine(
            self.site, "/open_api/create_monitor_object/", "POST", description="创建监控对象"
        )
        self.modify_monitor_object = WebApiDefine(
            self.site, "/open_api/modify_monitor_object/", "POST", description="修改监控对象"
        )
        self.delete_monitor_object = WebApiDefine(
            self.site, "/open_api/delete_monitor_object/", "POST", description="删除监控对象"
        )

        self.create_device_data_id = WebApiDefine(
            self.site, "/open_api/create_device_data_id/", "POST", description="创建网络设备DATA_ID"
        )


class BKMonitorApiOperation(BaseAPIOperation):
    def __init__(self):
        super().__init__()
        self.site = SiteConfig.BK_MONITOR
        self.search_host_performance = ApiDefine(
            self.site, "/rest/v2/performance/host_list/", "GET", description="查询主机列表（包括性能数据）"
        )
        self.import_uptime_check_task = WebApiDefine(
            self.site, "/rest/v2/uptime_check/import_uptime_check/", "POST", description="上传网站检测任务"
        )


class FlowOperation(BaseAPIOperation):
    def __init__(self):
        super().__init__()
        self.site = SiteConfig.FLOW
        self.over_get_tickets = ApiDefine(self.site, "/openapi/ticket/over_get_tickets/", "GET", description="获取单据")
        self.get_tickets_all = ApiDefine(self.site, "/openapi/ticket/get_tickets/", "POST", description="获取所有单据")

        self.get_service_catalogs = WebApiDefine(
            self.site, "/api/service/catalogs/tree_view/", "GET", description="服务目录查询"
        )
        self.get_services_by_service_catalog = WebApiDefine(
            self.site, "/api/service/catalog_services/get_services/", "GET", description="查询某个服务目录下服务列表"
        )
        self.get_services = WebApiDefine(self.site, "/api/service/projects/", "GET", description="查询服务列表")
        self.get_projects_services = WebApiDefine(
            self.site, "/api/service/projects/get_services/", "GET", description="查询服务目录下服务（会根据服务可见范围进行查询）"
        )
        self.create_service = WebApiDefine(self.site, "/api/service/projects/", "POST", description="创建服务")
        self.update_service = WebApiDefine(self.site, "/api/service/projects/{id}/", "PUT", description="修改服务")
        self.add_services_to_catalog_service = WebApiDefine(
            self.site, "/api/service/catalog_services/add_services/", "POST", description="添加服务到服务目录"
        )
        self.remove_services_from_catalog_service = WebApiDefine(
            self.site, "/api/service/catalog_services/remove_services/", "POST", description="从服务目录移除服务"
        )
        self.batch_update_service_workflow = WebApiDefine(
            self.site, "/api/service/projects/batch_update/", "POST", description="批量更新服务流程"
        )
        self.batch_delete_service = WebApiDefine(
            self.site, "/api/service/projects/batch_delete/", "POST", description="批量删除服务"
        )
        self.personal_set = WebApiDefine(self.site, "/api/esm/personal_set/{id}/", "PUT", description="保存工单查询条件")
        self.create_personal = WebApiDefine(self.site, "/api/esm/personal_set/", "POST", description="创建工单查询条件")
        self.get_personal = WebApiDefine(self.site, "/api/esm/personal_set/", "GET", description="查询工单查询条件")
        self.del_personal = WebApiDefine(self.site, "/api/esm/ticket_search/{id}/", "DELETE", description="删除工单查询条件")
        self.get_service_states = WebApiDefine(
            self.site, "/api/service/projects/get_service_states/", "GET", description="查询步骤"
        )
        self.get_service_fields = WebApiDefine(
            self.site, "/api/service/projects/get_service_fields/", "GET", description="查询字段"
        )

        self.get_tickets = WebApiDefine(self.site, "/api/ops/ticket/", "GET", description="获取单据列表")
        self.get_export_record = WebApiDefine(self.site, "/api/export_ticket/record/", "GET", description="获取导出记录")
        self.download_ticket = WebApiDefine(
            self.site, "/api/export_ticket/record/download_ticket/", "GET", description="下载导出记录", is_json=False
        )
        self.export_ticket = WebApiDefine(
            self.site, "/api/export_ticket/record/export_ticket/", "POST", description="导出工单"
        )
        self.get_ticket_info = WebApiDefine(self.site, "/api/ticket/receipts/{ticket_id}/", "GET", description="查询工单详情")
        self.supervise_ticket = WebApiDefine(
            self.site, "/api/ticket/receipts/{ticket_id}/supervise/", "POST", description="催办工单"
        )
        self.get_tickets_count = WebApiDefine(
            self.site, "/api/ops/ticket/get_view_type_count/", "GET", description="查询各个类型工单数量统计"
        )
        self.withdraw_ticket = WebApiDefine(self.site, "/api/ticket/receipts/{id}/close/", "POST", description="撤销单据")
        self.suspend_ticket = WebApiDefine(self.site, "/api/ticket/receipts/{id}/suspend/", "POST", description="挂起单据")
        self.unsuspend_ticket = WebApiDefine(
            self.site, "/api/ticket/receipts/{id}/unsuspend/", "POST", description="恢复单据"
        )
        self.get_user_groups = WebApiDefine(self.site, "/api/role/users/", "GET", description="查询用户组列表")
        self.add_user_group = WebApiDefine(self.site, "/api/role/users/", "POST", description="新增用户组")
        self.update_user_group = WebApiDefine(self.site, "/api/role/users/{id}/", "PUT", description="更新用户组信息")
        self.delete_user_group = WebApiDefine(self.site, "/api/role/users/{id}/", "DELETE", description="删除用户组")
        self.get_workflow_list = WebApiDefine(self.site, "/api/workflow/templates/", "GET", description="查询流程列表")
        self.get_workflow_versions = WebApiDefine(self.site, "/api/workflow/versions/", "GET", description="查询流程版本信息")
        self.get_workflow_version_states = WebApiDefine(
            self.site, "/api/workflow/versions/{workflow_version_id}/states/", "GET", description="查询流程版本节点"
        )
        self.get_workflow_version_transitions = WebApiDefine(
            self.site, "/api/workflow/versions/{workflow_version_id}/transitions/", "GET", description="查询流程版本节点关联"
        )
        self.get_workflow_version_sla_start_states_group = WebApiDefine(
            self.site,
            "/api/workflow/versions/{workflow_version_id}/sla_start_states_group/",
            "GET",
            description="查询流程版本节点分支",
        )
        self.get_scope_users = WebApiDefine(self.site, "/api/ops/user/get_scope_users/", "POST", description="查询用户")
        self.get_general_roles = WebApiDefine(self.site, "/api/role/users/", "GET", description="查询通用角色")
        self.get_root_organization = WebApiDefine(
            self.site, "/api/ops/user/get_root_organization/", "POST", description="查询组织架构"
        )
        self.get_organization_children = WebApiDefine(
            self.site, "/api/ops/user/get_organization_children/", "GET", description="查询组织架构的子层级"
        )
        self.get_sla = WebApiDefine(self.site, "/api/sla/protocols/", "GET", description="查询sla列表")
        self.get_service_categories = WebApiDefine(self.site, "/api/service/categories/", "GET", description="查询服务类别")
        self.get_transition_lines = WebApiDefine(
            self.site, "/api/workflow/versions/{workflow_version_id}/transition_lines/", "POST", description="查询节点间的关联"
        )
        self.export_ticket_to_excel = WebApiDefine(
            self.site, "/api/ticket/receipts/export_excel/", "GET", description="工单导出", is_json=False
        )
        self.import_picture = WebApiDefine(
            self.site, "/api/misc/upload_file/", "POST", description="公告插入图片", is_file=True
        )
        self.import_enclosure = WebApiDefine(
            self.site, "/api/esm/notify/upload_file/", "POST", description="公告导入附件", is_file=True
        )
        self.download_rich_file = WebApiDefine(
            self.site, "/api/misc/download_rich_file/", "GET", description="下载公告导入的附件", is_json=False
        )
        self.create_notify = WebApiDefine(self.site, "/api/esm/notify/", "POST", description="创建公告")
        self.count_unread_notify = WebApiDefine(
            self.site, "/api/esm/notify/count_unread_notify/", "GET", description="统计未读公告"
        )
        self.search_notify = WebApiDefine(self.site, "/api/esm/notify/", "GET", description="查询公告")
        self.update_notify_state = WebApiDefine(
            self.site, "/api/esm/notify/{notify_id}/update_notify_state/", "POST", description="更新公告浏览状态"
        )
        self.update_notify = WebApiDefine(self.site, "/api/esm/notify/{notify_id}/", "PUT", description="更新公告")
        self.batch_delete_notify = WebApiDefine(
            self.site, "/api/esm/notify/batch_delete/", "POST", description="批量删除公告"
        )
        self.clean_cache = WebApiDefine(self.site, "/api/misc/clean_cache/", "POST", description="后台管理-刷新缓存")

        self.print_ticket = WebApiDefine(
            self.site, "/api/ticket/receipts/{id}/print_ticket/", "GET", description="查询工单文章"
        )


class AutomationOperation(BaseAPIOperation):
    def __init__(self):
        super().__init__()
        self.site = SiteConfig.AUTOMATION
        self.bulk_import_plugins = ApiDefine(self.site, "/open_api/bulk_import_plugins/", "POST", description="批量导入插件")
        self.bk_obj_plugin_state = ApiDefine(self.site, "/open_api/bk_obj_plugin_state/", "GET", description="查询模型插件状态")


class AutoMateOperation(BaseAPIOperation):
    """
    自动发现服务 auto-mate
    """

    def __init__(self):
        super().__init__()
        self.site = ""
        self.exec_adhoc = OpenApiDefine("/api/ansible/v1/fast_execute_adhoc/", "POST", description="执行adhoc命令")
        self.run_collect_task = OpenApiDefine("/api/collect/v1/run_collect_task/", "POST", description="快速执行采集任务")
        self.test_run_collect_task = OpenApiDefine(
            "/api/collect/v1/collect_task_test/", "POST", description="开发测试快速执行采集任务"
        )
        self.send_command = OpenApiDefine("/api/ssh/v1/send_command/", "POST", description="对网络设备执行远程命令")
        self.get_task_status = OpenApiDefine("/api/task/v1/status/", "POST", description="获取采集任务状态")
        self.get_task_result = OpenApiDefine("/api/task/v1/result/", "POST", description="获取采集任务结果")
        self.stop_running_task = OpenApiDefine("/api/task/v1/stop_running_task/", "POST", description="停止运行中的任务")
        self.get_tasks = OpenApiDefine("/api/task/v1/", "POST", description="获取采集任务列表")
        self.cloud = OpenApiDefine("/api/cloud/v1/run/", "POST", description="通用云服务操作(增删改查)")

        self.topology_scan = OpenApiDefine("/api/ssh/v1/topology_discovery/run", "POST", description="执行拓扑扫描")
        self.get_scan_status = OpenApiDefine("/api/ssh/v1/topology_discovery/status", "GET", description="查询拓扑扫描状态")
        self.get_scan_result = OpenApiDefine("/api/ssh/v1/topology_discovery/result", "POST", description="查询拓扑扫描结果")
        self.run_monitor_collect_task = OpenApiDefine(
            "/api/cloud/v1/monitor/monitor_collect/", "POST", description="监控采集(CMP)"
        )
        self.exec_adhoc_file = OpenApiDefine(
            "/api/ansible/v1/upload_file_use_adhoc/", "POST", description="执行adhoc命令", is_file=True
        )
        self.fast_execute_script = OpenApiDefine(
            "/api/ansible/v1/fast_execute_script/", "POST", description="Ansible快速执行脚本", is_file=False
        )

        # bk_job
        self.get_job_task_result = OpenApiDefine(
            "/api/bk_job/job_task/{job_task_id}/", "GET", description="查询作业平台任务", is_file=False
        )
        self.get_job_task_status = OpenApiDefine(
            "/api/bk_job/job_task/{job_task_id}/status/", "GET", description="查询作业平台任务状态", is_file=False
        )
        self.get_job_task_log = OpenApiDefine(
            "/api/bk_job/job_task/{job_task_id}/log/", "GET", description="查询作业平台任务日志", is_file=False
        )

        self.run_scan_task = OpenApiDefine(
            "/api/collect/v1/run_scan_task/", "POST", description="快速执行扫描任务", is_file=False
        )


class BKSopsOperation(BaseAPIOperation):
    def __init__(self):
        super().__init__()
        self.site = SiteConfig.BK_SOPS
        self.get_common_template_list = ApiDefine(self.site, "/api/v3/common_template/", "GET", description="查询公共流程列表")
        self.get_taskflow = ApiDefine(self.site, "/api/v3/taskflow/", "GET", description="查询流程执行记录")
        self.get_flow_status = ApiDefine(self.site, "/taskflow/api/status/{project_id}/", "GET", description="查询流程状态")
        self.delete_common_template = ApiDefine(
            self.site, "/api/v3/common_template/{template_id}/", "DELETE", description="删除公共流程", is_json=False
        )


class NodeManOperation(BaseAPIOperation):
    def __init__(self):
        super().__init__()
        self.site = SiteConfig.NODE_MAN
        self.get_meta_filter_condition = ApiDefine(
            self.site, "/api/meta/filter_condition/", "GET", description="查询节点管理枚举字段"
        )
        self.get_fetch_topo = ApiDefine(self.site, "/api/cmdb/fetch_topo/", "GET", description="查询业务下拓扑节点")
        self.get_job_commands = ApiDefine(
            self.site, "/api/job/{job_id}/get_job_commands/", "GET", description="查询agent手动安装的安装命令"
        )


class ApiManager(LinkConfig):
    uac = UacApiOperation()
    monitor = MonitorApiOperation()
    flow = FlowOperation()
    automation = AutomationOperation()
    bk_monitor = BKMonitorApiOperation()
    auto_mate = AutoMateOperation()
    bk_sops = BKSopsOperation()
    node_man = NodeManOperation()
