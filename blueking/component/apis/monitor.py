# -*- coding: utf-8 -*-
from ..base import ComponentAPI


class CollectionsMonitor(object):
    """Collections of GSE APIS"""

    def __init__(self, client):
        self.client = client

        self.get_ts_data = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/get_ts_data/",
            description=u"查询TS",
        )
        self.metadata_get_time_series_group = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_get_time_series_group/",
            description=u"获取自定义时序分组具体内容",
        )

        self.metadata_modify_result_table = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_modify_result_table/",
            description=u"修改一个结果表的配置 根据给定的数据源ID，返回这个结果表的具体信息",
        )

        self.metadata_get_event_group = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_get_event_group/",
            description=u"查询事件组, 获取事件列表",
        )
        self.search_event = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/search_event/",
            description=u"查询事件",
        )
        self.save_alarm_strategy = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/save_alarm_strategy/",
            description=u"保存告警策略",
        )
        self.switch_alarm_strategy = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/switch_alarm_strategy/",
            description=u"开关告警策略",
        )
        self.delete_alarm_strategy = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/delete_alarm_strategy/",
            description=u"删除告警策略",
        )
        self.save_notice_group = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/save_notice_group/",
            description=u"保存告警组",
        )
        self.search_notice_group = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/search_notice_group/",
            description=u"查询告警组",
        )
        self.get_es_data = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/get_es_data/",
            description=u"获取事件数据",
        )

        self.collector_plugin_list = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/collector_plugin_list/",
            description=u"采集插件列表",
        )
        self.collector_plugin_detail = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/collector_plugin_detail/",
            description=u"获取采集插件详情",
        )
        self.ack_event = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/ack_event/",
            description=u"告警事件确认",
        )
        self.save_collect_config = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/save_collect_config/",
            description="创建/保存采集配置",
        )
        self.query_collect_config = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/query_collect_config/",
            description="查询采集配置",
        )
        self.toggle_collect_config_status = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/toggle_collect_config_status/",
            description="启停采集配置",
        )
        self.get_collect_status = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/get_collect_status/",
            description="查询采集配置节点状态",
        )
        self.delete_collect_config = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/delete_collect_config/",
            description="删除采集配置",
        )
        self.retry_target_nodes = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/retry_target_nodes/",
            description="重试部分实例或主机",
        )
        self.upgrade_collect_plugin = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/upgrade_collect_plugin/",
            description="采集配置插件升级",
        )
        self.batch_retry_config = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/batch_retry_config/",
            description="批量重试采集配置的失败实例",
        )
        self.rollback_deployment_config = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/rollback_deployment_config/",
            description="采集配置回滚",
        )
        self.collect_running_status = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/collect_running_status/",
            description="获取采集配置主机的运行状态",
        )
        self.get_collect_log_detail = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/get_collect_log_detail/",
            description="获取采集下发详细日志",
        )
        self.batch_retry_instance_step = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/batch_retry_instance_step/",
            description="重试失败的节点步骤",
        )
        self.metadata_list_result_table = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_list_result_table/",
            description=u"查询监控结果表",
        )
        self.test_uptime_check_task = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/test_uptime_check_task/",
            description=u"测试连通性",
        )
        self.create_uptime_check_task = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/create_uptime_check_task/",
            description=u"创建拨测任务",
        )
        self.edit_uptime_check_task = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/edit_uptime_check_task/",
            description=u"编辑拨测任务",
        )
        self.delete_uptime_check_task = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/delete_uptime_check_task/",
            description=u"删除拨测任务",
        )
        self.deploy_uptime_check_task = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/deploy_uptime_check_task/",
            description=u"下发拨测任务",
        )
        self.change_uptime_check_task_status = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/change_uptime_check_task_status/",
            description=u"启停拨测任务",
        )
        self.get_uptime_check_task_list = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/get_uptime_check_task_list/",
            description=u"拨测任务列表",
        )
        self.get_uptime_check_node_list = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/get_uptime_check_node_list/",
            description=u"拨测节点列表",
        )
        self.create_uptime_check_node = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/create_uptime_check_node/",
            description=u"创建拨测节点",
        )
        self.edit_uptime_check_node = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/edit_uptime_check_node/",
            description=u"编辑拨测节点",
        )
        self.delete_uptime_check_node = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/delete_uptime_check_node/",
            description=u"删除拨测节点",
        )

        self.metadata_get_time_series_metrics = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_get_time_series_metrics/",
            description=u"获取自定义时序结果表的metrics信息",
        )
        self.metadata_query_tag_values = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_query_tag_values/",
            description=u"获取自定义时序分组具体内容",
        )
        self.get_data_id = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_get_data_id/",
            description=u"获取监控数据源具体信息",
        )
        self.metadata_list_label = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_list_label/",
            description=u"查询当前已有的标签信息",
        )
        self.metadata_create_data_id = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_create_data_id/",
            description=u"创建监控数据源",
        )
        # 自定义时序分组相关接口
        self.metadata_create_time_series_group = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_create_time_series_group/",
            description=u"创建自定义时序分组",
        )
        self.metadata_modify_time_series_group = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_modify_time_series_group/",
            description=u"修改自定义时序分组",
        )
        self.metadata_delete_time_series_group = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_delete_time_series_group/",
            description=u"删除自定义时序分组",
        )
        self.metadata_get_time_series_metrics = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_get_time_series_metrics/",
            description=u"获取自定义时序结果表的metrics信息",
        )
        self.metadata_get_time_series_group = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_get_time_series_group/",
            description=u"获取自定义时序分组具体内容",
        )
        # 自定义事件分组相关接口
        self.metadata_get_event_group = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_get_event_group/",
            description=u"查询事件分组具体内容",
        )
        self.metadata_delete_event_group = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_delete_event_group/",
            description=u"删除事件分组",
        )
        self.metadata_modify_event_group = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_modify_event_group/",
            description=u"修改事件分组",
        )
        self.metadata_create_event_group = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_create_event_group/",
            description=u"创建事件分组",
        )
        self.metadata_query_tag_values = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_query_tag_values/",
            description=u"获取自定义时序分组具体内容",
        )
        self.collector_plugin_delete = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/collector_plugin_delete/",
            description=u"删除采集插件",
        )
        self.metadata_create_event_group = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_create_event_group/",
            description=u"创建自定义事件分组",
        )
        self.collector_plugin_upgrade_info = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/collector_plugin_upgrade_info/",
            description=u"获取插件升级日志",
        )
        self.business_list_by_actions = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/business_list_by_actions/",
            description=u"根据动作获取用户具有权限的业务列表",
        )
        self.metadata_create_result_table = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_create_result_table/",
            description=u"根据给定的配置参数，创建一个结果表",
        )
        self.metadata_get_result_table = ComponentAPI(
            client=self.client,
            method="GET",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_get_result_table/",
            description=u"查询一个结果表的信息 根据给定的结果表ID，返回这个结果表的具体信息",
        )
        self.metadata_modify_result_table = ComponentAPI(
            client=self.client,
            method="POST",
            path="/api/c/compapi{bk_api_ver}/monitor_v3/metadata_modify_result_table/",
            description=u"修改一个结果表的配置 根据给定的数据源ID，返回这个结果表的具体信息",
        )
