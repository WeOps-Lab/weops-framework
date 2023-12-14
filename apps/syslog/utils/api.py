import uuid

import requests

from apps.syslog.constants import GRAYLOG_AUTH, GRAYLOG_URL
from utils.app_log import logger


class GraylogRestApi(object):
    def __init__(self):
        self.search_logs = RequestApi(method="POST", path="/api/views/search", description="创建搜索查询")
        self.view_condition = RequestApi(method="GET", path="/api/views/search/{id}", description="查询视图条件")
        self.suggest = RequestApi(method="POST", path="/api/search/suggest", description="日志搜索字段提示")
        self.views_functions = RequestApi(method="GET", path="/api/views/functions", description="获取函数")
        self.view_detail = RequestApi(method="GET", path="/api/views/{id}", description="获取保存条件详情")
        self.entity_types = RequestApi(method="GET", path="/api/events/entity_types", description="获取实体类型")
        self.search_input_logs = RequestApi(method="POST", path="/api/views/search/{id}/execute", description="查询接收器日志")
        self.views_fields = RequestApi(method="GET", path="/api/views/fields", description="查询所有视图字段")
        self.search_views_fields = RequestApi(method="POST", path="/api/views/fields", description="查询视图字段")
        self.search_saved = RequestApi(method="GET", path="/api/search/saved", description="获取查询条件")
        self.add_views = RequestApi(method="POST", path="/api/views", description="创建查询视图")
        self.update_views = RequestApi(method="PUT", path="/api/views/{id}", description="修改查询视图")
        self.delete_views = RequestApi(method="DELETE", path="/api/views/{id}", description="删除查询视图")
        self.export_views_by_id_and_type = RequestApi(
            method="POST", path="/api/views/export/{searchId}/{searchTypeId}", description="导出指定ID和类型的数据", is_json=False
        )
        self.download_files = RequestApi(
            method="GET",
            path="/api/views/search/messages/job/{exportJobId}/{filename}",
            description="下载导出的日志文件",
            is_json=False,
        )
        self.search_nodes = RequestApi(method="GET", path="/api/system/cluster/nodes", description="查询集群中所有活动节点")
        self.search_node = RequestApi(method="GET", path="/api/system/cluster/nodes/{nodeId}", description="查询节点信息")
        self.search_inputs = RequestApi(method="GET", path="/api/system/inputs", description="获取所有接收器")
        self.create_inputs = RequestApi(method="POST", path="/api/system/inputs", description="创建接收器")
        self.search_input = RequestApi(method="GET", path="/api/system/inputs/{inputId}", description="获取某个接收器")
        self.update_input = RequestApi(method="PUT", path="/api/system/inputs/{inputId}", description="修改某个接收器")
        self.delete_input = RequestApi(
            method="DELETE", path="/api/system/inputs/{inputId}", description="删除某个接收器", is_json=False
        )
        self.search_inputs_types = RequestApi(
            method="GET", path="/api/system/inputs/types/all", description="获取有关所有接收器类型的信息"
        )
        self.inputstates = RequestApi(method="GET", path="/api/cluster/inputstates", description="获取所有接收器状态")
        self.open_inputs = RequestApi(method="PUT", path="/api/cluster/inputstates/{inputId}", description="开启接收器")
        self.close_inputs = RequestApi(method="DELETE", path="/api/cluster/inputstates/{inputId}", description="关闭接收器")
        self.add_staticfields = RequestApi(
            method="POST", path="/api/system/inputs/{inputId}/staticfields", description="添加静态字段", is_json=False
        )
        self.del_staticfields = RequestApi(
            method="DELETE", path="/api/system/inputs/{inputId}/staticfields/{key}", description="删除静态字段", is_json=False
        )
        self.metrics = RequestApi(method="POST", path="/api/cluster/metrics/multiple", description="获取集群所有节点指标")
        self.contains_string_tester = RequestApi(
            method="POST", path="/api/tools/contains_string_tester", description="校验字符串"
        )
        self.regex_tester = RequestApi(method="POST", path="/api/tools/regex_tester", description="校验正则")
        self.grok_tester = RequestApi(method="POST", path="/api/tools/grok_tester", description="校验grok")
        self.json_tester = RequestApi(method="POST", path="/api/tools/json_tester", description="校验json")
        self.regex_replace_tester = RequestApi(
            method="POST", path="/api/tools/regex_replace_tester", description="校验正则表达式替换"
        )
        self.split_and_index_tester = RequestApi(
            method="POST", path="/api/tools/split_and_index_tester", description="校验分割"
        )
        self.substring_tester = RequestApi(method="POST", path="/api/tools/substring_tester", description="校验子串捕获")
        self.get_grok = RequestApi(method="GET", path="/api/system/grok", description="获取grok")
        self.get_locales = RequestApi(method="GET", path="/api/system/locales", description="获取地区")

        # 告警策略
        self.create_event_definitions = RequestApi(
            method="POST", path="/api/events/definitions?schedule=true", description="创建告警策略"
        )
        self.get_event_definitions = RequestApi(method="GET", path="/api/events/definitions", description="获取告警策略")
        self.event_definitions_validate = RequestApi(
            method="POST", path="/api/events/definitions/validate", description="验证告警策略"
        )
        self.search_event_definitions = RequestApi(
            method="GET", path="/api/events/definitions/{definitionId}", description="查询告警策略详情"
        )
        self.update_event_definitions = RequestApi(
            method="PUT", path="/api/events/definitions/{definitionId}/?schedule=true", description="修改告警策略"
        )
        self.delete_event_definitions = RequestApi(
            method="DELETE", path="/api/events/definitions/{definitionId}", description="删除告警策略", is_json=False
        )
        self.schedule_event_definitions = RequestApi(
            method="PUT", path="/api/events/definitions/{definitionId}/schedule", description="启动告警策略", is_json=False
        )
        self.unschedule_event_definitions = RequestApi(
            method="PUT", path="/api/events/definitions/{definitionId}/unschedule", description="禁用告警策略", is_json=False
        )

        self.create_notifications = RequestApi(method="POST", path="/api/events/notifications", description="创建通知")
        self.get_notifications = RequestApi(method="GET", path="/api/events/notifications", description="获取通知")
        self.search_notifications = RequestApi(
            method="GET", path="/api/events/notifications/{notificationId}", description="查询通知详情"
        )
        self.update_notifications = RequestApi(
            method="PUT", path="/api/events/notifications/{notificationId}", description="修改通知详情"
        )
        self.delete_notifications = RequestApi(
            method="DELETE", path="/api/events/notifications/{notificationId}", description="删除通知", is_json=False
        )

        self.get_urlwhitelist = RequestApi(method="GET", path="/api/system/urlwhitelist", description="获取api白名单")
        self.update_urlwhitelist = RequestApi(
            method="PUT", path="/api/system/urlwhitelist", description="更新api白名单", is_json=False
        )
        self.get_collectors_configurations = RequestApi(
            method="GET", path="/api/sidecar/configurations", description="查询采集器配置列表"
        )
        self.get_collectors_configuration = RequestApi(
            method="GET", path="/api/sidecar/configurations/{id}", description="查询指定id的采集器配置"
        )
        self.get_collectors_summary = RequestApi(
            method="GET", path="/api/sidecar/collectors/summary", description="查询采集器列表"
        )
        self.get_collectors = RequestApi(method="GET", path="/api/sidecar/collectors", description="查询采集器列表")
        self.get_extractors = RequestApi(
            method="GET", path="/api/system/inputs/{id}/extractors", description="查询某个接收器下的提取器"
        )
        self.add_extractors = RequestApi(
            method="POST", path="/api/system/inputs/{id}/extractors", description="创建某个接收器下的提取器"
        )
        self.order_extractors = RequestApi(
            method="POST", path="/api/system/inputs/{id}/extractors/order", description="为提取器排序", is_json=False
        )
        self.del_extractors = RequestApi(
            method="DELETE",
            path="/api/system/inputs/{id}/extractors/{ex_id}",
            description="删除某个接收器下的某个提取器",
            is_json=False,
        )
        self.update_extractors = RequestApi(
            method="PUT", path="/api/system/inputs/{id}/extractors/{ex_id}", description="修改某个接收器下的某个提取器"
        )
        self.extractor_detail = RequestApi(
            method="GET", path="/api/system/inputs/{id}/extractors/{ex_id}", description="查询提取器详情"
        )
        self.create_collectors_configurations = RequestApi(
            method="POST", path="/api/sidecar/configurations", description="创建采集器配置"
        )
        self.delete_collectors_configurations = RequestApi(
            method="DELETE", path="/api/sidecar/configurations/{id}", description="删除采集器配置", is_json=False
        )
        self.copy_collectors_configurations = RequestApi(
            method="POST", path="/api/sidecar/configurations/{id}/{name}", description="复制采集器配置", is_json=False
        )
        self.create_collectors_configurations = RequestApi(
            method="POST", path="/api/sidecar/configurations", description="创建采集器配置"
        )
        self.update_collectors_configurations = RequestApi(
            method="PUT", path="/api/sidecar/configurations/{id}", description="修改采集器配置"
        )
        self.associative_configuration = RequestApi(
            method="PUT", path="/api/sidecars/configurations", description="节点采集器应用配置", is_json=False
        )
        self.create_collectors = RequestApi(method="POST", path="/api/sidecar/collectors", description="创建采集器")
        self.delete_collectors = RequestApi(
            method="DELETE", path="/api/sidecar/collectors/{id}", description="删除采集器", is_json=False
        )

        # 控制器与探针
        self.get_sidecars = RequestApi(method="POST", path="/api/sidecar/administration", description="获取sidecar")
        self.get_probe = RequestApi(method="GET", path="/api/sidecar/collectors/summary", description="获取探针列表")
        self.get_configs = RequestApi(method="GET", path="/api/sidecar/configurations", description="获取配置列表")
        self.action = RequestApi(
            method="PUT", path="/api/sidecar/administration/action", description="操作探针", is_json=False
        )

        # 数据流
        self.get_streams = RequestApi(method="GET", path="/api/streams/paginated", description="查询数据流")
        self.add_stream = RequestApi(method="POST", path="/api/streams", description="新增数据流")
        self.start_stream = RequestApi(
            method="POST", path="/api/streams/{id}/resume", description="启动数据流", is_json=False
        )
        self.stream_detail = RequestApi(method="GET", path="/api/streams/{id}", description="数据流详情")
        self.update_stream = RequestApi(method="PUT", path="/api/streams/{id}", description="编辑数据流")
        self.delete_stream = RequestApi(method="DELETE", path="/api/streams/{id}", description="删除数据流", is_json=False)
        self.clone_stream = RequestApi(method="POST", path="/api/streams/{id}/clone", description="克隆数据流")
        self.rule_types = RequestApi(method="GET", path="/api/streams/{id}/rules/types", description="规则类型")
        self.relative = RequestApi(method="GET", path="/api/search/universal/relative", description="加载信息")
        self.test_match = RequestApi(method="POST", path="/api/streams/{id}/testMatch", description="验证规则")
        self.add_rule = RequestApi(method="POST", path="/api/streams/{id}/rules", description="新增验证规则")
        self.rule_detail = RequestApi(method="GET", path="/api/streams/{id}/rules/{rule_id}", description="验证规则详情")
        self.update_rule = RequestApi(method="PUT", path="/api/streams/{id}/rules/{rule_id}", description="修改验证规则")
        self.del_rule = RequestApi(
            method="DELETE", path="/api/streams/{id}/rules/{rule_id}", description="删除验证规则", is_json=False
        )
        self.system_fields = RequestApi(method="GET", path="/api/system/fields", description="系统字段")
        self.system_inputs = RequestApi(method="GET", path="/api/system/inputs", description="匹配输入值列表")

        # 索引集
        self.index_sets_stats = RequestApi(
            method="GET", path="/api/system/indices/index_sets/stats", description="获取全局索引集"
        )
        self.index_sets = RequestApi(method="GET", path="/api/system/indices/index_sets", description="索引集")
        self.default_index = RequestApi(
            method="PUT", path="/api/system/indices/index_sets/{id}/default", description="设置为默认索引集"
        )
        self.delete_index = RequestApi(
            method="DELETE", path="/api/system/indices/index_sets/{id}", description="删除索引集", is_json=False
        )
        self.add_index = RequestApi(method="POST", path="/api/system/indices/index_sets", description="新增索引集")
        self.update_index = RequestApi(method="PUT", path="/api/system/indices/index_sets/{id}", description="修改索引集")
        self.index_set = RequestApi(method="GET", path="/api/system/indices/index_sets/{id}", description="索引集详情")
        self.indexs_multiple = RequestApi(
            method="POST", path="/api/system/indexer/indices/multiple", description="查询展开索引的信息"
        )
        self.index_set_overview = RequestApi(
            method="GET", path="/api/system/indexer/overview/{id}", description="索引集索引数据详情"
        )
        self.index_set_rebuild = RequestApi(
            method="POST",
            path="/api/system/indices/ranges/index_set/{id}/rebuild",
            description="更新索引集范围",
            is_json=False,
        )

        self.indexs = RequestApi(method="GET", path="/api/system/indexer/indices/{id}/list", description="索引列表")
        self.create_index = RequestApi(
            method="POST", path="/api/cluster/deflector/{id}/cycle", description="创建新索引", is_json=False
        )
        self.index_rebuild = RequestApi(
            method="POST", path="/api/system/indices/ranges/{index_name}/rebuild", description="重新计算索引范围", is_json=False
        )
        self.index_reopen = RequestApi(
            method="POST", path="/api/system/indexer/indices/{index_name}/reopen", description="重新打开索引", is_json=False
        )
        self.index_close = RequestApi(
            method="POST", path="/api/system/indexer/indices/{index_name}/close", description="关闭索引", is_json=False
        )
        self.index_delete = RequestApi(
            method="DELETE", path="/api/system/indexer/indices/{index_name}", description="删除索引", is_json=False
        )


class RequestApi(object):
    HTTP_STATUS_OK_SET = {200, 201, 202, 203, 204}

    requests_methods = {
        "GET": requests.get,
        "POST": requests.post,
        "PUT": requests.put,
        "PATCH": requests.patch,
        "DELETE": requests.delete,
    }

    def __init__(self, method, path, description, is_json=True):
        self.method = method
        self.path = path
        self.description = description
        self.is_json = is_json

    def get_headers(self):
        return {
            "X-Requested-By": str(uuid.uuid4()),
            "Authorization": f"Basic {GRAYLOG_AUTH}",
            "Content-Type": "application/json",
        }

    def send_request(self, *args, **kwargs):
        path = self.path
        if kwargs.get("url_param_dict"):
            path = path.format(**kwargs.get("url_param_dict"))
        request_data = dict(url=f"{GRAYLOG_URL}{path}", headers=self.get_headers(), verify=False)
        if kwargs.get("params"):
            request_data.update(params=kwargs.get("params", {}))
        if kwargs.get("data"):
            request_data.update(data=kwargs.get("data", {}))
        if kwargs.get("json"):
            request_data.update(json=kwargs.get("json", {}))
        request_method = self.requests_methods[self.method]

        logger.info("调用接口【{}】, params=【{}】".format(self.path, kwargs))

        try:
            resp = request_method(**request_data)
        except Exception as e:
            message = getattr(e, "message", "接口调用失败！")
            logger.exception(f"接口调用失败，详情：{message}")
            return {"result": False, "message": message}

        if resp.status_code not in self.HTTP_STATUS_OK_SET:
            return {"result": False, **resp.json()}

        data = resp.json() if self.is_json else resp

        return {"result": True, "data": data}

    def __call__(self, *args, **kwargs):
        return self.send_request(*args, **kwargs)


graylog_api = GraylogRestApi()
