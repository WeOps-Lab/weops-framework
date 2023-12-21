from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from common.keycloak_auth import KeycloakIsAuthenticated, KeycloakTokenAuthentication
from apps.syslog.constants import APP_MODULE_NAME, MONITOR
from apps.syslog.permission import MonitorPolicyLogInstPermission
from apps.syslog.services.log import SyslogService
from apps.syslog.utils.migrate_notice import init_migrate_notice
from apps.system_mgmt.casbin_package.permissions import ManagerPermission
from apps.system_mgmt.models import OperationLog, SysRole
from apps.system_mgmt.utils import batch_create_log, create_log
from common.casbin_inst_service import CasBinInstService
from utils.app_log import logger
from utils.decorators import ApiLog


class SyslogViewSet(ViewSet):
    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]

    # @property
    # def permissions_actions(self):
    #     """权限校验action"""
    #     return [
    #         "delete_event_definitions",
    #         "update_event_definitions",
    #         "schedule_event_definitions",
    #         "unschedule_event_definitions",
    #         "batch_schedule_event_definitions",
    #         "batch_unschedule_event_definitions",
    #     ]
    #
    # def get_permissions(self):
    #     if self.action in self.permissions_actions:
    #         _permission_classes = [permission() for permission in self.permission_classes]
    #         _permission_classes += [MonitorPolicyLogInstPermission()]
    #         return _permission_classes
    #     return super().get_permissions()

    @action(methods=["POST"], detail=False, url_path="views/search")
    @ApiLog("查询日志")
    def search_logs(self, request):
        result = SyslogService.search_logs(json=request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "查询日志",
            "执行日志查询操作",
            OperationLog.EXEC,
            "执行日志查询操作。",
        )
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="suggest")
    @ApiLog("日志搜索字段提示")
    def suggest(self, request):
        result = SyslogService.suggest(json=request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="views/search/(?P<id>.+?)/execute")
    @ApiLog("查询视图日志")
    def search_input_logs(self, request, id):
        url_param_dict = dict(id=id)
        result = SyslogService.search_input_logs(url_param_dict=url_param_dict, json=request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "查询日志",
            "查询视图日志",
            OperationLog.EXEC,
            f"查询视图{id}日志。",
        )
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="views/fields")
    @ApiLog("查询所有视图字段")
    def views_fields(self, request):
        result = SyslogService.views_fields()
        return Response(result)

    @views_fields.mapping.post
    @ApiLog("查询视图字段")
    def search_views_fields(self, request):
        result = SyslogService.search_views_fields(json=request.data)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="search/saved")
    @ApiLog("获取查询条件")
    def search_saved(self, request):
        result = SyslogService.search_saved(params=request.GET)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="create_views")
    @ApiLog("创建查询视图")
    def add_views(self, request):
        result = SyslogService.add_views(json=request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "查询日志",
            "创建查询视图",
            OperationLog.DELETE,
            f"创建查询视图{result.get('id', '')}。",
        )
        return Response(result)

    @action(methods=["DELETE"], detail=False, url_path="delete_views/(?P<id>.+?)")
    @ApiLog("删除查询视图")
    def delete_views(self, request, id):
        url_param_dict = dict(id=id)
        result = SyslogService.delete_views(url_param_dict=url_param_dict)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "查询日志",
            "删除查询视图",
            OperationLog.DELETE,
            f"删除查询视图{id}。",
        )
        return Response(result)

    @action(methods=["PUT"], detail=False, url_path="update_views/(?P<id>.+?)")
    @ApiLog("修改查询视图")
    def update_views(self, request, id):
        url_param_dict = dict(id=id)
        result = SyslogService.update_views(url_param_dict=url_param_dict, json=request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "查询日志",
            "更新查询视图",
            OperationLog.MODIFY,
            f"修改查询视图{id}。",
        )
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="create_import_job/(?P<searchId>.+?)/(?P<searchTypeId>.+?)")
    @ApiLog("创建指定ID和类型的导出任务")
    def export_views_by_id_and_type(self, request, searchId, searchTypeId):
        url_param_dict = dict(searchId=searchId, searchTypeId=searchTypeId)
        result = SyslogService.export_views_by_id_and_type(url_param_dict=url_param_dict, json=request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "查询日志",
            "创建导出任务",
            OperationLog.MODIFY,
            f"创建导出任务，查询ID{searchId}，查询类型{searchTypeId}，任务号{result}。",
        )
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="download_files/(?P<exportJobId>.+?)/(?P<filename>.+?)")
    @ApiLog("下载导出的日志文件")
    def download_files(self, request, exportJobId, filename):
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "查询日志",
            "下载导出的日志文件",
            OperationLog.MODIFY,
            f"下载导出的日志文件，任务号{exportJobId}。",
        )
        return SyslogService.download_files(exportJobId, filename)

    # 下面为接收器相关接口
    @action(methods=["GET"], detail=False, url_path="system/cluster/nodes")
    @ApiLog("查询集群中所有活动节点")
    def search_nodes(self, request):
        result = SyslogService.search_nodes(params=request.GET)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="system/inputs/types/all")
    @ApiLog("获取有关所有接收器类型的信息")
    def search_inputs_types(self, request):
        result = SyslogService.search_inputs_types(params=request.GET)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="system/inputs")
    @ApiLog("获取所有接收器")
    def search_inputs(self, request):
        result = SyslogService.search_inputs(params=request.GET)
        return Response(result)

    @search_inputs.mapping.post
    @ApiLog("创建接收器")
    def create_inputs(self, request):
        result = SyslogService.create_inputs(json=request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "日志接收器",
            f"{result.get('id', '')}",
            OperationLog.ADD,
            f"创建日志接收器{result.get('id', '')}。",
        )
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="system/inputs/(?P<inputId>.+?)")
    @ApiLog("查询接收器详情")
    def search_input(self, request, inputId):
        url_param_dict = dict(inputId=inputId)
        result = SyslogService.search_input(url_param_dict=url_param_dict, params=request.GET)
        return Response(result)

    @search_input.mapping.put
    @ApiLog("修改接收器")
    def update_input(self, request, inputId):
        url_param_dict = dict(inputId=inputId)
        result = SyslogService.update_input(url_param_dict=url_param_dict, json=request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "日志接收器",
            f"{inputId}",
            OperationLog.MODIFY,
            f"修改日志接收器{inputId}。",
        )
        return Response(result)

    @search_input.mapping.delete
    @ApiLog("删除接收器")
    def delete_input(self, request, inputId):
        url_param_dict = dict(inputId=inputId)
        result = SyslogService.delete_input(url_param_dict=url_param_dict)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "日志接收器",
            f"{inputId}",
            OperationLog.DELETE,
            f"删除日志接收器{inputId}。",
        )
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="cluster/inputstates")
    @ApiLog("获取所有接收器状态")
    def search_inputstates(self, request):
        result = SyslogService.inputstates(params=request.GET)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="system/inputs/(?P<inputId>.+?)/staticfields")
    @ApiLog("添加静态字段")
    def add_staticfields(self, request, inputId):
        url_param_dict = dict(inputId=inputId)
        result = SyslogService.add_staticfields(url_param_dict=url_param_dict, json=request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "日志接收器",
            f"{inputId}",
            OperationLog.EXEC,
            f"对日志接收器{inputId}执行添加静态字段{request.data.get('key', '')}操作。",
        )
        return Response(result)

    @action(methods=["DELETE"], detail=False, url_path="system/inputs/(?P<inputId>.+?)/staticfields/(?P<key>.+?)")
    @ApiLog("删除静态字段")
    def del_staticfields(self, request, inputId, key):
        url_param_dict = dict(inputId=inputId, key=key)
        result = SyslogService.del_staticfields(url_param_dict=url_param_dict)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "日志接收器",
            f"{inputId}",
            OperationLog.EXEC,
            f"对日志接收器{inputId}执行删除静态字段{key}操作。",
        )
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="cluster/metrics/multiple")
    @ApiLog("查询集群所有节点的所有指标")
    def metrics(self, request):
        result = SyslogService.metrics(json=request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="tools/contains_string_tester")
    @ApiLog("校验字符串数据")
    def contains_string_tester(self, request):
        result = SyslogService.contains_string_tester(json=request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="tools/regex_tester")
    @ApiLog("校验正则数据")
    def regex_tester(self, request):
        result = SyslogService.regex_tester(json=request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="tools/grok_tester")
    @ApiLog("校验grok")
    def grok_tester(self, request):
        result = SyslogService.grok_tester(json=request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="tools/json_tester")
    @ApiLog("校验json")
    def json_tester(self, request):
        result = SyslogService.json_tester(json=request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="tools/regex_replace_tester")
    @ApiLog("校验正则表达式替换")
    def regex_replace_tester(self, request):
        result = SyslogService.regex_replace_tester(json=request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="tools/split_and_index_tester")
    @ApiLog("校验分割")
    def split_and_index_tester(self, request):
        result = SyslogService.split_and_index_tester(json=request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="tools/substring_tester")
    @ApiLog("校验子串捕获")
    def substring_tester(self, request):
        result = SyslogService.substring_tester(json=request.data)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="tools/locales")
    @ApiLog("获取地区")
    def get_locales(self, request):
        result = SyslogService.get_locales(params=request.GET)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="tools/grok")
    @ApiLog("查询grok")
    def get_grok(self, request):
        result = SyslogService.get_grok(params=request.GET)
        return Response(result)

    @action(methods=["PUT"], detail=False, url_path="cluster/inputstates/(?P<inputId>.+?)")
    @ApiLog("开启接收器")
    def open_inputs(self, request, inputId):
        url_param_dict = dict(inputId=inputId)
        result = SyslogService.open_inputs(url_param_dict=url_param_dict)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "日志接收器",
            f"{inputId}",
            OperationLog.EXEC,
            f"启动日志接收器{inputId}。",
        )
        return Response(result)

    @open_inputs.mapping.delete
    @ApiLog("关闭接收器")
    def close_inputs(self, request, inputId):
        url_param_dict = dict(inputId=inputId)
        result = SyslogService.close_inputs(url_param_dict=url_param_dict)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            "日志接收器",
            f"{inputId}",
            OperationLog.EXEC,
            f"关闭日志接收器{inputId}。",
        )
        return Response(result)

    # 告警策略
    @action(methods=["GET"], detail=False, url_path="events/definitions")
    @ApiLog("获取告警策略")
    def get_event_definitions(self, request):
        kwargs = dict(username=request.user.username, query=request.GET, is_super=request.user.is_super)
        result = SyslogService.get_event_definitions(**kwargs)
        return Response(result)

    @get_event_definitions.mapping.post
    @ApiLog("创建告警策略")
    def create_event_definitions(self, request):
        result = SyslogService.create_event_definitions(request.user.username, **request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            MONITOR,
            f"{result['id']}",
            OperationLog.ADD,
            f"创建日志告警策略{result['title']}。",
        )
        role_names = SysRole.get_user_roles(request.user.username)
        policies = [[role_name, "监控策略log", "manage", str(result["id"]), "0"] for role_name in role_names]
        res = CasBinInstService.create_policies(policies=policies, sec="p", ptype="p")
        logger.warning("创建log监控策略任务后权限同步到casbin, result={}".format(res))
        return Response(result)

    @action(methods=["GET"], detail=False, url_path=r"events/definitions/(?P<definitionId>[^/]+)")
    @ApiLog("查询告警策略详情")
    def search_event_definitions(self, request, definitionId):
        result = SyslogService.search_event_definitions(definitionId)
        return Response(result)

    @search_event_definitions.mapping.put
    @ApiLog("修改告警策略")
    def update_event_definitions(self, request, definitionId):
        result = SyslogService.update_event_definitions(definitionId, request.user.username, **request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            MONITOR,
            f"{result['id']}",
            OperationLog.MODIFY,
            f"创建日志告警策略{result['title']}。",
        )
        return Response(result)

    @search_event_definitions.mapping.delete
    @ApiLog("删除告警策略")
    def delete_event_definitions(self, request, definitionId):
        created_by = SyslogService.delete_event_definitions(definitionId)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            MONITOR,
            f"{definitionId}",
            OperationLog.DELETE,
            "删除日志告警策略。",
        )
        role_names = SysRole.get_user_roles(created_by)
        policies = [[role_name, "监控策略log", "manage", str(definitionId), "0"] for role_name in role_names]
        res = CasBinInstService.remove_policies(policies=policies, sec="p", ptype="p")
        logger.warning("删除log监控策略任务后权限同步到casbin, result={}".format(res))
        return Response()

    @action(methods=["PUT"], detail=False, url_path=r"events/definitions/(?P<definitionId>.+?)/schedule")
    @ApiLog("启动告警策略")
    def schedule_event_definitions(self, request, definitionId):
        url_param_dict = dict(definitionId=definitionId)
        result = SyslogService.schedule_event_definitions(url_param_dict=url_param_dict)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            MONITOR,
            f"{definitionId}",
            OperationLog.EXEC,
            "启动日志告警策略。",
        )
        return Response(result)

    @action(methods=["PUT"], detail=False, url_path=r"events/definitions/(?P<definitionId>.+?)/unschedule")
    @ApiLog("禁用告警策略")
    def unschedule_event_definitions(self, request, definitionId):
        url_param_dict = dict(definitionId=definitionId)
        result = SyslogService.unschedule_event_definitions(url_param_dict=url_param_dict)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            MONITOR,
            f"{definitionId}",
            OperationLog.EXEC,
            "禁用日志告警策略。",
        )
        return Response(result)

    @action(methods=["PUT"], detail=False, url_path="events/definitions/batch_schedule")
    @ApiLog("批量启动告警策略")
    def batch_schedule_event_definitions(self, request):
        SyslogService.batch_schedule_event_definitions(request.data.get("definitionids", []))
        logs = [
            dict(
                operator=request.user.username,
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module=APP_MODULE_NAME,
                obj_type=MONITOR,
                operate_obj=f"{definitionId}",
                operate_type=OperationLog.EXEC,
                operate_summary="启动日志告警策略",
            )
            for definitionId in request.data.get("definitionids", [])
        ]
        batch_create_log(logs)
        return Response()

    @action(methods=["PUT"], detail=False, url_path="events/definitions/batch_unschedule")
    @ApiLog("批量禁用告警策略")
    def batch_unschedule_event_definitions(self, request):
        SyslogService.batch_unschedule_event_definitions(request.data.get("definitionids", []))
        logs = [
            dict(
                operator=request.user.username,
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module=APP_MODULE_NAME,
                obj_type=MONITOR,
                operate_obj=f"{definitionId}",
                operate_type=OperationLog.EXEC,
                operate_summary="禁用日志告警策略",
            )
            for definitionId in request.data.get("definitionids", [])
        ]
        batch_create_log(logs)
        return Response()

    @action(methods=["GET"], detail=False, url_path="views/functions")
    @ApiLog("获取函数")
    def views_functions(self, request):
        result = SyslogService.views_functions()
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="view_detail/(?P<id>.+?)")
    @ApiLog("获取保存条件详情")
    def view_detail(self, request, id):
        result = SyslogService.view_detail(url_param_dict=dict(id=id))
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="events/entity_types")
    @ApiLog("获取实体类型")
    def entity_types(self, request):
        result = SyslogService.entity_types()
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="notice/migrate")
    @ApiLog("初始化告警通知")
    def notice_migrate(self, request):
        init_migrate_notice()
        return Response()

    @action(methods=["GET"], detail=False, url_path="extractors/(?P<id>.+?)")
    @ApiLog("查询接收器下的提取器")
    def get_extractors(self, request, id):
        result = SyslogService.get_extractors(id)
        return Response(result)

    @action(methods=["DELETE"], detail=False, url_path="del_extractor/(?P<id>.+?)/(?P<ex_id>.+?)")
    @ApiLog("删除接收器下的提取器")
    def del_extractors(self, request, id, ex_id):
        SyslogService.del_extractors(id, ex_id)
        return Response()

    @action(methods=["POST"], detail=False, url_path="add_extractors/(?P<id>.+?)")
    @ApiLog("创建接收器下的提取器")
    def add_extractors(self, request, id):
        result = SyslogService.add_extractors(id, request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="order_extractors/(?P<id>.+?)")
    @ApiLog("提取器排序")
    def order_extractors(self, request, id):
        SyslogService.order_extractors(id, request.data)
        return Response()

    @action(methods=["PUT"], detail=False, url_path="update_extractor/(?P<id>.+?)/(?P<ex_id>.+?)")
    @ApiLog("修改接收器下的提取器")
    def update_extractors(self, request, id, ex_id):
        result = SyslogService.update_extractors(id, ex_id, request.data)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="extractor_detail/(?P<id>.+?)/(?P<ex_id>.+?)")
    @ApiLog("提取器详情")
    def extractor_detail(self, request, id, ex_id):
        result = SyslogService.extractor_detail(id, ex_id)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="import")
    @ApiLog("导入本地日志")
    def import_log(self, request):
        SyslogService.import_log(request.data)
        return Response()

    @action(methods=["GET"], detail=False, url_path="view_condition/(?P<id>.+?)")
    @ApiLog("查询视图条件")
    def view_condition(self, request, id):
        data = SyslogService.view_condition(id)
        return Response(data)

    @action(methods=["POST"], detail=False, url_path="log_clustering")
    @ApiLog("日志聚类查询")
    def log_clustering(self, request):
        data = SyslogService.log_clustering(**request.data)
        return Response(data)
