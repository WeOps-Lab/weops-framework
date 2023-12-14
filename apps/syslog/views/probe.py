import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from apps.syslog.celery_tasks import deal_job_result
from apps.syslog.constants import APP_MODULE_NAME, PROBE, SIDECAR
from apps.syslog.services.probe import ProbeService
from apps.system_mgmt.casbin_package.permissions import ManagerPermission
from apps.system_mgmt.models import OperationLog
from apps.system_mgmt.utils import batch_create_log
from blueapps.account.decorators import login_exempt
from utils.app_log import logger
from utils.decorators import ApiLog


@login_exempt
@csrf_exempt
def job_call_back(request):
    """文件下发后，作业平台回调函数"""
    logger.info("日志模块文件下发完成，作业平台回调!")
    try:
        params = json.loads(request.body)
        job_id = params.get("job_instance_id")
        job_code = params.get("status", 0)
        logger.info("回调作业实例ID{}状态{}!".format(job_id, job_code))
        deal_job_result.delay(job_id, job_code)
        return JsonResponse({"result": True, "data": "success"})
    except Exception as e:
        logger.exception("job_call_back error %s" % e)


class ProbeViewSet(ViewSet):
    permission_classes = [IsAuthenticated, ManagerPermission]

    @action(methods=["POST"], detail=False, url_path="host")
    @ApiLog("查询主机")
    def host(self, request):
        result = ProbeService.host_list(request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="node/list")
    @ApiLog("查询探针节点列表")
    def node_list(self, request):
        result = ProbeService.sidecar_list(request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="node/create")
    @ApiLog("创建探针节点")
    def create_node(self, request):
        for host in request.data.get("hosts"):
            host.update(
                ip=host["inner_ip"],
                os_type=host["os_type"].lower(),
            )

        exist_host = ProbeService.check_host(request.data.get("hosts"))

        if request.data.get("is_manual"):
            # 手动安装的主机过滤掉已经创建的节点
            if exist_host:
                request.data["hosts"] = [i for i in request.data.get("hosts", []) if i["bk_host_id"] not in exist_host]
            ProbeService.create_sidecar_by_manual(request.user.username, request.data)
        else:
            # 自动安装的主机如果存在已经创建的节点，则直接返回
            if exist_host:
                return JsonResponse(dict(result=False, message="存在已经创建的节点！", exist_host=list(exist_host.values())))
            ProbeService.create_sidecar(request.user.username, request.data)

        logs = [
            dict(
                operator=request.user.username,
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module=APP_MODULE_NAME,
                obj_type=SIDECAR,
                operate_obj=f"{host['ip']}-{host['bk_cloud_id']}",
                operate_type=OperationLog.ADD,
                operate_summary="创建控制器！",
            )
            for host in request.data.get("hosts", [])
        ]
        batch_create_log(logs)

        return Response()

    @action(methods=["GET"], detail=False, url_path="list")
    @ApiLog("查询探针列表")
    def probe_list(self, request):
        result = ProbeService.probe_list()
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="sidecar/action")
    @ApiLog("操作控制器")
    def action_sidecar(self, request):
        for host in request.data.get("hosts"):
            host.update(
                os_type=host["os_type"].lower(),
            )
        ProbeService.action_sidecar(request.data)

        logs = [
            dict(
                operator=request.user.username,
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module=APP_MODULE_NAME,
                obj_type=SIDECAR,
                operate_obj=f"{host['ip']}-{host['bk_cloud_id']}",
                operate_type=OperationLog.EXEC,
                operate_summary=f"控制器执行{request.data.get('action')}操作！",
            )
            for host in request.data.get("hosts", [])
        ]
        batch_create_log(logs)

        return Response()

    @action(methods=["POST"], detail=False, url_path="action")
    @ApiLog("操作探针")
    def action_probe(self, request):
        for host in request.data.get("hosts"):
            host.update(
                ip=host["inner_ip"],
                os_type=host["os_type"].lower(),
                sidecar_id=host["node_id"],
            )
        ProbeService.action_probe(request.data)

        logs = [
            dict(
                operator=request.user.username,
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module=APP_MODULE_NAME,
                obj_type=PROBE,
                operate_obj=f"{host['ip']}-{host['bk_cloud_id']}",
                operate_type=OperationLog.EXEC,
                operate_summary=f"探针执行{request.data.get('action')}操作！",
            )
            for host in request.data.get("hosts", [])
        ]
        batch_create_log(logs)

        return Response()

    @action(methods=["PUT"], detail=False, url_path="configs")
    @ApiLog("操作探针配置")
    def action_configs(self, request):
        ProbeService.action_probe_configs(request.data)
        return Response()

    @action(methods=["POST"], detail=False, url_path="install_steps")
    @ApiLog("获取安装步骤")
    def install_steps(self, request):
        result = ProbeService.get_installation_steps(request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="search_sidecar")
    @ApiLog("根据节点名称查询sidecar信息")
    def search_sidecar_by_nodes(self, request):
        result = ProbeService.search_sidecar_map(set(request.data.get("nodes", [])))
        return Response(result)
