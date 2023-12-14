# -- coding: utf-8 --

# @File : config_views.py
# @Time : 2023/6/8 10:39
# @Author : windyzhao
"""
采集器配置
"""
import os

from django.db.models import Q
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from apps.syslog.constants import COLOR, YAML_FILE_DIR
from apps.syslog.models import Node
from apps.syslog.services.config import SidecarConfigurationService
from apps.syslog.services.probe import ProbeService
from apps.syslog.utils.api import graylog_api
from apps.syslog.utils.probe import read_file, render_content
from apps.system_mgmt.models import OperationLog
from utils.app_log import logger
from utils.decorators import ApiLog


class SidecarCollectorsConfigViews(ViewSet):
    permission_classes = [IsAuthenticated]

    @ApiLog("查询指定id的采集器配置")
    @action(methods=["GET"], detail=False, url_path=r"configurations/(?P<configurations_id>\w+)")
    def get_configuration(self, request, configurations_id):

        resp = graylog_api.get_collectors_configuration(url_param_dict={"id": configurations_id})
        if resp["result"]:
            return Response(resp["data"])
        else:
            return Response({"detail": "查询失败！请检查配置id是否正确或联系管理员！"}, status=500)

    @ApiLog("查询采集器配置列表")
    @action(methods=["POST"], detail=False, url_path="get_configurations")
    def get_collectors_configurations(self, request):
        """
        查询配置列表
        """
        resp = SidecarConfigurationService.get_configurations(params=request.data)
        return Response(resp)

    @ApiLog("创建采集器配置")
    @action(methods=["POST"], detail=False, url_path="configurations")
    def create_collectors_configurations(self, request):
        """
        创建采集器配置
        """
        data = request.data
        params = data.get("params")  # 映射参数
        config_name = data["name"]  # 配置名称
        collector_name = data["collector_name"]  # 采集器名称
        template = data.get("template")

        # 通过采集器名称+操作系统 查询到 采集器的id
        collector_id = SidecarConfigurationService.search_collectors_id(collector_name, data["os_type"])
        if not collector_id:
            return Response({"detail": "采集器模版不存在！"}, status=500)

        # 通过采集器名称查询到采集器的配置的render数据
        if not template:
            file_path = os.path.join(YAML_FILE_DIR, f"{collector_name.lower()}.yml")
            template = render_content(read_file(file_path), params)

        created_params = {"color": COLOR, "name": config_name, "collector_id": collector_id, "template": template}
        resp = graylog_api.create_collectors_configurations(json=created_params)
        if resp["result"]:
            OperationLog.objects.create(
                operator=request.user.username,
                operate_type=OperationLog.ADD,
                operate_obj=config_name,
                operate_summary="新增采集配置:【{}】".format(config_name),
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module="日志管理",
                obj_type="采集配置",
            )
            return Response(resp["data"])

        if not resp["result"] or resp["message"].get("errors").get("failed", False):
            try:
                detail = ",".join(*resp["message"].get("errors").values())
            except Exception:
                detail = "创建失败！请联系管理员！"

            logger.warning("创建采集器配置失败! res={}".format(resp))
            return Response({"detail": detail}, status=500)

    @ApiLog("删除采集器配置")
    @action(methods=["DELETE"], detail=False, url_path=r"(?P<configurations_id>\w+)/configurations")
    def delete_collectors_configurations(self, request, configurations_id):
        """
        删除采集器配置
        """
        resp = graylog_api.delete_collectors_configurations(url_param_dict={"id": configurations_id})
        if not resp["result"]:
            logger.warning("删除id为【{}】的采集器配置失败! res={}".format(configurations_id, resp))
            return Response({"detail": "删除失败！请联系管理员！"}, status=500)

        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.DELETE,
            operate_obj=configurations_id,
            operate_summary="删除id为【{}】的采集器配置".format(configurations_id),
            current_ip=getattr(request, "current_ip", "127.0.0.1"),
            app_module="日志管理",
            obj_type="采集配置",
        )

        return Response()

    @ApiLog("复制采集器配置")
    @action(methods=["POST"], detail=False, url_path="copy_configurations")
    def copy_collectors_configurations(self, request):
        """
        复制采集器配置
        """

        data = request.data
        resp = graylog_api.copy_collectors_configurations(url_param_dict=dict(id=data["id"], name=data["name"]))

        if not resp["result"]:
            logger.warning("复制id为【{}】的采集器配置失败! res={}".format(data["id"], resp))
            return Response({"detail": "复制失败！请联系管理员！"}, status=500)

        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.ADD,
            operate_obj=data["name"],
            operate_summary="复制新的采集配置【{}】".format(data["name"]),
            current_ip=getattr(request, "current_ip", "127.0.0.1"),
            app_module="日志管理",
            obj_type="采集配置",
        )

        return Response()

    @ApiLog("修改采集器配置")
    @action(methods=["PUT"], detail=False, url_path="update_configurations")
    def update_collectors_configurations(self, request):
        """
        修改采集器配置
        """
        data = request.data
        # 使用操作系统+去查询
        params = {
            "color": COLOR,
            "name": data["name"],  # 配置名称
            "id": data["id"],  # 配置id
            "collector_id": data["collector_id"],  # 采集器id
            "template": data["template"],
        }
        resp = graylog_api.update_collectors_configurations(url_param_dict={"id": data["id"]}, json=params)
        if not resp["result"]:
            logger.warning("修改id为【{}】的采集器配置失败! res={}".format(data["id"], resp))
            return Response({"detail": "修改失败！请联系管理员！"}, status=500)

        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.MODIFY,
            operate_obj=data["name"],
            operate_summary="修改名称为【{}】的采集配置".format(data["name"]),
            current_ip=getattr(request, "current_ip", "127.0.0.1"),
            app_module="日志管理",
            obj_type="采集配置",
        )

        return Response(resp["data"])

    @ApiLog("查询使用节点的数据列表")
    @action(methods=["POST"], detail=False, url_path="get_use_nodes")
    def get_use_nodes(self, request):
        """
        查询使用节点的数据
        """
        nodes = request.data.get("nodes")  # 节点数据
        page = request.data.get("page", 1)
        page_size = request.data.get("page_size", 10)
        condition = request.data.get("conditions", [])
        start, end = (page - 1) * page_size, page * page_size
        bk_host_ids = Node.objects.filter(node_name__in=[i["node_name"] for i in nodes])[start:end].values_list(
            "bk_host_id", flat=True
        )
        condition.append({"key": "bk_host_id", "value": list(bk_host_ids)})
        res = ProbeService.sidecar_list(kwargs=dict(conditions=condition))
        return Response(res)

    @ApiLog("查询未用节点的数据列表")
    @action(methods=["POST"], detail=False, url_path="nodes")
    def nodes(self, request):
        """
        查询未使用的节点数据
        节点安装的探针类型是filebeat，但是filebeat使用的配置不是这个配置01的
        查询出来应用上
        """
        nodes = request.data.get("nodes")  # 节点数据
        page = request.data.get("page", 1)
        condition = request.data.get("condition", [])
        page_size = request.data.get("page_size", 10)
        start, end = (page - 1) * page_size, page * page_size
        bk_host_ids = Node.objects.filter(~Q(node_name__in=[i["node_name"] for i in nodes]))[start:end].values_list(
            "bk_host_id", flat=True
        )
        condition.append({"key": "bk_host_id", "value": list(bk_host_ids)})
        res = ProbeService.sidecar_list(kwargs=dict(conditions=condition))
        return Response(res)

    @ApiLog("节点采集器应用配置")
    @action(methods=["POST"], detail=False, url_path="associative_configuration")
    def associative_configuration(self, request):
        """
        把配置和采集器关联
        """
        data = request.data
        configuration_id = data["id"]  # 配置id
        collector_id = data["collector_id"]  # 采集器id
        node_names = data["node_names"]  # 节点名称数组
        node_dict = SidecarConfigurationService.get_node_data()
        if not node_dict:
            return Response({"detail": "应用配置失败！请联系管理员！"}, status=500)

        error_list = []
        success_list = []
        for node_name in node_names:
            node_data = node_dict.get(node_name)
            if not node_data:
                error_list.append(node_name)
                continue

            add_assignments = {"collector_id": collector_id, "configuration_id": configuration_id}
            if add_assignments in node_data["assignments"]:
                success_list.append(node_name)
                continue

            # 采集器新的配置 + 去掉此采集器已存在配置
            _node_data = [add_assignments] + [i for i in node_data["assignments"] if i["collector_id"] != collector_id]
            node_data["assignments"] = _node_data

            resp = graylog_api.associative_configuration(json={"nodes": [node_data]})
            if resp["result"]:
                success_list.append(node_name)
            else:
                logger.warning("节点为【{}】的采集器【{}】应用配置失败! res={}".format(node_name, collector_id, resp))
                error_list.append(node_name)

        error_node = ",".join(error_list)
        success_node = ",".join(success_list)
        if not success_node:
            return Response({"detail": "应用配置失败！请联系管理员！"}, status=500)

        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.ADD,
            operate_obj=node_names,
            operate_summary="节点应用配置.应用成功配置节点【{}】,应用失败配置节点【{}】".format(success_node, error_node),
            current_ip=getattr(request, "current_ip", "127.0.0.1"),
            app_module="日志管理",
            obj_type="采集配置",
        )

        return Response({"success": success_node, "error": error_node})
