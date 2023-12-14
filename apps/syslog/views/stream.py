from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from apps.syslog.constants import APP_MODULE_NAME, STREAM
from apps.syslog.services.stream import StreamService
from apps.system_mgmt.casbin_package.permissions import ManagerPermission
from apps.system_mgmt.models import OperationLog
from apps.system_mgmt.utils import create_log
from utils.decorators import ApiLog


class StreamViewSet(ViewSet):
    permission_classes = [IsAuthenticated, ManagerPermission]

    @action(methods=["GET"], detail=False, url_path="paginated")
    @ApiLog("查询数据流")
    def streams(self, request):
        result = StreamService.streams(request.user.username, request.GET)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="create")
    @ApiLog("创建数据流")
    def add_stream(self, request):
        stream_id = StreamService.add_stream(request.user.username, request.data)
        StreamService.start_stream(stream_id)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            STREAM,
            f"{request.data.get('title', '')}",
            OperationLog.ADD,
            f"创建日志分组{request.data.get('title', '')}。",
        )
        return Response(stream_id)

    @action(methods=["PUT"], detail=False, url_path="update/(?P<id>.+?)")
    @ApiLog("更新数据流")
    def update_stream(self, request, id):
        result = StreamService.update_stream(request.user.username, id, request.data)
        return Response(result)

    @action(methods=["DELETE"], detail=False, url_path="delete/(?P<id>.+?)")
    @ApiLog("删除数据流")
    def delete_stream(self, request, id):
        title = StreamService.delete_stream(request.user.username, id)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            STREAM,
            f"{title}",
            OperationLog.DELETE,
            f"删除日志分组{title}。",
        )
        return Response()

    @action(methods=["GET"], detail=False, url_path="detail/(?P<id>.+?)")
    @ApiLog("数据流详情")
    def stream_detail(self, request, id):
        result = StreamService.stream_detail(request.user.username, id)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="clone/(?P<id>.+?)")
    @ApiLog("克隆消息流")
    def clone_stearm(self, request, id):
        stream_id = StreamService.clone_stearm(request.user.username, id, request.data)
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            STREAM,
            f"{request.data.get('title', '')}",
            OperationLog.ADD,
            f"创建日志分组{request.data.get('title', '')}。",
        )
        return Response(stream_id)

    @action(methods=["GET"], detail=False, url_path="rule_types/(?P<id>.+?)")
    @ApiLog("查询规则类型")
    def rule_types(self, request, id):
        result = StreamService.rule_types(id)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="relative")
    @ApiLog("查询规则")
    def relative(self, request):
        result = StreamService.relative(request.GET)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="test_match/(?P<id>.+?)")
    @ApiLog("验证规则")
    def test_match(self, request, id):
        result = StreamService.test_match(id, request.data)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="add_rules/(?P<id>.+?)")
    @ApiLog("新增验证规则")
    def add_rule(self, request, id):
        result = StreamService.add_rule(id, request.data)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="rule_detail/(?P<id>.+?)/(?P<rule_id>.+?)")
    @ApiLog("规则详情")
    def rule_detail(self, request, id, rule_id):
        result = StreamService.rule_detail(id, rule_id)
        return Response(result)

    @action(methods=["PUT"], detail=False, url_path="update_rule/(?P<id>.+?)/(?P<rule_id>.+?)")
    @ApiLog("修改规则")
    def update_rule(self, request, id, rule_id):
        result = StreamService.update_rule(id, rule_id, request.data)
        return Response(result)

    @action(methods=["DELETE"], detail=False, url_path="del_rule/(?P<id>.+?)/(?P<rule_id>.+?)")
    @ApiLog("删除验证规则")
    def del_rule(self, request, id, rule_id):
        StreamService.del_rule(id, rule_id)
        return Response()

    @action(methods=["GET"], detail=False, url_path="system_fields")
    @ApiLog("规则详情")
    def system_fields(self, request):
        result = StreamService.system_fields()
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="index_sets")
    @ApiLog("索引集")
    def index_sets(self, request):
        result = StreamService.index_sets(request.GET)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="system_inputs")
    @ApiLog("匹配输入值列表")
    def system_inputs(self, request):
        result = StreamService.system_inputs()
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="role_streams/(?P<role_id>.+?)")
    @ApiLog("查询角色数据流列表")
    def get_role_streams(self, request, role_id):
        result = StreamService.get_role_streams(int(role_id))
        return Response(result)

    @get_role_streams.mapping.post
    @ApiLog("设置角色数据流")
    def set_role_streams(self, request, role_id):
        StreamService.set_role_streams(int(role_id), request.data.get("stream_list", []))
        create_log(
            request.user.username,
            getattr(request, "current_ip", "127.0.0.1"),
            APP_MODULE_NAME,
            STREAM,
            "设置角色日志分组",
            OperationLog.MODIFY,
            f"{request.user.username}设置了角色日志分组。",
        )
        return Response()

    @action(methods=["GET"], detail=False, url_path="user_streams")
    @ApiLog("查询用户授权的数据流")
    def get_user_streams(self, request):
        result = StreamService.get_user_streams(request.user.username, request.user.is_super)
        return Response(result)
