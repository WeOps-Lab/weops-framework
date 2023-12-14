from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from apps.syslog.services.index import IndexSetService
from apps.system_mgmt.casbin_package.permissions import ManagerPermission
from utils.decorators import ApiLog


class IndexViewSet(ViewSet):
    permission_classes = [IsAuthenticated, ManagerPermission]

    @action(methods=["PUT"], detail=False, url_path="default/(?P<id>.+?)")
    @ApiLog("设为默认索引集")
    def default_index(self, request, id):
        result = IndexSetService.default_index(id)
        return Response(result)

    @action(methods=["DELETE"], detail=False, url_path="delete/(?P<id>.+?)")
    @ApiLog("删除索引集")
    def delete_index(self, request, id):
        result = IndexSetService.delete_index(id, request.GET)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="create")
    @ApiLog("创建索引集")
    def add_index(self, request):
        result = IndexSetService.add_index(request.data)
        return Response(result)

    @action(methods=["PUT"], detail=False, url_path="update/(?P<id>.+?)")
    @ApiLog("修改索引集")
    def update_index(self, request, id):
        result = IndexSetService.update_index(id, request.data)
        return Response(result)

    @action(methods=["GET"], detail=False, url_path="index_set/(?P<id>.+?)")
    @ApiLog("索引集详情")
    def index_set(self, request, id):
        result = IndexSetService.index_set(id)
        return Response(result)

    @action(methods=["POST"], detail=False, url_path="index_rebuild/(?P<index_name>.+?)")
    @ApiLog("重新计算索引范围")
    def index_rebuild(self, request, index_name):
        IndexSetService.index_rebuild(index_name)
        return Response()

    @action(methods=["POST"], detail=False, url_path="index_reopen/(?P<index_name>.+?)")
    @ApiLog("重新打开索引")
    def index_reopen(self, request, index_name):
        IndexSetService.index_reopen(index_name)
        return Response()

    @action(methods=["POST"], detail=False, url_path="index_close/(?P<index_name>.+?)")
    @ApiLog("关闭索引")
    def index_close(self, request, index_name):
        IndexSetService.index_close(index_name)
        return Response()

    @action(methods=["DELETE"], detail=False, url_path="index_delete/(?P<index_name>.+?)")
    @ApiLog("删除索引")
    def index_delete(self, request, index_name):
        IndexSetService.index_delete(index_name)
        return Response()

    @action(methods=["POST"], detail=False, url_path="index_set_rebuild/(?P<id>.+?)")
    @ApiLog("更新索引集范围")
    def index_set_rebuild(self, request, id):
        IndexSetService.index_set_rebuild(id)
        return Response()

    @action(methods=["POST"], detail=False, url_path="create_index/(?P<id>.+?)")
    @ApiLog("创建新索引")
    def create_index(self, request, id):
        data = IndexSetService.create_index(id, request.data)
        return Response(data)

    @action(methods=["GET"], detail=False, url_path="index_set_overview/(?P<id>.+?)")
    @ApiLog("索引集索引数据详情")
    def index_set_overview(self, request, id):
        data = IndexSetService.index_set_overview(id)
        return Response(data)

    @action(methods=["GET"], detail=False, url_path="index_list/(?P<id>.+?)")
    @ApiLog("索引列表")
    def indexs(self, request, id):
        data = IndexSetService.indexs(id)
        return Response(data)

    @action(methods=["POST"], detail=False, url_path="indexs_multiple")
    @ApiLog("索引列表")
    def indexs_multiple(self, request):
        data = IndexSetService.indexs_multiple(request.data)
        return Response(data)

    @action(methods=["GET"], detail=False, url_path="index_sets_stats")
    @ApiLog("获取全局索引集")
    def index_sets_stats(self, request):
        data = IndexSetService.index_sets_stats(request.GET)
        return Response(data)
