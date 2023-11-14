# -*- coding: utf-8 -*-

# @File    : casbin_middleware.py
# @Date    : 2022-07-01
# @Author  : windyzhao
import re

from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

from apps.system_mgmt.casbin_package.policy_constants import MESH_NAMESPACE
from apps.system_mgmt.constants import DB_SUPER_USER
from apps.system_mgmt.models import SysRole, SysUser
from apps.system_mgmt.common_utils.casbin_mesh_common import CasbinMeshApiServer
from apps.system_mgmt.common_utils.casbin_register_policy import MATCH_PASS_PATH, PASS_PATH
from utils.app_log import logger
from django.conf import settings
from blueapps.account import get_user_model


class CasbinRBACMiddleware(MiddlewareMixin):
    """
    接口只要有一处允许通过，那么此接口就允许访问
    接口在多处页面重复，那么由前端做按钮限制
    """

    @staticmethod
    def super(user):
        if settings.LOGIN_METHOD == "local":
            return get_user_model().objects.get(username=user).is_superuser
        else:
            if not SysRole.objects.filter(sysuser__bk_username=user).exists():
                return
            return SysRole.objects.filter(sysuser__bk_username=user, role_name=DB_SUPER_USER).exists()

    @staticmethod
    def super_role(user):
        is_super = SysRole.objects.filter(sysuser__bk_username=user, role_name=DB_SUPER_USER).exists()
        roles = []
        if is_super:
            return is_super, roles

        user_obj = SysUser.objects.filter(bk_username=user).first()
        if user_obj is not None:
            roles = user_obj.roles.all().values_list("role_name", flat=True)

        return False, list(roles)

    def process_view(self, request, view, args, kwargs):
        """
        data = ("admin","/get_user/","GET","sys_memg")
        """

        if getattr(view, "login_exempt", False):
            return None

        # 校验app
        if self.check_app(request):
            return None

        action = request.method
        path_info = request.path_info
        username = request.user.username

        # 校验白名单
        if self.check_white_list(path_info, action):
            return None

        # 超管放行
        if self.super(username):
            return None

        eft = CasbinMeshApiServer.enforce(namespace=MESH_NAMESPACE, params=[username, path_info, action])
        if eft:
            return None
        logger.info(f"[{username}] has no auth, path: {path_info}")
        response = JsonResponse({"result": False, "code": "40300", "message": "抱歉！您没有访问此功能的权限！", "data": None})
        response.status_code = 403

        return response

    @staticmethod
    def check_white_list(path_info, action):
        """
        白名单接口校验
        """
        # 白名单
        if (path_info, action) in PASS_PATH:
            return True

        for path, ac in MATCH_PASS_PATH:
            if ac != action:
                continue
            match_result = re.match(path, path_info)
            if match_result is not None:
                return True

        return False

    @staticmethod
    def check_app(request):
        """
        校验APP，符号条件的APP即不在进行api校验
        """
        # TODO 考虑是否对某些app指定免校验某些api
        my_app = request.META.get("HTTP_MY_APP")
        return False
