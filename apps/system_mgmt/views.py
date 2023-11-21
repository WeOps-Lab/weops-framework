# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云PaaS平台社区版 (BlueKing PaaS Community
Edition) available.
Copyright (C) 2017-2020 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import hashlib
import json
import logging
import os
import random
import re
import string
import time

import requests
from django.conf import settings
from django.db import transaction
from django.db.models import Q, QuerySet
from django.db.transaction import atomic
from django.http import JsonResponse
from django.http import HttpResponseBadRequest
from rest_framework.request import Request
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from keycloak import KeycloakOpenID, KeycloakOpenIDConnection, KeycloakAdmin

# 开发框架中通过中间件默认是需要登录态的，如有不需要登录的，可添加装饰器login_exempt
# 装饰器引入 from blueapps.account.decorators import login_exempt
from rest_framework.decorators import action
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from django.apps import apps
from apps.system_mgmt import constants as system_constants
from apps.system_mgmt.KeycloakTokenAuthentication import KeycloakTokenAuthentication
from apps.system_mgmt.KeycloakIsAutenticated import KeycloakIsAuthenticated
from apps.system_mgmt.casbin_package.permissions import ManagerPermission, get_user_roles
from apps.system_mgmt.constants import DB_APPS, DB_MENU_IDS, MENUS_MAPPING
from apps.system_mgmt.filters import (
    InstancesPermissionsFilter,
    MenuManageFilter,
    NewSysUserFilter,
    OperationLogFilter,
    SysRoleFilter,
    SysUserFilter,
)
from apps.system_mgmt.models import InstancesPermissions, MenuManage, OperationLog, SysRole, SysSetting, SysUser
from apps.system_mgmt.pages import LargePageNumberPagination
from apps.system_mgmt.serializers import (
    InstancesPermissionsModelSerializer,
    LogSerializer,
    MenuManageModelSerializer,
    OperationLogSer,
    SysRoleSerializer,
    SysSettingSer,
    SysUserSerializer,
)
from apps.system_mgmt.user_manages import UserManageApi
from apps.system_mgmt.utils import UserUtils
from apps.system_mgmt.utils_package.controller import RoleController, UserController, KeyCloakUserController
from apps.system_mgmt.utils_package.inst_permissions import InstPermissionsUtils
from blueapps.account.components.weixin.weixin_utils import WechatUtils
from blueapps.account.decorators import login_exempt

from blueking.component.shortcuts import get_client_by_user
from apps.system_mgmt.common_utils.bk_api_utils.main import ApiManager
from apps.system_mgmt.common_utils.casbin_inst_service import CasBinInstService
from apps.system_mgmt.constants import USER_CACHE_KEY
from packages.drf.viewsets import ModelViewSet
from utils.app_log import logger

from utils.decorators import ApiLog, delete_cache_key_decorator
from utils.usermgmt_sql_utils import UsermgmtSQLUtils


@login_exempt
@require_POST
def test_post(request):
    return JsonResponse({"result": True, "data": {}})


@login_exempt
@require_GET
def test_get(request):
    return JsonResponse({"result": True, "data": {}})


@login_exempt
@csrf_exempt
def reset_policy_init(request):
    """
    手动初始化新的policy到数据库
    """
    if request.method != "POST":
        return JsonResponse({"result": False, "message": "请求方式不允许！"})

    res = RoleController.open_set_casbin_mesh()

    return JsonResponse({"result": res, "message": "初始化成功" if res else "初始化失败！错误信息请查询日志！"})


@login_exempt
@csrf_exempt
@require_POST
def open_create_user(request, *args, **kwargs):
    """
    对外开放接口
    创建用户
    data = {
            "username": "hhhopen_user",
            "display_name": "测试开放接口",
            "email": "111@qq.com",
            "telephone": "13237897621"
            }
    """
    try:
        data = json.loads(request.body)
    except Exception as err:
        logger.exception("对外开放接口[open_create_user]参数错误，无法序列化！error={}".format(err))
        res = {"result": False, "data": {}, "message": "参数错误！"}
        return JsonResponse(data=res)

    try:
        manage_api = UserManageApi()
        res = UserController.open_create_user(data, manage_api, SysUserSerializer)
    except Exception as e:
        logger.exception("对外开放接口[open_create_user]执行错误！error={}".format(e))
        res = {"result": False, "data": {}, "message": "创建用户失败! 请联系管理员！"}

    return JsonResponse(data=res)


@login_exempt
@csrf_exempt
@require_POST
def open_set_user_roles(request, *args, **kwargs):
    """
    对外开放接口
    设置用户角色
    data = {
            "user_id":77,
            "roles":[16]
            }
    """
    try:
        data = json.loads(request.body)
    except Exception as err:
        logger.exception("对外开放接口[open_set_user_roles]参数错误，无法序列化！error={}".format(err))
        res = {"result": False, "data": {}, "message": "参数错误！"}
        return JsonResponse(data=res)
    try:
        res = UserController.open_set_user_roles(data)
    except Exception as e:
        logger.exception("对外开放接口[open_set_user_roles]执行错误！error={}".format(e))
        res = {"result": False, "data": {}, "message": "设置用户角色失败！请联系管理员"}

    return JsonResponse(data=res)


class LogoViewSet(RetrieveModelMixin, UpdateModelMixin, GenericViewSet):
    permission_classes = [IsAuthenticated, ManagerPermission]
    queryset = SysSetting.objects.all()
    serializer_class = LogSerializer

    def get_object(self):
        obj, created = self.get_queryset().get_or_create(
            key=system_constants.SYSTEM_LOGO_INFO["key"],
            defaults=system_constants.SYSTEM_LOGO_INFO,
        )
        return obj

    def get_permissions(self):
        if self.action == "retrieve":
            self.permission_classes = [IsAuthenticated]
        return super().get_permissions()

    def update(self, request, *args, **kwargs):
        file_obj = request.FILES.get("file", "")
        instance = self.get_object()
        data = request.data
        data["file"] = file_obj
        serializer = self.get_serializer(instance, data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.MODIFY,
            operate_obj="Logo设置",
            operate_summary="修改Logo为:[{}]".format(file_obj.name if file_obj else ""),
            current_ip=current_ip,
            app_module="系统管理",
            obj_type="系统设置",
        )
        return Response(serializer.data)

    def reset(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.value = system_constants.SYSTEM_LOGO_INFO["value"]
        instance.save()
        serializer = self.get_serializer(instance)
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.MODIFY,
            operate_obj="Logo设置",
            operate_summary="logo恢复默认",
            current_ip=current_ip,
            app_module="系统管理",
            obj_type="系统设置",
        )
        return Response(serializer.data)


class SysUserViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, ManagerPermission]
    queryset = SysUser.objects.all()
    serializer_class = SysUserSerializer
    ordering_fields = ["created_at"]
    ordering = ["-created_at"]
    filter_class = SysUserFilter
    pagination_class = LargePageNumberPagination

    def list(self, request, *args, **kwargs):
        page_size = request.GET["page_size"]
        if page_size == "-1":
            # 返回全部的数据
            return Response({"items": self.queryset.values("chname", "bk_username", "bk_user_id")})

        return super().list(request, *args, **kwargs)

    def get_permissions(self):
        if self.action == "pull_bk_user":
            self.permission_classes = [IsAuthenticated]
        return super().get_permissions()

    @delete_cache_key_decorator(USER_CACHE_KEY)
    @action(methods=["POST"], detail=False, url_path="pull_bk_user")
    def pull_bk_user(self, request, *args, **kwargs):
        UserUtils.pull_sys_user()
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.ADD,
            operate_obj=SysUser._meta.verbose_name,
            operate_summary="手动拉取蓝鲸用户",
            current_ip=current_ip,
            app_module="系统管理",
            obj_type="用户",
        )

        return Response({})

    # @action(methods=["GET"], detail=False, url_path="bizs")
    # def get_bizs(self, request, *args, **kwargs):
    #     res = get_user_biz_list(request)
    #     return Response(res)


class OperationLogViewSet(ListModelMixin, GenericViewSet):
    permission_classes = [IsAuthenticated, ManagerPermission]
    queryset = OperationLog.objects.all()
    serializer_class = OperationLogSer
    ordering_fields = ["created_at"]
    ordering = ["-created_at"]
    filter_class = OperationLogFilter


class SysSettingViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, ManagerPermission]
    queryset = SysSetting.objects.all()
    serializer_class = SysSettingSer
    ordering_fields = ["created_at"]
    ordering = ["-created_at"]
    lookup_field = "key"

    @action(methods=["GET"], detail=False)
    @ApiLog("获取登录配置")
    def get_login_set(self, request):
        sys_set_list = SysSetting.objects.filter(
            key__in=["two_factor_enable", "auth_type", "auth_white_list", "default_domain"]
        )
        if not sys_set_list:
            user = SysUser.objects.get(bk_username="admin")
            return JsonResponse(
                {
                    "result": True,
                    "data": {
                        "auth_type": ["mail"],
                        "two_factor_enable": False,
                        "auth_white_list": {
                            "user": [{"bk_username": "admin", "chname": user.chname, "id": user.id}],
                            "role": [],
                        },
                    },
                }
            )
        return_data = {i.key: i.real_value for i in sys_set_list}
        if "default_domain" not in return_data:
            return_data["default_domain"] = ""
        return JsonResponse({"result": True, "data": return_data})

    @action(methods=["GET"], detail=False)
    @ApiLog("获取所有的域")
    def get_domain(self, request):
        client = UsermgmtSQLUtils()
        return_data = client.get_domain()
        client.disconnect()
        return JsonResponse({"result": True, "data": return_data})

    @action(methods=["POST"], detail=False)
    @ApiLog("设置默认域")
    def set_domain(self, request):
        SysSetting.objects.update_or_create(
            key="default_domain",
            defaults={"value": request.data.get("default_domain", "")},
        )
        return JsonResponse({"result": True})

    @action(methods=["POST"], detail=False)
    @ApiLog("修改双因子配置")
    def update_login_set(self, request):
        params = request.data
        set_list = []
        for key, value in params.items():
            if key not in ["two_factor_enable", "auth_type", "auth_white_list"]:
                continue
            set_list.append(SysSetting(key=key, value=json.dumps(value), vtype="json"))
        with atomic():
            SysSetting.objects.filter(key__in=["two_factor_enable", "auth_type", "auth_white_list"]).delete()
            SysSetting.objects.bulk_create(set_list)
            OperationLog.objects.create(
                operator=request.user.username,
                operate_type=OperationLog.MODIFY,
                operate_obj="多因子认证",
                operate_summary=f"用户{request.user.username}修改了多因子认证信息",
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module="系统配置",
                obj_type="多因子认证",
            )
        return JsonResponse({"result": True})

    @action(methods=["POST"], detail=False)
    @ApiLog("发送验证码")
    def send_validate_code(self, request):
        user = request.user.username
        result = _send_validate_code(user)
        return JsonResponse(result)

    @action(methods=["POST"], detail=False, url_path="wx_app_id")
    @ApiLog("获取微信/企业微信APP_ID")
    def get_weixin_app_id(self, request):
        path_url = request.data.get("path_url")
        wx_app_id = settings.WX_APP_ID
        timestamp = str(time.time())
        noncestr = "".join(random.sample(string.ascii_letters + string.digits, 16))
        params = {
            "jsapi_ticket": WechatUtils.jsapi_ticket(),
            "noncestr": noncestr,
            "timestamp": timestamp,
            "url": path_url,
        }
        signature = WechatUtils.generate_signature(params)
        return Response(data={"appId": wx_app_id, "timestamp": timestamp, "nonceStr": noncestr, "signature": signature})


from rest_framework import viewsets
from rest_framework import views, status
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token


class KeyCloakLoginView(views.APIView):
    '''
    该类用作验证登录
    '''
    # 让RDF不认证
    authentication_classes = []
    permission_classes = []

    keycloak_openid = KeycloakOpenID(
        server_url=f'http://{settings.KEYCLOAK_SETTINGS["KEYCLOAK_SERVER"]}:{settings.KEYCLOAK_SETTINGS["KEYCLOAK_PORT"]}/',
        client_id=f'{settings.KEYCLOAK_SETTINGS["CLIENT_ID"]}',
        realm_name=f'{settings.KEYCLOAK_SETTINGS["REALM_NAME"]}',
        client_secret_key=f'{settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"]}')

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='User username'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
            }
        ),
    )
    def post(self, request: Request) -> Response:
        # 从请求中获取用户名和密码
        username = request.data.get('username', None)
        password = request.data.get('password', None)
        if username is None or password is None:
            return Response({'detail': 'username or password are not present!'}, status=status.HTTP_400_BAD_REQUEST)

        # # 使用 Keycloak API 验证用户
        # response = self.authenticate_with_keycloak(username, password)
        # user_data = response.json()
        # if user_data:
        #     # 检查用户是否在本地数据库中
        #     user = get_user_model().objects.filter(username=username).first()
        #
        #     if not user:
        #         # 如果用户不在本地数据库中，创建本地用户
        #         user = get_user_model().objects.create(username=username)
        #
        #     # 返回令牌和成功响应
        #     # token, created = Token.objects.get_or_create(user=user)
        #     token = response.json().get("access_token")
        try:
            kc_response = self.keycloak_openid.token(username, password)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        token = kc_response.get('access_token', None)
        if token is None:
            # 用户验证失败，返回错误响应
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'token': token}, status=status.HTTP_200_OK)

    @classmethod
    def authenticate_with_keycloak(cls, username, password):
        keycloak_server = settings.KEYCLOAK_SERVER
        keycloak_port = settings.KEYCLOAK_PORT
        keycloak_url = f"http://{keycloak_server}:{keycloak_port}/realms/master/protocol/openid-connect/token"

        payload = {
            "client_id": "security-admin-console",
            "grant_type": "password",
            "username": username,
            "password": password,
        }
        response = requests.post(keycloak_url, data=payload)

        if response.status_code == 200:
            return response
        else:
            return None


class KeyCloakViewSet(viewsets.ViewSet):
    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]


    def __init__(self, *args, **kwargs):
        super(KeyCloakViewSet, self).__init__(*args, **kwargs)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('per_page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('search', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING),
        ]
    )
    @transaction.atomic
    @action(methods=["GET"], detail=False, url_path="get_users")
    @ApiLog("用户管理获取用户")
    def get_user(self, request: Request):
        page = request.query_params.get("page", 1)  # 获取请求中的页码参数，默认为第一页
        per_page = request.query_params.get("per_page", 10)  # 获取请求中的每页结果数，默认为10
        # bk_token = request.COOKIES.get('bk_token', None)
        res = KeyCloakUserController.get_user_list(**{"page": int(page), "per_page": int(per_page)
            , "token": request.auth, "search":request.query_params.get('search', None)})
        return Response(res)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='User username'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'lastName': openapi.Schema(type=openapi.TYPE_STRING, description='User last name'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
            },
            required=['username', 'password']
        ),
    )
    @transaction.atomic
    @action(methods=["POST"], detail=False, url_path="create_user")
    @ApiLog("用户管理创建用户")
    def create_keycloak_user_manage(self, request, *args, **kwargs):
        res = KeyCloakUserController.create_user(**{"request": request})
        return Response(res)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('user_id', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING)
        ]
    )
    @transaction.atomic
    @action(methods=["DELETE"], detail=False, url_path="delete_users")
    @ApiLog("用户管理删除用户")
    def delete_user(self, request : Request, *args, **kwargs):
        """
        删除用户
        """
        user_id = request.query_params.get('user_id', None)
        if user_id is None:
            return Response({"error":"user id is not present"}, status=status.HTTP_400_BAD_REQUEST)
        res = KeyCloakUserController.delete_user(**{"user_id": user_id, 'token':request.auth})
        return Response(res)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'user_id': openapi.Schema(type=openapi.TYPE_STRING, description='User id (Required)'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'firstName': openapi.Schema(type=openapi.TYPE_STRING, description='User first name'),
                'lastName': openapi.Schema(type=openapi.TYPE_STRING, description='User last name'),
            },
            required=['user_id']
        )
    )
    @transaction.atomic
    @action(methods=["PUT"], detail=False, url_path="update_user")
    @ApiLog("用户管理修改用户信息")
    def update_user(self, request):
        """
        修改用户信息
        """
        user_id = request.data.get('user_id', None)
        if user_id is None:
            return Response({"error": "user id is not present"}, status=status.HTTP_400_BAD_REQUEST)
        payload = dict()
        # 除了user_id其他属性放入payload
        for k in request.data.keys():
            if not k == 'user_id':
                payload[k] = request.data[k]
        res = KeyCloakUserController.update_user(**{"user_id":user_id, "payload":payload, "token":request.auth})
        return Response(res)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'id': openapi.Schema(type=openapi.TYPE_STRING, description='User id'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
            }
        ),
    )
    @transaction.atomic
    @action(methods=["PUT"], detail=False, url_path="reset_password")
    @ApiLog("用户管理重置密码")
    def reset_user_password(self, request):
        """
        重置用户密码
        """
        # id = request.data.get("id")
        # password = request.data.get("password")
        # bk_token = request.COOKIES.get('bk_token', None)
        user_id = request.data.get('user_id', None)
        password = request.data.get('password', None)
        if user_id is None or password is None:
            return Response({"error": "user_id or password is not present"}, status=status.HTTP_400_BAD_REQUEST)
        res = KeyCloakUserController.reset_password(**{"user_id": user_id, "password": password, "token": request.auth})
        return Response(res)


class UserManageViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = SysUser.objects.all()
    serializer_class = SysUserSerializer
    ordering_fields = ["created_at"]
    ordering = ["-created_at"]
    filter_class = NewSysUserFilter
    pagination_class = LargePageNumberPagination

    def __init__(self, *args, **kwargs):
        super(UserManageViewSet, self).__init__(*args, **kwargs)
        self.manage_api = UserManageApi()

    @action(methods=["GET"], detail=False, url_path="get_users")
    @ApiLog("用户管理获取用户")
    def bk_user_manage_list(self, request, *args, **kwargs):
        """
        获取用户
        """
        return super().list(request, *args, **kwargs)

    @action(methods=["GET"], detail=False)
    @ApiLog("多因子用户查询")
    def search_user_list(self, request, *args, **kwargs):
        """
        获取用户
        """
        page = int(request.GET.get("page", 1))
        page_size = int(request.GET.get("page_size", 20))
        search = request.GET.get("search", "")
        start = page_size * (page - 1)
        end = page_size * page

        user_list = SysUser.objects.filter(Q(bk_username__icontains=search) | Q(chname__icontains=search))
        user_count = user_list.count()
        return_data = list(user_list.values("id", "bk_username", "chname")[start:end])
        return JsonResponse({"result": True, "data": {"count": user_count, "items": return_data}})

    @delete_cache_key_decorator(USER_CACHE_KEY)
    @action(methods=["POST"], detail=False, url_path="create_user")
    @ApiLog("用户管理创建用户")
    def create_bk_user_manage(self, request, *args, **kwargs):
        """
        创建用户
        采用数据库事务控制
        先本地插入数据，再去请求用户中心
        若请求成功：
            更新入库，提交事务
        若请求失败：
            事务回滚

        最后返回前 都显性提交一次事务
        """
        res = UserController.add_user_controller(**{"request": request, "self": self, "manage_api": self.manage_api})
        return Response(**res)

    @action(methods=["PATCH"], detail=False, url_path="edit_user")
    @ApiLog("用户管理修改用户")
    def modify_bk_user_manage(self, request, *args, **kwargs):
        """
        修改用户
        """

        res = UserController.update_user_controller(**{"request": request, "self": self, "manage_api": self.manage_api})
        return Response(**res)

    @action(methods=["PATCH"], detail=False, url_path="reset_password")
    @ApiLog("用户管理重置密码")
    def reset_bk_user_password(self, request, *args, **kwargs):
        """
        重置密码
        """
        res = UserController.reset_user_password_controller(
            **{"request": request, "self": self, "manage_api": self.manage_api}
        )
        return Response(**res)

    @delete_cache_key_decorator(USER_CACHE_KEY)
    @action(methods=["DELETE"], detail=False, url_path="delete_users")
    @ApiLog("用户管理删除用户")
    def delete_bk_user_manage(self, request, *args, **kwargs):
        """
        删除用户
        """
        res = UserController.delete_user_controller(**{"request": request, "self": self, "manage_api": self.manage_api})
        return Response(**res)

    @action(methods=["POST"], detail=False, url_path="set_user_roles")
    @ApiLog("用户管理设置用户角色")
    def set_bk_user_roles(self, request, *args, **kwargs):
        """
        设置用户角色
        """
        res = UserController.set_user_roles_controller(**{"request": request, "self": self})
        return Response(**res)

    @action(methods=["PATCH"], detail=True)
    @ApiLog("设置用户角色状态")
    def update_user_status(self, request, pk):
        res = UserController.set_user_status(
            **{"request": request, "self": self, "manage_api": self.manage_api, "id": pk}
        )
        return Response(**res)


class RoleManageViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = SysRole.objects.prefetch_related("sysuser_set")
    serializer_class = SysRoleSerializer
    ordering_fields = ["-built_in", "created_at"]
    ordering = ["-built_in", "-created_at"]
    filter_class = SysRoleFilter
    pagination_class = LargePageNumberPagination

    @action(methods=["GET"], detail=False, url_path="get_roles")
    @ApiLog("角色管理获取角色")
    def bk_role_manage_list(self, request, *args, **kwargs):
        """
        获取角色 分页
        """
        return super().list(request, *args, **kwargs)

    @action(methods=["GET"], detail=False)
    @ApiLog("多因子角色查询")
    def search_role_list(self, request, *args, **kwargs):
        """
        获取角色 分页
        """
        page = int(request.GET.get("page", 1))
        page_size = int(request.GET.get("page_size", 10))
        search = request.GET.get("search", "")
        start = page_size * (page - 1)
        end = page_size * page
        role_list = SysRole.objects.filter(role_name__icontains=search)
        role_count = role_list.count()
        return_data = list(role_list.values("id", "role_name")[start:end])
        user_list = SysUser.objects.filter(roles__in=[i["id"] for i in return_data]).values("roles", "id")
        user_map = {}
        for i in user_list:
            user_map.setdefault(i["roles"], []).append(i["id"])
        for i in return_data:
            i["user_count"] = len(user_map.get(i["id"], []))
        return JsonResponse({"result": True, "data": {"count": role_count, "items": return_data}})

    @action(methods=["GET"], detail=False, url_path="get_all_roles")
    @ApiLog("角色管理获取全部角色")
    def bk_role_manage_all(self, request, *args, **kwargs):
        """
        获取全部角色
        """
        role_list = SysRole.objects.all().values("id", "role_name")
        return JsonResponse({"result": True, "data": list(role_list)})

    @action(methods=["POST"], detail=False, url_path="create_role")
    @ApiLog("角色管理创建角色")
    @transaction.atomic
    def create_bk_role_manage(self, request, *args, **kwargs):
        """
        创建角色
        """
        res = RoleController.create_role_controller(**{"request": request, "self": self})

        return Response(data=res)

    @action(methods=["PUT"], detail=False, url_path="edit_role")
    @ApiLog("角色管理修改角色")
    @transaction.atomic
    def update_bk_role_manage(self, request, *args, **kwargs):
        """
        修改角色，内置角色不能编辑
        """
        res = RoleController.update_role_controller(**{"request": request, "self": self})
        return Response(**res)

    @action(methods=["DELETE"], detail=False, url_path="delete_role")
    @ApiLog("角色管理删除角色")
    def delete_bk_role_manage(self, request, *args, **kwargs):
        """
        删除角色，内置角色不能删除
        """
        res = RoleController.delete_role_controller(**{"request": request})
        return Response(**res)

    @action(methods=["POST"], detail=False, url_path="set_role_menus")
    @ApiLog("角色管理设置角色菜单权限")
    def set_bk_role_menus(self, request, *args, **kwargs):
        """
        设置角色菜单权限，操作权限，应用权限
        """
        res = RoleController.set_role_menus_operates(**{"self": self, "request": request})
        return Response(**res)

    @action(methods=["GET"], detail=False, url_path="get_role_menus")
    @ApiLog("角色管获取角色菜单")
    def get_bk_role_manage_menus(self, request, *args, **kwargs):
        """
        获取角色菜单
        """
        resource = RoleController.get_role_resources(**{"request": request, "app_key": DB_MENU_IDS})
        operate_ids = RoleController.get_role_operate_ids(request=request)

        return Response(data={"menus_ids": resource, "operate_ids": operate_ids})

    @action(methods=["GET"], detail=False, url_path="get_role_applications")
    @ApiLog("角色管理获取角色应用")
    def get_bk_role_manage_applications(self, request, *args, **kwargs):
        """
        获取角色应用
        """
        res = RoleController.get_role_resources(**{"request": request, "app_key": DB_APPS})
        return Response(res)

    @action(methods=["GET"], detail=False, url_path="menus")
    @ApiLog("查询菜单权限中的监控和资产数据的其他分类")
    def get_role_other_menus(self, request, *args, **kwargs):
        """
        查询菜单权限中的监控和资产数据的其他分类
        TODO 根据购买的模块 进行把 监控/云/资产进行判断 没有购买的就不返回
        """
        res = RoleController.get_menus()
        return Response(data=res)

    @action(methods=["GET"], detail=False, url_path="applications")
    @ApiLog("查询weops功能模块")
    def get_applications(self, request, *args, **kwargs):
        """
        查询weops功能模块
        """
        res = RoleController.get_applications()
        return Response(data=res)

    @action(methods=["POST"], detail=True)
    @ApiLog("通过角色设置用户角色")
    def role_set_users(self, request, *args, **kwargs):
        res = RoleController.role_set_users(self=self, request=request)
        return Response(**res)

    @staticmethod
    def create_alarmcenter_data(request):
        request_data = request.data
        data = {
            "name": request_data.get("role_name"),
            "desc": request_data.get("describe"),
            "type": "self_built",
            "user_id_list": [],
            "is_enable": 1,
            "can_delete": 1,
            "can_modify": 1,
            "cookies": request.COOKIES,
        }
        res = ApiManager.uac.create_alarmcenter_data(**data)
        return res

    def relate_alarm_role_user(self, request):
        self.sync_alarmcenter_user(request)
        group_data = self.get_group_data(request)
        group_id = group_data.pop("id")
        id_data = self.get_user_id(request)
        group_data["user_id_list"] = id_data
        group_data["cookies"] = request.COOKIES
        group_data["url_params"] = {"group_id": group_id}
        ApiManager.uac.set_alarm_group_user(**group_data)

    def sync_alarmcenter_user(self, request):
        data = {"cookies": request.COOKIES}
        ApiManager.uac.sync_alarmcenter_user(**data)

    @staticmethod
    def get_group_data(request):
        group_obj = SysRole.objects.filter(id=request.data.get("id")).first()
        data = {"name": group_obj.role_name, "cookies": request.COOKIES}
        res = ApiManager.uac.accord_name_search_info(**data)
        return res.get("data")

    @staticmethod
    def get_user_id(request):
        user_id_list = request.data.get("users")
        user_name_list = list(SysUser.objects.filter(id__in=user_id_list).values_list("bk_username", flat=True))
        data = {"user_name_list": user_name_list, "cookies": request.COOKIES}
        res = ApiManager.uac.accord_name_search_userid(**data)
        return res.get("data")

    # @action(detail=False, methods=["GET"])
    # @ApiLog("将用户组同步达到告警中心")
    # def sync_alarm_center_group(self, request):
    #     all_role_obj = list(SysRole.objects.all().values("role_name", "describe"))
    #     role_user_map = list(SysUser.objects.annotate(role_id=F("roles")).values("roles__role_name", "bk_username"))
    #     role_users = {}
    #     all_role_obj = self.dispose_group_data(role_user_map, role_users, all_role_obj)
    #     group_data = {"group_data": all_role_obj, "cookies": request.COOKIES}
    #     res = ApiManager.uac.sync_alarm_center_group(**group_data)
    #     if not res["result"]:
    #         raise BlueException("同步告警中心失败，请联系管理员！")
    #     return Response("用户组同步告警中心成功")

    @staticmethod
    def dispose_group_data(role_user_map, role_users, all_role_obj):
        for role_user_obj in role_user_map:
            if role_user_obj["roles__role_name"] not in role_users:
                role_users[role_user_obj["roles__role_name"]] = []
            role_users[role_user_obj["roles__role_name"]].append(role_user_obj["bk_username"])
        for role_obj in all_role_obj:
            role_obj["name"] = role_obj.pop("role_name")
            role_obj["desc"] = role_obj.pop("describe")
            role_obj["type"] = "self_built"
            role_obj["is_enable"] = 1
            role_obj["can_delete"] = 1
            role_obj["can_modify"] = 1
            if role_obj["name"] not in role_users:
                role_obj["user_id_list"] = []
                continue
            role_obj["user_id_list"] = role_users[role_obj["name"]]
        return all_role_obj


class MenuManageModelViewSet(ModelViewSet):
    """
    自定义菜单管理
    """

    permission_classes = [IsAuthenticated]
    queryset = MenuManage.objects.all()
    serializer_class = MenuManageModelSerializer
    ordering = ["created_at"]
    ordering_fields = ["created_at"]
    filter_class = MenuManageFilter
    pagination_class = LargePageNumberPagination

    @ApiLog("修改自定义菜单")
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.default:
            return Response(data={"success": False, "detail": "默认菜单不允许修改！"}, status=500)

        serializer = self.get_serializer(instance, data=request.data, partial=False)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.MODIFY,
            operate_obj=instance.menu_name,
            operate_summary="自定义菜单管理修改自定义菜单:[{}]".format(instance.menu_name),
            current_ip=getattr(request, "current_ip", "127.0.0.1"),
            app_module="系统管理",
            obj_type="自定义菜单管理",
        )
        return Response(serializer.data)

    @ApiLog("查询自定义菜单列表")
    def list(self, request, *args, **kwargs):
        return super(MenuManageModelViewSet, self).list(request, *args, **kwargs)

    @ApiLog("创建自定义菜单")
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        instance = serializer.instance
        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.ADD,
            operate_obj=instance.menu_name,
            operate_summary="自定义菜单管理新增自定义菜单:[{}]".format(instance.menu_name),
            current_ip=getattr(request, "current_ip", "127.0.0.1"),
            app_module="系统管理",
            obj_type="自定义菜单管理",
        )
        return Response(serializer.data)

    @ApiLog("删除自定义菜单")
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        if instance.use:
            return Response(data={"success": False, "detail": "已启用的菜单不允许删除！"}, status=500)

        if instance.default:
            return Response(data={"success": False, "detail": "默认菜单不允许删除！"}, status=500)

        instance.delete()
        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.DELETE,
            operate_obj=instance.menu_name,
            operate_summary="自定义菜单管理删除自定义菜单:[{}]".format(instance.menu_name),
            current_ip=getattr(request, "current_ip", "127.0.0.1"),
            app_module="系统管理",
            obj_type="自定义菜单管理",
        )
        return Response(data={"success": True})

    @ApiLog("启用自定义菜单")
    @transaction.atomic
    @action(methods=["PATCH"], detail=True)
    def use_menu(self, request, *args, **kwargs):
        """
        关闭启用的
        设置此对象为启用
        """
        instance = self.get_object()
        self.queryset.update(use=False)
        instance.use = True
        instance.save()
        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.MODIFY,
            operate_obj=instance.menu_name,
            operate_summary="自定义菜单管理启用自定义菜单:[{}]".format(instance.menu_name),
            current_ip=getattr(request, "current_ip", "127.0.0.1"),
            app_module="系统管理",
            obj_type="自定义菜单管理",
        )
        return Response(data={"success": True})

    @ApiLog("获取启用自定义菜单")
    @action(methods=["GET"], detail=False)
    def get_use_menu(self, request, *args, **kwargs):
        instance = self.queryset.get(use=True)
        return Response(instance.menu)


class InstancesPermissionsModelViewSet(ModelViewSet):
    """
    实例权限管理
    """

    permission_classes = [IsAuthenticated, ManagerPermission]
    queryset = InstancesPermissions.objects.all()
    serializer_class = InstancesPermissionsModelSerializer
    ordering = ["-created_at"]
    ordering_fields = ["-created_at"]
    filter_class = InstancesPermissionsFilter
    pagination_class = LargePageNumberPagination

    @ApiLog("查询实例类型的具体实例列表")
    @action(methods=["GET"], detail=False)
    def get_instances(self, request):
        params = request.GET.dict()
        result = InstPermissionsUtils.instances(params["instance_type"], params, request, self)
        if isinstance(result, dict):
            return Response(result)
        elif isinstance(result, QuerySet):
            page = self.paginate_queryset(result)
            return self.get_paginated_response(page)
        else:
            return result

    @ApiLog("查询实例权限的权限类型")
    @action(methods=["GET"], detail=False)
    def get_instance_types(self, request):
        result = InstPermissionsUtils.get_model_attrs()
        return Response(result)

    @ApiLog("查询实例权限的权限类型")
    @action(methods=["GET"], detail=False)
    def get_monitor_attrs(self, request):
        params = request.GET.dict()
        bk_obj_id = params.get("bk_obj_id")
        instance_type = params.get("instance_type")
        result = InstPermissionsUtils.get_monitor_and_monitor_policy_attr(instance_type, bk_obj_id)
        return Response(result)

    @ApiLog("查询实例权限详情")
    def retrieve(self, request, *args, **kwargs):
        # TODO 返回选择实例的详情给前端回显
        instance = self.get_object()
        res = {
            "instance_type": instance.instance_type,
            "permissions": instance.permissions,
            "role": instance.role.id,
            "instances": instance.instances,
        }
        return Response(data=res)

    @ApiLog("查询实例权限列表")
    def list(self, request, *args, **kwargs):
        return super(InstancesPermissionsModelViewSet, self).list(request, *args, **kwargs)

    @ApiLog("创建实例权限对象")
    def create(self, request, *args, **kwargs):
        result = {}
        with transaction.atomic():
            sid = transaction.savepoint()
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            OperationLog.objects.create(
                operator=request.user.username,
                operate_type=OperationLog.ADD,
                operate_obj=request.data["instance_type"],
                operate_summary="创建实例权限对象:【{}".format(request.data["instance_type"]),
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module="系统管理",
                obj_type="角色管理",
            )
            try:
                inst_data = {"id": serializer.data["id"]}
                inst_data.update(request.data)
                policies = CasBinInstService.operator_polices(inst_data)
                res = CasBinInstService.create_policies(policies=policies, sec="p", ptype="p")
                if not res:
                    raise Exception(res)
            except Exception as err:
                logger.exception("新增policy到casbin失败！创建回滚！error={}".format(err))
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                result.update(dict(status=500, data={"success": False, "detail": "创建失败！请联系管理员"}))

        return Response(**result)

    @ApiLog("修改实例权限对象")
    def update(self, request, *args, **kwargs):
        result = {}
        with transaction.atomic():
            sid = transaction.savepoint()
            partial = kwargs.pop("partial", False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            OperationLog.objects.create(
                operator=request.user.username,
                operate_type=OperationLog.MODIFY,
                operate_obj=instance.instance_type,
                operate_summary="修改实例权限对象:【{}".format(instance.instance_type),
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module="系统管理",
                obj_type="角色管理",
            )
            try:
                # 删除掉旧的 新增新的
                remove_res = CasBinInstService.remove_filter_policies(
                    sec="p", ptype="p", field_index=4, field_values=instance.id
                )
                if not remove_res:
                    raise Exception(remove_res)

                inst_data = {"id": serializer.data["id"]}
                inst_data.update(request.data)
                # policies = CasBinInstService.operator_polices(inst_data)
                # res = CasBinInstService.create_policies(policies=policies, sec="p", ptype="p")
                # if not res:
                #     raise Exception(res)
            except Exception as err:
                logger.exception("新增policy到casbin失败！创建回滚！error={}".format(err))
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                result.update(dict(status=500, data={"success": False, "detail": "修改失败！请联系管理员"}))

        return Response(**result)

    @ApiLog("删除实例权限对象")
    def destroy(self, request, *args, **kwargs):
        result = {}
        with transaction.atomic():
            sid = transaction.savepoint()
            instance = self.get_object()
            self.perform_destroy(instance)
            OperationLog.objects.create(
                operator=request.user.username,
                operate_type=OperationLog.DELETE,
                operate_obj=instance.instance_type,
                operate_summary="删除实例权限对象:【{}".format(instance.instance_type),
                current_ip=getattr(request, "current_ip", "127.0.0.1"),
                app_module="系统管理",
                obj_type="角色管理",
            )
            remove_res = CasBinInstService.remove_filter_policies(
                sec="p", ptype="p", field_index=4, field_values=instance.id
            )
            if not remove_res:
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                result.update(dict(status=500, data={"success": False, "detail": "删除失败！请联系管理员"}))

        return Response(**result)


@login_exempt
def get_is_need_two_factor(request):
    user = request.GET["user"]
    if user == "admin":
        return JsonResponse({"result": True, "is_need": False})
    sys_set = SysSetting.objects.filter(key="two_factor_enable").first()
    if not sys_set or not sys_set.real_value:
        return JsonResponse({"result": True, "is_need": False})
    white_obj = SysSetting.objects.get(key="auth_white_list").real_value
    user_list = [i["bk_username"] for i in white_obj["user"]]
    if user in user_list:
        return JsonResponse({"result": True, "is_need": False})
    is_white = SysUser.objects.filter(roles__in=[i["id"] for i in white_obj["role"]], bk_username=user).exists()
    return JsonResponse({"result": True, "is_need": not is_white})


@login_exempt
@csrf_exempt
def send_validate_code_exempt(request):
    user = json.loads(request.body).get("user", "")
    result = _send_validate_code(user)
    return JsonResponse(result)


def _send_validate_code(user):
    sys_set = SysSetting.objects.filter(key="auth_type").first()
    validate_way = sys_set.real_value[0]
    validate_code, md5_code = generate_validate_code()
    if validate_way == "mail":
        result = send_validate_mail(user, validate_code)
    else:
        result = send_validate_msg(user, validate_code)
    if not result["result"]:
        return result
    return {"result": True, "data": {"validate_code": md5_code}}


def send_validate_msg(user, validate_code):
    kwargs = {
        "receiver__username": user,
        "content": f"WeOps登录账号验证码：{validate_code}",
    }
    client = get_client_by_user("admin")
    result = client.cmsi.send_sms(kwargs)
    return result


def send_validate_mail(user, validate_code):
    kwargs = {
        "receiver__username": user,
        "title": "WeOps登录验证",
        "content": f"""<div style="line-height: 32px;">
尊敬的WeOps用户，您好！<br>
&emsp;&emsp;您正在进行账号验证操作的验证码为：{validate_code}<br>
&emsp;&emsp;此验证码只能使用一次，验证成功自动失效<br>
&emsp;&emsp;(请在30分钟内完成验证，30分钟后验证码失效，您需要重新验证。)<br>
</div>""",
    }
    client = get_client_by_user("admin")
    result = client.cmsi.send_mail(kwargs)
    return result


def generate_validate_code():
    code = ""
    for _ in range(6):
        code += f"{random.randint(0, 9)}"
    md5_client = hashlib.md5()
    md5_client.update(code.encode("utf8"))
    return code, md5_client.hexdigest()


@require_GET
def login_info(request):
    pattern = re.compile(r"weops_saas[-_]+[vV]?([\d.]*)")
    version = [i.strip() for i in pattern.findall(os.getenv("FILE_NAME", "weops_saas-3.5.3.tar.gz")) if i.strip()]

    user_super, _, user_menus, chname, operate_ids = get_user_roles(request.user)
    notify_day = 30
    expired_day = 365

    app_list = apps.get_app_configs()
    applications = []
    for app in app_list:
        if app.name.startswith("apps."):
            app.name = app.name.replace("apps.", '')
            applications.append(app.name)
        elif app.name.startswith("apps_other."):
            app.name = app.name.replace("apps_other.", '')
            applications.append(app.name)

    # 去重user_menus
    user_menus = list(set(user_menus))
    # 去重operate_ids
    operate_ids = duplicate_removal_operate_ids(operate_ids)

    # 启用的菜单
    menu_instance = MenuManage.objects.filter(use=True).first()
    weops_menu = menu_instance.menu if menu_instance else []

    return JsonResponse(
        {
            "result": True,
            "data": {
                "weops_menu": weops_menu,
                "username": request.user.username,
                "applications": applications or list(MENUS_MAPPING.keys()),  # weops有的权限
                "is_super": user_super,
                "menus": user_menus,
                "chname": chname,
                "operate_ids": operate_ids,
                "role": request.user.role,
                "last_login_addr": request.user.get_property("last_login_addr") or "",
                "last_login": request.user.last_login.strftime("%Y-%m-%d %H:%M"),
                "bk_token": request.COOKIES.get("bk_token", ""),
                "version": version[0].strip(".") if version else "3.5.3",
                "expired_day": expired_day,
                "notify_day": notify_day,
            },
        }
    )


def get_init_data():
    init_data = {
        "email": os.getenv("BKAPP_ESB_EMAIL", "326"),
        "sms": os.getenv("BKAPP_ESB_SMS", "408"),
        "voice": os.getenv("BKAPP_ESB_VOICE", "325"),
        "weixin": os.getenv("BKAPP_ESB_WEIXIN", "328"),
        "remote_url": os.getenv("BKAPP_REMOTE_URL", "http://paas.weops.com/o/views/connect"),
        "is_activate": 1,
        "log_output_host": os.getenv("BKAPP_LOG_OUTPUT_HOST", "127.0.0.1:8000"),  # log输出地址
    }
    return init_data


def duplicate_removal_operate_ids(operate_ids):
    operate_dict = {}
    for operate in operate_ids:
        menu_id, operates = operate["menuId"], operate["operate_ids"]
        if menu_id not in operate_dict:
            operate_dict[menu_id] = []
        operate_dict[menu_id].extend(operates)

    return [{"menuId": menu_id, "operate_ids": list(set(operates))} for menu_id, operates in operate_dict.items()]
