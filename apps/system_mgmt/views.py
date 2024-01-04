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
import os
import random
import re
import string
import time

from django.conf import settings
from django.db import transaction
from django.db.models import Q, QuerySet
from django.db.transaction import atomic
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import redirect
from rest_framework.request import Request
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

# 开发框架中通过中间件默认是需要登录态的，如有不需要登录的，可添加装饰器login_exempt
# 装饰器引入 from blueapps.account.decorators import login_exempt
from rest_framework.decorators import action
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from apps.system_mgmt import constants as system_constants
from common.keycloak_auth import KeycloakTokenAuthentication
from common.keycloak_auth import KeycloakIsAuthenticated
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
    LogSerializer,
    MenuManageModelSerializer,
    OperationLogSer,
    SysUserSerializer,
)
from apps.system_mgmt.user_manages import UserManageApi
from apps.system_mgmt.utils_package.controller import UserController, KeycloakUserController, \
    KeycloakRoleController, KeycloakPermissionController
from blueapps.account.decorators import login_exempt

from apps.system_mgmt.constants import USER_CACHE_KEY
from packages.drf.viewsets import ModelViewSet

from utils.decorators import ApiLog, delete_cache_key_decorator
from apps.system_mgmt.utils_package.CheckKeycloakPermission import check_keycloak_permission


@login_exempt
@require_POST
def test_post(request):
    return JsonResponse({"result": True, "data": {}})


@login_exempt
@require_GET
def test_get(request):
    return JsonResponse({"result": True, "data": {}})


class LogoViewSet(RetrieveModelMixin, UpdateModelMixin, GenericViewSet):
    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]
    queryset = SysSetting.objects.all()
    serializer_class = LogSerializer

    def get_object(self):
        obj, created = self.get_queryset().get_or_create(
            key=system_constants.SYSTEM_LOGO_INFO["key"],
            defaults=system_constants.SYSTEM_LOGO_INFO,
        )
        return obj

    @check_keycloak_permission('SysSetting_logo_change')
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
            operator=request.user.get('username', None),
            operate_type=OperationLog.MODIFY,
            operate_obj="Logo设置",
            operate_summary="修改Logo为:[{}]".format(file_obj.name if file_obj else ""),
            current_ip=current_ip,
            app_module="系统管理",
            obj_type="系统设置",
        )
        return Response(serializer.data)

    @check_keycloak_permission('SysSetting_logo_change')
    def reset(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.value = system_constants.SYSTEM_LOGO_INFO["value"]
        instance.save()
        serializer = self.get_serializer(instance)
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        OperationLog.objects.create(
            operator=request.user.get('username', None),
            operate_type=OperationLog.MODIFY,
            operate_obj="Logo设置",
            operate_summary="logo恢复默认",
            current_ip=current_ip,
            app_module="系统管理",
            obj_type="系统设置",
        )
        return Response(serializer.data)


class OperationLogViewSet(ListModelMixin, GenericViewSet):
    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]
    queryset = OperationLog.objects.all()
    serializer_class = OperationLogSer
    ordering_fields = ["created_at"]
    ordering = ["-created_at"]
    filter_class = OperationLogFilter


from rest_framework import viewsets
from rest_framework import views, status


class KeycloakLoginView(views.APIView):
    '''
    该类用作验证登录
    '''
    # 让RDF不认证
    authentication_classes = []
    permission_classes = []

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
        try:
            token = KeycloakUserController.get_token(username, password)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        if token is None:
            # 用户验证失败，返回错误响应
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            res = Response({'token': token}, status=status.HTTP_200_OK)
            res.set_cookie('token', token)
            return res


class KeycloakCodeLoginView(views.APIView):
    '''
    该类用作验证登录
    '''
    authentication_classes = []
    permission_classes = []

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('code', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING)
        ],
        operation_description='用作登录后的重定向，根据请求的code获取token，获取完回到主页'
    )
    def get(self, request: Request):
        # 从请求中获取code
        code = request.query_params.get('code', None)
        if code is None:
            return Response({'error': 'no code found'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = KeycloakUserController.get_token_from_code(code, request.build_absolute_uri().split('?')[0])
            print(f'token get from code: {token}')
            # response = Response(status=302)
            # response['Location'] = request.build_absolute_uri('/')
            # response.set_cookie('token', token)
            response = HttpResponseRedirect(request.build_absolute_uri('/'))
            response.set_cookie('token', token)
            return response
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)


class KeycloakUserViewSet(viewsets.ViewSet):
    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('per_page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('search', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING),
            openapi.Parameter('roles', in_=openapi.IN_QUERY, type=openapi.TYPE_ARRAY, items=openapi.TYPE_STRING),
        ]
    )
    @check_keycloak_permission('SysUser_view')
    def list(self, request: Request):
        page = request.query_params.get("page", 1)  # 获取请求中的页码参数，默认为第一页
        per_page = request.query_params.get("per_page", 10)  # 获取请求中的每页结果数，默认为10
        roles = []
        try:
            roles_p = request.query_params.get('roles', None)
            if roles_p:
                roles = eval(roles_p)
        except Exception as e:
            return Response({'error': 'roles format error'}, status=status.HTTP_400_BAD_REQUEST)
        res = KeycloakUserController.get_user_list(**{"page": int(page),
                                                      "per_page": int(per_page),
                                                      "search": request.query_params.get('search', None),
                                                      'role_ids': roles})
        return Response(res)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('per_page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER)
        ],
        operation_description='获取该角色下的所有用户'
    )
    @action(detail=False, methods=['get'], url_path='roles/(?P<role_id>[^/.]+)')
    @check_keycloak_permission('SysRole_users_manage')
    def get_users_in_role(self, request: Request, role_id: str):
        page = request.query_params.get("page", 1)  # 获取请求中的页码参数，默认为第一页
        per_page = request.query_params.get("per_page", 10)  # 获取请求中的每页结果数，默认为10
        res = KeycloakUserController.get_user_in_role(role_id, page, per_page)
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
    @check_keycloak_permission('SysUser_create')
    def create(self, request):
        user = dict()
        username = request.data.get('username', None)
        password = request.data.get('password', None)
        if username is None or password is None:
            return Response({"error": "password or username are not present"}, status=status.HTTP_400_BAD_REQUEST)
        user['username'] = username
        user['email'] = request.data.get('email', None)
        user['lastName'] = request.data.get('lastName', None)
        user['enabled'] = True
        user['credentials'] = [{"value": password, "type": 'password', }]
        try:
            id = KeycloakUserController.create_user(**{"user": user})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'id': id}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_PATH, description="User ID", type=openapi.TYPE_STRING)
        ]
    )
    @check_keycloak_permission('SysUser_delete')
    def destroy(self, request: Request, pk: str):
        """
        删除用户
        """
        user_id = id
        try:
            KeycloakUserController.delete_user(**{"user_id": pk})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'id': pk}, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_PATH, description="User ID", type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'firstName': openapi.Schema(type=openapi.TYPE_STRING, description='User first name'),
                'lastName': openapi.Schema(type=openapi.TYPE_STRING, description='User last name'),
            }
        )
    )
    @check_keycloak_permission('SysUser_edit', check_user_itself=False)
    def update(self, request: Request, pk: str):
        """
        修改用户信息
        """
        payload = dict()
        for k in request.data.keys():
            payload[k] = request.data[k]
        try:
            KeycloakUserController.update_user(**{"user_id": pk, "payload": payload})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'id': pk}, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_PATH, description="User ID", type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
            }
        ),
    )
    @check_keycloak_permission('SysUser_edit', check_user_itself=False)
    def partial_update(self, request: Request, pk: str):
        """
        重置用户密码
        """
        password = request.data.get('password', None)
        if password is None:
            return Response({"error": "password is not present"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            KeycloakUserController.reset_password(**{"user_id": pk, "password": password})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'id': pk}, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        ),
        operation_description='将一系列组添加到用户'
    )
    @action(detail=True, methods=['patch'], url_path='assign_groups')
    def assign_user_groups(self, request: Request, pk: str):
        try:
            ids = request.data
            if ids is None or not isinstance(ids, list) or len(ids) == 0:
                return Response({"error": "check your request data"}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakGroupController.assign_user_group(pk, ids)
            return Response({'id': pk}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        ),
        operation_description='将一系列组从该用户移除'
    )
    @action(detail=True, methods=['delete'], url_path='unassign_groups')
    def unassign_user_groups(self, request: Request, pk: str):
        try:
            ids = request.data
            if ids is None or not isinstance(ids, list) or len(ids) == 0:
                return Response({"error": "check your request data"}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakGroupController.unassigned_user_group(pk, ids)
            return Response({'id': pk}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class KeycloakRoleViewSet(viewsets.ViewSet):
    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]

    @swagger_auto_schema()
    @check_keycloak_permission('SysRole_view')
    def list(self, request: Request):
        '''
        获取所有角色
        '''
        res = KeycloakRoleController.get_client_roles()
        return Response(res)

    @swagger_auto_schema()
    @check_keycloak_permission('SysRole_view')
    def retrieve(self, request: Request, pk: str):
        '''
        获取指定角色，以及其拥有的权限
        '''
        try:
            res = KeycloakRoleController.get_client_roles_permissions_by_id(pk)
        except Exception as e:
            return Response({'error', str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(res)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'role_name': openapi.Schema(type=openapi.TYPE_STRING, description='Role name'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='description'),
            },
            required=['role_name']
        ),
    )
    @check_keycloak_permission('SysRole_create')
    def create(self, request):
        '''
        创建角色
        '''
        role_name = request.data.get('role_name', None)
        des = request.data.get('description', None)
        if not role_name or not des:
            return Response({"error": "rolename or description is not present"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            role = KeycloakRoleController.create_client_role_and_policy(role_name, des)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(role, status=status.HTTP_201_CREATED)

    @swagger_auto_schema()
    @check_keycloak_permission('SysRole_delete')
    def destroy(self, request: Request, pk: str):
        """
        删除角色
        """
        try:
            KeycloakRoleController.delete_role(pk)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'role_id': pk}, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        ),
        operation_description='更改角色的权限状态，如果有切换为有，反之'
    )
    @action(detail=True, methods=['patch'], url_path='permissions')
    @check_keycloak_permission('SysRole_permissions')
    def ch_permission(self, request: Request, pk: str):
        try:
            permission_ids = request.data
            return Response(KeycloakRoleController.ch_permission_role(pk, permission_ids))
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('user_id', openapi.IN_PATH, description="user ID", type=openapi.TYPE_STRING),
        ],
        operation_description='将一个用户添加到角色'
    )
    @action(detail=True, methods=['put'], url_path='assign/(?P<user_id>[^/.]+)')
    @check_keycloak_permission('SysRole_users_manage')
    def assign_role(self, request: Request, pk: str, user_id: str):
        try:
            return Response(KeycloakRoleController.assign_role_users(pk, user_id))
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('user_id', openapi.IN_PATH, description="user ID", type=openapi.TYPE_STRING),
        ],
        operation_description='将一个用户从角色移除'
    )
    @action(detail=True, methods=['delete'], url_path='withdraw/(?P<user_id>[^/.]+)')
    @check_keycloak_permission('SysRole_users_manage')
    def withdraw_role(self, request: Request, pk: str, user_id: str):
        try:
            return Response(KeycloakRoleController.remove_role_users(pk, user_id))
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_PATH, description="User ID", type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Role description')
            }
        )
    )
    @check_keycloak_permission('SysRole_edit')
    def update(self, request: Request, pk: str):
        des = request.data.get('description', None)
        if not des:
            return Response({'error': 'description needed'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            KeycloakRoleController.edit_role(pk, des)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({'id': pk}, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        ),
        operation_description='将该角色添加到一系列组中'
    )
    @action(detail=True, methods=['patch'], url_path='assign_groups')
    def assign_groups(self, request: Request, pk: str):
        try:
            ids = request.data
            if ids is None or not isinstance(ids, list) or len(ids) == 0:
                return Response({"error": "check your request data"}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakRoleController.assign_role_groups(pk, ids)
            return Response({'id': pk}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        ),
        operation_description='将该角色从一系列组中移除'
    )
    @action(detail=True, methods=['delete'], url_path='unassign_groups')
    def unassign_groups(self, request: Request, pk: str):
        try:
            ids = request.data
            if ids is None or not isinstance(ids, list) or len(ids) == 0:
                return Response({"error": "check your request data"}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakRoleController.unassign_role_groups(pk, ids)
            return Response({'id': pk}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class KeycloakPermissionViewSet(viewsets.ViewSet):
    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]

    @swagger_auto_schema()
    def list(self, request: Request):
        """
        基于该token获取所有权限，以及该用户是否拥有该权限
        """
        try:
            return Response(KeycloakPermissionController.get_permissions(request.auth))
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class KeycloakGroupViewSet(viewsets.ViewSet):
    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('per_page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('search', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING),
        ]
    )
    @check_keycloak_permission('SysGroup_view')
    def list(self, request: Request):
        """
        查询组
        """
        try:
            groups = KeycloakGroupController.get_groups(int(request.query_params.get('page', 1))
                                                        , int(request.query_params.get('per_page', 20))
                                                        , request.query_params.get('search', ''))
            return Response(groups, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema()
    @check_keycloak_permission('SysGroup_view')
    def retrieve(self, request: Request, pk: str):
        '''
        获取一个组以及其子组
        '''
        try:
            group = KeycloakGroupController.get_group(pk)
            return Response(group, status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        pass

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'group_name': openapi.Schema(type=openapi.TYPE_STRING, description='Role name'),
                'parent_group_id': openapi.Schema(type=openapi.TYPE_STRING, description='description'),
            },
            required=['group_name']
        )
    )
    @check_keycloak_permission('SysGroup_create')
    def create(self, request: Request):
        """
        创建一个组，如有父组织请添加字段parent_group_id
        """
        try:
            group_name = request.data.get("group_name", None)
            if not group_name:
                return Response({'error': 'group_name are needed'}, status=status.HTTP_400_BAD_REQUEST)
            g_id = KeycloakGroupController.create_group(group_name, request.data.get('parent_group_id', None))
            return Response({'id': g_id}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        pass

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'group_name': openapi.Schema(type=openapi.TYPE_STRING, description='group name')
            },
            required=['group_name']
        )
    )
    @check_keycloak_permission('SysGroup_edit')
    def update(self, request: Request, pk: str):
        """
        修改组名
        """
        try:
            group_name = request.data.get("group_name", None)
            if not group_name:
                return Response({'error': 'group_name are needed'}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakGroupController.update_group(pk, group_name)
            return Response({'id': pk}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        )
    )
    @action(detail=False, methods=['delete'])
    @check_keycloak_permission('SysGroup_delete')
    def delete_groups(self, request: Request):
        """
        删除组
        """
        try:
            ids = request.data
            if ids is None or not isinstance(ids, list) or len(ids) == 0:
                return Response({"error": "check your request data"}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakGroupController.delete_group(ids)
            return Response({'id': ""}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('per_page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER)
        ],
        operation_description='获取该组下的所有用户'
    )
    @action(detail=True, methods=['get'], url_path='users')
    @check_keycloak_permission('SysGroup_user')
    def get_users_in_group(self, request: Request, pk: str):
        try:
            users = KeycloakGroupController.get_group_users(pk,
                                                            int(request.query_params.get('page', 1)),
                                                            int(request.query_params.get('per_page', 20)))
            return Response(users, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        ),
        operation_description='将一系列用户添加到组'
    )
    @action(detail=True, methods=['patch'], url_path='assign_users')
    @check_keycloak_permission('SysGroup_user')
    def assign_group_users(self, request: Request, pk: str):
        try:
            ids = request.data
            if ids is None or not isinstance(ids, list) or len(ids) == 0:
                return Response({"error": "check your request data"}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakGroupController.assign_group_user(pk, ids)
            return Response({'id': pk}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        ),
        operation_description='将一系列用户从组移除'
    )
    @action(detail=True, methods=['delete'], url_path='unassign_users')
    @check_keycloak_permission('SysGroup_user')
    def unassigned_group_users(self, request: Request, pk: str):
        try:
            ids = request.data
            if ids is None or not isinstance(ids, list) or len(ids) == 0:
                return Response({"error": "check your request data"}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakGroupController.unassigned_group_user(pk, ids)
            return Response({'id': pk}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(operation_description='获取该组下的所有角色')
    @action(detail=True, methods=['get'], url_path='roles')
    @check_keycloak_permission('SysGroup_role')
    def get_roles_in_group(self, request: Request, pk: str):
        try:
            roles = KeycloakGroupController.get_group_roles(pk)
            return Response(roles, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        ),
        operation_description='将一系列角色添加到组'
    )
    @action(detail=True, methods=['patch'], url_path='assign_roles')
    @check_keycloak_permission('SysGroup_role')
    def assign_group_roles(self, request: Request, pk: str):
        try:
            ids = request.data
            if ids is None or not isinstance(ids, list) or len(ids) == 0:
                return Response({"error": "check your request data"}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakGroupController.assign_group_role(pk, ids)
            return Response({'id': pk}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING)
        ),
        operation_description='将一系列角色从组移除'
    )
    @action(detail=True, methods=['delete'], url_path='unassign_roles')
    @check_keycloak_permission('SysGroup_role')
    def unassigned_group_roles(self, request: Request, pk: str):
        try:
            ids = request.data
            if ids is None or not isinstance(ids, list) or len(ids) == 0:
                return Response({"error": "check your request data"}, status=status.HTTP_400_BAD_REQUEST)
            KeycloakGroupController.unassigned_group_role(pk, ids)
            return Response({'id': pk}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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

    @swagger_auto_schema(
        operation_description='获取所有用户（无参）'
    )
    @action(methods=["GET"], detail=False, url_path="get_users")
    @ApiLog("用户管理获取用户")
    def bk_user_manage_list(self, request, *args, **kwargs):
        """
        获取用户
        """
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('page', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('search', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING),
        ]
    )
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

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='User bk_rname'),
                'display_name': openapi.Schema(type=openapi.TYPE_STRING, description='User displayname'),
                'telephone': openapi.Schema(type=openapi.TYPE_STRING, description='User telephone'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
            },
            required=['username', 'display_name', 'password']
        ),
    )

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

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'id': openapi.Schema(type=openapi.TYPE_STRING, description='User id'),
                'bk_user_id': openapi.Schema(type=openapi.TYPE_STRING, description='随便填'),
                'display_name': openapi.Schema(type=openapi.TYPE_STRING, description='User username'),
                'telephone': openapi.Schema(type=openapi.TYPE_STRING, description='User telephone'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email')
            },
            required=['id', 'display_name']
        ),
    )
    @action(methods=["PUT"], detail=False, url_path="edit_user")
    @ApiLog("用户管理修改用户")
    def modify_bk_user_manage(self, request, *args, **kwargs):
        """
        修改用户,username不可更改
        """
        if request.data.get('username', None) is not None:
            return Response({'error': 'username cannot be changed'}, status=status.HTTP_400_BAD_REQUEST)
        res = UserController.update_user_controller(**{"request": request, "self": self, "manage_api": self.manage_api})
        return Response(**res)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'id': openapi.Schema(type=openapi.TYPE_STRING, description='User id'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
            },
            required=['id', 'password']
        ),
    )
    @action(methods=["PUT"], detail=False, url_path="reset_password")
    @ApiLog("用户管理重置密码")
    def reset_bk_user_password(self, request, *args, **kwargs):
        """
        重置密码
        """
        id = request.data.get('id', None)
        password = request.data.get('password', None)
        if id is None or password is None:
            return Response({'error': 'is or password are not present'}, status=status.HTTP_400_BAD_REQUEST)
        sys_user = SysUser.objects.get(pk=int(id))
        kc_user = KeycloakUserController.get_user_by_name(sys_user.bk_username, request.auth)
        if kc_user is None:
            return Response({'error': 'user not found'}, status=status.HTTP_404_NOT_FOUND)
        KeycloakUserController.reset_password(kc_user['id'], password, request.auth)
        # res = UserController.reset_user_password_controller(
        #     **{"request": request, "self": self, "manage_api": self.manage_api}
        # )
        return Response({'message': 'success'})

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('id', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('bk_user_id', in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description='随便填'),
        ],
    )
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

    @action(methods=["PUT"], detail=True)
    @ApiLog("设置用户角色状态")
    def update_user_status(self, request, pk):
        res = UserController.set_user_status(
            **{"request": request, "self": self, "manage_api": self.manage_api, "id": pk}
        )
        return Response(**res)


class MenuManageModelViewSet(ModelViewSet):
    """
    自定义菜单管理
    """

    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]
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
            operator=request.user.get('username', None),
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
            operator=request.user.get('username', None),
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
            operator=request.user.get('username', None),
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
            operator=request.user.get('username', None),
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


def generate_validate_code():
    code = ""
    for _ in range(6):
        code += f"{random.randint(0, 9)}"
    md5_client = hashlib.md5()
    md5_client.update(code.encode("utf8"))
    return code, md5_client.hexdigest()


class LoginInfoView(views.APIView):
    authentication_classes = [KeycloakTokenAuthentication]
    permission_classes = [KeycloakIsAuthenticated]

    def get(self, request: Request) -> Response:
        is_super = False
        try:
            is_super = 'admin' in request.user['resource_access'][settings.KEYCLOAK_SETTINGS['CLIENT_ID']]['roles']
        except Exception as e:
            pass
        permissions: dict = KeycloakPermissionController.get_permissions(request.auth)
        # 根据拥有view权限的获取其菜单
        menus = list()
        # 根据权限划分菜单和操作，按格式返回
        operate_ids = list()
        for k, v in permissions.items():
            operate_idss = list()
            for p in v:
                strs = p['name'].split('_')
                if p['allow']:
                    operate_idss.append(p['name'])
                if strs[-1] == 'view' and p['allow']:
                    menus.append(k)
                    operate_ids.append({
                        'operate_ids': operate_idss,
                        'menuId': k
                    })
        # for menu in menus:
        #     for p in permissions['menu']:
        #         operate_idss = list
        #         if p['allow']:
        #             pass
        return Response({
            'username': request.user['username'],
            'id': request.user['id'],
            'chname': request.user.get('lastName', ""),
            'email': request.user.get('email', ""),
            'token': request.auth,
            'is_super': is_super,
            'menus': menus,
            'operate_ids': operate_ids,
            'weops_menu': [],
            'applications': [
                "resource",
                "big_screen",
                "health_advisor",
                "operational_tools",
                "repository",
                "senior_resource",
                "itsm",
                "patch_mgmt",
                "auto_process",
                "chat_ops",
                "syslog",
                "dashboard",
                "custom_topology",
                "monitor_mgmt",
                "dashboard_senior",
                "timed_job",
                "apm"
            ]
        })


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
