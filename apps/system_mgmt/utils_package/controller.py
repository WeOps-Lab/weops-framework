# -*- coding: utf-8 -*-

# @File    : controller.py
# @Date    : 2022-03-25
# @Author  : windyzhao

import copy
import json
import logging
import uuid

import requests
from casbin_adapter.models import CasbinRule
from django.conf import settings, LazySettings
from django.db import transaction
from keycloak import KeycloakAdmin, KeycloakOpenIDConnection, KeycloakOpenID

# from apps.monitor_mgmt.models import CloudPlatGroup
from apps.system_mgmt.celery_tasks import (
    sync_casbin_mesh_add_policies,
    sync_casbin_mesh_remove_add_policies,
    sync_casbin_mesh_remove_filter_policies,
    sync_casbin_mesh_remove_policies,
    sync_role_permissions,
)
from apps.system_mgmt.constants import (
    DB_APPS,
    DB_APPS_DISPLAY_NAME,
    DB_MENU_IDS,
    DB_MENU_IDS_DISPLAY_NAME,
    DB_OPERATE_IDS,
    DB_OPERATE_IDS_DISPLAY_NAME,
    DB_SUPER_USER,
    MENUS_MAPPING,
    MENUS_REMOVE_CLASSIFICATIONS,
)
from apps.system_mgmt.models import OperationLog, SysRole, SysUser
from apps.system_mgmt.utils_package.casbin_utils import CasbinUtils
from apps.system_mgmt.utils_package.dao import RoleModels, UserModels
from apps.system_mgmt.utils_package.db_utils import RolePermissionUtil, RoleUtils, UserUtils
from apps.system_mgmt.common_utils.menu_service import Menus
from apps.system_mgmt.common_utils.token import get_bk_token
from apps.system_mgmt.utils_package.keycloak_utils import KeycloakUtils
from utils.app_log import logger
from utils.app_utils import AppUtils


class UserController(object):
    @classmethod
    def open_create_user(cls, data, manage_api, serializer):
        with transaction.atomic():
            sid = transaction.savepoint()
            try:
                cookies = {"bk_token": get_bk_token()}
                normal_role = UserModels.get_normal_user()
                user_data = UserUtils.formative_user_data(**{"data": data, "normal_role": normal_role})
                serializer = serializer(data=user_data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                instance = serializer.instance
                # 给新增对用户加入普通角色组
                UserModels.add_many_to_many_field(
                    **{"instance": instance, "add_data": normal_role, "add_attr": "roles"}
                )
                OperationLog.objects.create(
                    operator="admin",
                    operate_type=OperationLog.ADD,
                    operate_obj=data.get("username", ""),
                    operate_summary="对外开放接口调用，用户管理新增用户:[{}]".format(data.get("username", "")),
                    current_ip="127.0.0.1",
                    app_module="系统管理",
                    obj_type="用户管理",
                )
                res = UserUtils.username_manage_add_user(**{"cookies": cookies, "data": data, "manage_api": manage_api})
            except Exception as user_error:
                logger.exception("对外开放接口：新增用户调用用户管理接口失败. message={}".format(user_error))
                res = {"result": False, "data": {}}

            if not res["result"]:
                # 请求错误，或者创建失败 都回滚
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                return {"result": False, "data": {}, "message": "创建用户失败! 请联系管理员！"}

            UserModels.user_update_bk_user_id(**{"instance": instance, "bk_user_id": res["data"]["id"]})
            transaction.savepoint_commit(sid)

        # casbin_mesh 新增用户
        transaction.on_commit(
            lambda: sync_casbin_mesh_add_policies(
                sec="g",
                ptype="g",
                rules=[[instance.bk_username, normal_role.role_name]],
            )
        )

        try:
            AppUtils.static_class_call(
                "apps.monitor_mgmt.uac.utils",
                "UACHelper",
                "sync_user",
                {"cookies": cookies},
            )
        except Exception as uac_error:
            logger.exception("用户管理新增用户调用统一告警同步用户失败.error={}".format(uac_error))

        return {"result": True, "data": {"user_id": instance.id}, "message": "创建用户成功"}

    @classmethod
    def open_set_user_roles(cls, data):
        """
        用户设置角色
        data = {
            "user_id":1,
            "roles":[1]
            }
        """

        user_id = data["user_id"]
        roles_ids = data["roles"]
        instance = SysUser.objects.filter(id=user_id).first()
        if instance is None:
            return {"result": False, "data": {}, "message": "此用户不存在！"}
        if instance.bk_username == "admin":
            return {"result": False, "data": {}, "message": "无法修改admin用户的角色！"}

        old_user_role = set(instance.roles.all().values_list("role_name", flat=True))
        admin_group = SysRole.objects.get(role_name=DB_SUPER_USER)
        user_obj_in_admin_group = instance.roles.filter(role_name=DB_SUPER_USER).first()  # 用户是否在超管组内
        operator = 0  # 0 无修改 1 新增 2 删除
        if admin_group.id in roles_ids:
            if not user_obj_in_admin_group:
                operator = 1
        else:
            if user_obj_in_admin_group:
                operator = 2

        with transaction.atomic():
            sid = transaction.savepoint()
            try:
                cookies = {"bk_token": get_bk_token()}
                roles = UserModels.user_set_roles(**{"user_obj": instance, "roles_ids": roles_ids})
                roles_names = set(roles.values_list("role_name", flat=True))

                OperationLog.objects.create(
                    operator="admin",
                    operate_type=OperationLog.MODIFY,
                    operate_obj=instance.bk_username,
                    operate_summary="对外开放接口调用，修改用户角色，角色名称：[{}]".format(
                        ",".join(i for i in roles_names)),
                    current_ip="127.0.0.1",
                    app_module="系统管理",
                    obj_type="角色管理",
                )
                if operator:
                    # 把此用户加入到权限中心到超级管理员里
                    role_permission = RolePermissionUtil(username=instance.bk_username)
                    if operator == 1:
                        res = role_permission.add_main()
                    else:
                        res = role_permission.delete_main()
                    if not res:
                        raise Exception("权限中心设置超管角色失败！")

                # 把此用户和角色加入policy
                add_role, delete_role = RoleUtils.get_add_role_remove_role(roles=roles_names, old_roles=old_user_role)
                CasbinUtils.set_user_role_policy(instance.bk_username, add_role, delete_role)
                transaction.savepoint_commit(sid)

            except Exception as err:
                logger.exception("设置用户角色失败！，error={}".format(err))
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                return {"result": False, "data": {}, "message": "设置用户角色失败！请联系管理员"}

        # 删除角色 policy
        transaction.on_commit(
            lambda: sync_casbin_mesh_remove_policies(
                sec="g",
                ptype="g",
                rules=[[instance.bk_username, role_name] for role_name in delete_role],
            )
        )
        # 新增g的policy
        transaction.on_commit(
            lambda: sync_casbin_mesh_add_policies(
                sec="g",
                ptype="g",
                rules=[[instance.bk_username, role_name] for role_name in add_role],
            )
        )

        return {"result": True, "data": {}, "message": "设置用户角色成功！"}

    @classmethod
    def add_user_controller(cls, *args, **kwargs):
        """
        新增用户
        """
        self = kwargs["self"]
        request = kwargs["request"]
        manage_api = kwargs["manage_api"]
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        with transaction.atomic():
            sid = transaction.savepoint()
            try:
                normal_role = UserModels.get_normal_user()
                user_data = UserUtils.formative_user_data(**{"data": request.data, "normal_role": normal_role})

                kc_user = dict()
                username = request.data.get('username', None)
                password = request.data.get('password', None)
                kc_user['username'] = username
                kc_user['email'] = request.data.get('email', None)
                kc_user['lastName'] = request.data.get('display_name', None)
                kc_user['enabled'] = True
                kc_user['credentials'] = [{"value": password, "type": 'password'}]
                result = KeycloakUserController.create_user(kc_user, request.auth).get('error', None)
                if result is not None:
                    raise Exception(result)

                serializer = UserModels.create(**{"model_manage": self, "data": user_data})
                # 给新增对用户加入普通角色组
                UserModels.add_many_to_many_field(
                    **{"instance": serializer.instance, "add_data": normal_role, "add_attr": "roles"}
                )
                OperationLog.objects.create(
                    operator=request.user.username,
                    operate_type=OperationLog.ADD,
                    operate_obj=request.data.get("username", ""),
                    operate_summary="用户管理新增用户:[{}]".format(request.data.get("username", "")),
                    current_ip=current_ip,
                    app_module="系统管理",
                    obj_type="用户管理",
                )
                # 蓝鲸接口
                # res = UserUtils.username_manage_add_user(
                #     **{"cookies": request.COOKIES, "data": request.data, "manage_api": manage_api}
                # )
                res = {"result": True}
            except Exception as user_error:
                logger.exception("新增用户调用用户管理接口失败. message={}".format(user_error))
                res = {"result": False, 'error': str(user_error)}

            if not res["result"]:
                # 请求错误，或者创建失败 都回滚
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)

                return {"data": {"detail": f"创建用户失败! {res['error']}"}, "status": 500}

            # UserModels.user_update_bk_user_id(**{"instance": serializer.instance, "bk_user_id": res["data"]["id"]})
            transaction.savepoint_commit(sid)

        # casbin_mesh 新增用户
        transaction.on_commit(
            lambda: sync_casbin_mesh_add_policies(
                sec="g",
                ptype="g",
                rules=[[serializer.instance.bk_username, normal_role.role_name]],
            )
        )

        try:
            AppUtils.static_class_call(
                "apps.monitor_mgmt.uac.utils",
                "UACHelper",
                "sync_user",
                {"cookies": request.COOKIES},
            )
        except Exception as uac_error:
            logger.exception("用户管理新增用户调用统一告警同步用户失败.error={}".format(uac_error))

        return {"data": "创建用户成功"}

    @classmethod
    def update_user_controller(cls, *args, **kwargs):
        """
        修改用户
        """
        self = kwargs["self"]
        request = kwargs["request"]
        manage_api = kwargs["manage_api"]
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        with transaction.atomic():
            sid = transaction.savepoint()
            try:
                update_data, bk_user_id, user_id = UserUtils.formative_update_user_data(**{"data": request.data})
                user_obj = UserModels.get_user_objects(**{"user_id": user_id})
                serializer = UserModels.update(**{"model_manage": self, "data": update_data, "instance": user_obj})
                OperationLog.objects.create(
                    operator=request.user.username,
                    operate_type=OperationLog.MODIFY,
                    operate_obj=serializer.instance.bk_username,
                    operate_summary="用户管理修改用户:[{}]".format(serializer.instance.bk_username),
                    current_ip=current_ip,
                    app_module="系统管理",
                    obj_type="用户管理",
                )
                # res = UserUtils.username_manage_update_user(
                #     **{
                #         "cookies": request.COOKIES,
                #         "data": request.data,
                #         "manage_api": manage_api,
                #         "bk_user_id": bk_user_id,
                #     }
                # )
                res = {'result': True}

            except Exception as user_error:
                logger.exception("修改用户调用用户管理接口失败. message={}".format(user_error))
                res = {"result": False}

            if not res["result"]:
                # 请求错误，或者修改失败 都回滚
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)

                return {"data": {"detail": "修改用户失败! "}, "status": 500}

            transaction.savepoint_commit(sid)

        return {"data": "修改用户成功"}

    @classmethod
    def reset_user_password_controller(cls, *args, **kwargs):
        """
        用户重置密码
        """
        self = kwargs["self"]
        request = kwargs["request"]
        manage_api = kwargs["manage_api"]
        current_ip = getattr(request, "current_ip", "127.0.0.1")

        data, bk_user_id = UserUtils.username_manage_get_bk_user_id(**{"data": request.data})

        admin_bool = UserModels.get_user_admin_bool(**{"id": bk_user_id, "self": self, "field": "bk_user_id"})

        if admin_bool:
            return {"data": {"detail": "内置用户admin不允修改密码! "}, "status": 500}

        res = UserUtils.username_manage_reset_password(
            **{"cookies": request.COOKIES, "data": data, "manage_api": manage_api, "bk_user_id": bk_user_id}
        )
        instance = self.queryset.filter(bk_user_id=bk_user_id).first()
        bk_username = instance.bk_username if instance is not None else ""
        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.MODIFY,
            operate_obj=bk_username,
            operate_summary="用户管理用户[{}]重置密码".format(bk_username),
            current_ip=current_ip,
            app_module="系统管理",
            obj_type="用户管理",
        )

        if not res["result"]:
            return {"data": {"detail": f"重置用户密码失败，{res.get('message')}"}, "status": 500}

        return {"data": "重置用户密码成功"}

    @classmethod
    def delete_user_controller(cls, *args, **kwargs):
        """
        删除用户
        """
        self = kwargs["self"]
        request = kwargs["request"]
        manage_api = kwargs["manage_api"]
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        user_id, bk_user_id = UserUtils.username_manage_get_user_data(**{"request": request})
        admin_bool = UserModels.get_user_admin_bool(**{"id": user_id, "self": self, "field": "id"})

        if admin_bool:
            return {"data": {"detail": "内置用户admin不允许删除! "}, "status": 500}

        with transaction.atomic():
            sid = transaction.savepoint()
            try:
                user_obj = UserModels.get_user_objects(user_id=user_id)
                user_roles = user_obj.roles.all()
                rules = [[user_obj.bk_username, i.role_name] for i in user_roles]

                kc_user = KeycloakUserController.get_user_by_name(user_obj.bk_username, request.auth)
                KeycloakUserController.delete_user(kc_user['id'], request.auth)

                delete_user_belong_roles = {i.id for i in user_roles}
                UserModels.delete_user(**{"user": user_obj})
                OperationLog.objects.create(
                    operator=request.user.username,
                    operate_type=OperationLog.DELETE,
                    operate_obj=user_obj.bk_username,
                    operate_summary="用户管理删除用户:[{}]".format(user_obj.bk_username),
                    current_ip=current_ip,
                    app_module="系统管理",
                    obj_type="用户管理",
                )
                # res = UserUtils.username_manage_delete_user(
                #     **{"cookies": request.COOKIES, "data": [{"id": bk_user_id}], "manage_api": manage_api}
                # )
                res = {'result': True}
            except Exception as user_error:
                logger.exception("删除用户调用用户管理接口失败. message={}".format(user_error))
                res = {"result": False}

            if not res["result"]:
                # 请求错误，或者删除失败 都回滚
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                return {"data": {"detail": "删除用户失败! "}, "status": 500}

            transaction.savepoint_commit(sid)

        # casbin_mesh 删除用户
        transaction.on_commit(lambda: sync_casbin_mesh_remove_policies(sec="g", ptype="g", rules=rules))

        return {"data": "删除用户成功！"}

    @classmethod
    def set_user_roles_controller(cls, *args, **kwargs):
        """
        用户设置角色
        """
        self = kwargs["self"]
        request = kwargs["request"]
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        user_id, roles_ids = UserUtils.username_manage_get_user_role_data(**{"data": request.data})
        admin_bool = UserModels.get_user_admin_bool(**{"id": user_id, "self": self, "field": "id"})

        if admin_bool:
            return {"data": {"detail": "无法修改admin的角色! "}, "status": 500}

        user_obj = UserModels.get_user_objects(user_id=user_id)
        old_user_role = set(user_obj.roles.all().values_list("role_name", flat=True))
        admin_group = SysRole.objects.get(role_name=DB_SUPER_USER)
        user_obj_in_admin_group = user_obj.roles.filter(role_name=DB_SUPER_USER).first()  # 用户是否在超管组内
        operator = 0  # 0 无修改 1 新增 2 删除
        if admin_group.id in roles_ids:
            if not user_obj_in_admin_group:
                operator = 1
        else:
            if user_obj_in_admin_group:
                operator = 2

        with transaction.atomic():
            sid = transaction.savepoint()
            try:
                roles = UserModels.user_set_roles(**{"user_obj": user_obj, "roles_ids": roles_ids})
                roles_names = set(roles.values_list("role_name", flat=True))

                OperationLog.objects.create(
                    operator=request.user.username,
                    operate_type=OperationLog.MODIFY,
                    operate_obj=user_obj.bk_username,
                    operate_summary="修改用户角色，角色名称：[{}]".format(",".join(i for i in roles_names)),
                    current_ip=current_ip,
                    app_module="系统管理",
                    obj_type="角色管理",
                )
                if operator:
                    # 把此用户加入到权限中心到超级管理员里
                    role_permission = RolePermissionUtil(username=user_obj.bk_username)
                    if operator == 1:
                        res = role_permission.add_main()
                    else:
                        res = role_permission.delete_main()
                    if not res:
                        raise Exception("权限中心设置超管角色失败！")

                # 把此用户和角色加入policy
                add_role, delete_role = RoleUtils.get_add_role_remove_role(roles=roles_names, old_roles=old_user_role)
                CasbinUtils.set_role_user_policy(user_obj.bk_username, add_role, delete_role)
                transaction.savepoint_commit(sid)

            except Exception as err:
                logger.exception("设置用户角色失败！，error={}".format(err))
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                return {"data": {"detail": "设置用户角色失败! "}, "status": 500}

        # 删除角色policy
        transaction.on_commit(
            lambda: sync_casbin_mesh_remove_policies(
                sec="g",
                ptype="g",
                rules=[[user_obj.bk_username, i] for i in delete_role],
            )
        )

        # 新增角色policy
        transaction.on_commit(
            lambda: sync_casbin_mesh_add_policies(
                sec="g", ptype="g", rules=[[user_obj.bk_username, i] for i in add_role]
            )
        )

        return {"data": "设置用户角色成功！"}

    @classmethod
    def set_user_status(cls, **kwargs):
        """
        设置用户状态
        """
        self = kwargs["self"]
        request = kwargs["request"]
        manage_api = kwargs["manage_api"]
        user_id = kwargs["id"]
        data = self.request.data
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        admin_bool = UserModels.get_user_admin_bool(**{"id": user_id, "self": self, "field": "id"})

        if admin_bool:
            return {"data": {"detail": "无法修改admin的状态! "}, "status": 500}

        with transaction.atomic():
            sid = transaction.savepoint()
            try:
                instance = self.get_object()
                instance.status = data["status"]
                instance.save()

                OperationLog.objects.create(
                    operator=request.user.username,
                    operate_type=OperationLog.MODIFY,
                    operate_obj=instance.bk_username,
                    operate_summary="修改用户【{}】状态为【{}】".format(instance.bk_username,
                                                                    instance.get_status_display()),
                    current_ip=current_ip,
                    app_module="系统管理",
                    obj_type="用户管理",
                )
                data["user_id"] = instance.bk_user_id
                res = UserUtils.user_manage_update_status(
                    **{"cookies": request.COOKIES, "data": data, "manage_api": manage_api}
                )

            except Exception as user_error:
                logger.exception("修改用户状态失败. message={}".format(user_error))
                res = {"result": False}

            if not res["result"]:
                # 请求错误，或者创建失败 都回滚
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                return {"data": {"detail": "修改用户状态失败! "}, "status": 500}

            transaction.savepoint_commit(sid)

        return {"data": "修改用户状态成功"}


class RoleController(object):
    @classmethod
    def create_role_controller(cls, *args, **kwargs):
        """
        创建角色
        """
        self = kwargs["self"]
        request = kwargs["request"]
        role_data = copy.deepcopy(request.data)
        # res = self.create_alarmcenter_data(request)
        # if not res.get("result"):
        #     return res
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        serializer = self.get_serializer(data=role_data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        OperationLog.objects.create(
            operator=request.user.username,
            operate_type=OperationLog.ADD,
            operate_obj=role_data["role_name"],
            operate_summary="角色管理新增角色:[{}]".format(role_data["role_name"]),
            current_ip=current_ip,
            app_module="系统管理",
            obj_type="角色管理",
        )

        return serializer.data

    @classmethod
    def update_role_controller(cls, *args, **kwargs):
        """
        修改角色
        """
        self = kwargs["self"]
        request = kwargs["request"]
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        data, role_id = RoleUtils.get_update_role_data(**{"data": request.data})
        role_obj = RoleModels.get_role(role_id=role_id)
        if role_obj.built_in:
            return {"data": {"detail": "内置角色不允许被修改！"}, "status": 500}
        old_role_name, new_role_name = role_obj.role_name, data["role_name"]

        with transaction.atomic():
            serializer = RoleModels.update(**{"model_manage": self, "data": data, "instance": role_obj})
            OperationLog.objects.create(
                operator=request.user.username,
                operate_type=OperationLog.MODIFY,
                operate_obj=serializer.instance.role_name,
                operate_summary="角色管理修改角色:[{}]".format(serializer.instance.role_name),
                current_ip=current_ip,
                app_module="系统管理",
                obj_type="角色管理",
            )

        return {"data": "修改角色成功！"}

    @classmethod
    def delete_role_controller(cls, *args, **kwargs):
        """
        删除角色
        """
        request = kwargs["request"]
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        role_id = RoleUtils.get_role_id(**{"request": request})
        instance = RoleModels.get_role(role_id=role_id)
        if instance.built_in:
            return {"data": {"detail": "内置角色不允许被删除！"}, "status": 500}

        usernames = instance.sysuser_set.all().values_list("bk_username", flat=True)

        with transaction.atomic():
            RoleModels.delete(**{"instance": instance})
            OperationLog.objects.create(
                operator=request.user.username,
                operate_type=OperationLog.DELETE,
                operate_obj=instance.role_name,
                operate_summary="角色管理删除角色:[{}]".format(instance.role_name),
                current_ip=current_ip,
                app_module="系统管理",
                obj_type="角色管理",
            )

            CasbinRule.objects.filter(ptype="g", v1=instance.role_name).delete()
            CasbinRule.objects.filter(ptype="p", v0=instance.role_name).delete()

        # 删除角色 policy
        transaction.on_commit(
            lambda: sync_casbin_mesh_remove_policies(
                sec="g",
                ptype="g",
                rules=[[username, instance.role_name] for username in usernames],
            )
        )
        # 删除policy
        transaction.on_commit(
            lambda: sync_casbin_mesh_remove_filter_policies(
                sec="p", ptype="p", field_index=0, field_values=[instance.role_name]
            )
        )

        return {"data": "删除角色成功！"}

    @classmethod
    def get_role_resources(cls, *args, **kwargs):
        """
        获取角色的资源 如应用 页面权限
        """
        app_key = kwargs["app_key"]
        request = kwargs["request"]
        role_id = RoleUtils.get_role_id(**{"request": request})
        resource = RoleModels.get_role_resource(role_id=role_id, app_key=app_key)

        return resource

    @classmethod
    def get_role_operate_ids(cls, *args, **kwargs):
        """
        获取角色的操作权限
        """
        request = kwargs["request"]
        role_id = RoleUtils.get_role_id(**{"request": request})
        operate_ids = RoleModels.get_role_resource(role_id=role_id, app_key=DB_OPERATE_IDS)
        return operate_ids

    @classmethod
    def set_role_menus_operates(cls, *args, **kwargs):
        """
        设置角色的页面权限 页面接口权限
        """
        self = kwargs["self"]
        request = kwargs["request"]
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        data, role_id = RoleUtils.data_role_id(**{"data": request.data})
        super_bool = RoleModels.get_role_super_bool(**{"self": self, "id": role_id})
        if super_bool:
            return {"data": {"detail": "超级管理员角色拥有全部权限，不允许修改！"}, "status": 500}

        instance = RoleModels.get_role(role_id=role_id)

        add_data = {
            "sys_role_id": instance.id,
            "app_name": DB_MENU_IDS_DISPLAY_NAME,
            "app_key": DB_MENU_IDS,
            "app_ids": data[DB_MENU_IDS],
        }

        operate_id_add_data = {
            "sys_role_id": instance.id,
            "app_name": DB_OPERATE_IDS_DISPLAY_NAME,
            "app_key": DB_OPERATE_IDS,
            "app_ids": data[DB_OPERATE_IDS],
        }

        app_ids_data = {
            "sys_role": instance,
            "app_name": DB_APPS_DISPLAY_NAME,
            "app_key": DB_APPS,
            "app_ids": data[DB_APPS],
        }

        app_names = "{},{},{}".format(DB_MENU_IDS_DISPLAY_NAME, DB_OPERATE_IDS_DISPLAY_NAME, DB_APPS_DISPLAY_NAME)

        with transaction.atomic():
            sid = transaction.savepoint()
            try:
                RoleModels.set_role_resource(role_id=role_id, data=app_ids_data)
                RoleModels.set_role_resource(role_id=role_id, data=add_data)
                RoleModels.set_role_resource(role_id=role_id, data=operate_id_add_data)
                OperationLog.objects.create(
                    operator=request.user.username,
                    operate_type=OperationLog.MODIFY,
                    operate_obj=instance.role_name,
                    operate_summary="角色管理修改角色的[{}]".format(app_names),
                    current_ip=current_ip,
                    app_module="系统管理",
                    obj_type="角色管理",
                )

                # 把此角色的接口policy加入到policy里
                RoleModels.reset_role_policy(instance.role_name)
                casbin_mesh_policies = CasbinUtils.save_role_policy(instance, data[DB_OPERATE_IDS], add_data["app_ids"])

            except Exception as err:
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                logger.exception("修改角色权限错误！error={}".format(err))
                return {"data": {"detail": "设置错误，请重试"}, "status": 500}

            transaction.savepoint_commit(sid)

            add_policy_data = dict(sec="p", ptype="p", rules=casbin_mesh_policies)
            delete_policy_data = dict(sec="p", ptype="p", field_index=0, field_values=[instance.role_name])

            transaction.on_commit(
                lambda: sync_casbin_mesh_remove_add_policies(
                    create_data=add_policy_data, delete_data=delete_policy_data
                )
            )

        return {"data": "设置成功！"}

    @classmethod
    def get_menus(cls, *args, **kwargs):
        """
        从数据库查询到缓存的监控和资产记录里的其他的数据分组
        TODO 为什么要存数据库？
        """
        # from apps.monitor_mgmt.models import CloudPlatGroup

        cmdb_classification = Menus.get_menus_classification_list()

        classification_list = []
        for i in cmdb_classification:
            if i["bk_classification_id"] != "bk_host_manage":
                classification_list.append(i)

        monitor = Menus.get_monitor_group_dict()
        classification = {
            i["bk_classification_id"]: i["bk_classification_name"]
            for i in classification_list
            if i["bk_classification_id"] not in MENUS_REMOVE_CLASSIFICATIONS
        }

        # cloud_menu = dict(CloudPlatGroup.objects.all().values_list("name", "cn_name"))
        return {
            "classification": classification,
            "monitor": monitor,
            # "cloud": cloud_menu,
        }

    @classmethod
    def get_applications(cls, *args, **kwargs):
        """
        返回全部的功能模块
        """

        return MENUS_MAPPING

    @classmethod
    def role_set_users(cls, *args, **kwargs):
        """
        角色设置多个用户
        """
        self = kwargs["self"]
        request = kwargs["request"]
        current_ip = getattr(request, "current_ip", "127.0.0.1")
        users = set(request.data["users"])
        admin_user = SysUser.objects.get(bk_username="admin")

        add_user_names = []
        delete_user_names = []
        role_instance = self.get_object()

        if role_instance.role_name == DB_SUPER_USER and admin_user.id not in users:
            return {"data": {"detail": "无法去除admin的超管角色"}, "status": 500}
        if role_instance.role_name != DB_SUPER_USER and admin_user.id in users:
            return {"data": {"detail": "无法修改admin的角色! "}, "status": 500}
        add_user_abjects = SysUser.objects.filter(id__in=users)
        users_dict = dict(add_user_abjects.values_list("id", "bk_username"))
        users_dict.update(dict(role_instance.sysuser_set.all().values_list("id", "bk_username")))
        role_users = set(role_instance.sysuser_set.all().values_list("id", flat=True))
        if role_instance.role_name != DB_SUPER_USER:
            add_user_set, delete_user_set = RoleUtils.get_add_role_remove_role(roles=users, old_roles=role_users)
            add_user_names = [users_dict[i] for i in add_user_set]
            delete_user_names = [users_dict[i] for i in delete_user_set]

        with transaction.atomic():
            sid = transaction.savepoint()
            try:
                role_instance.sysuser_set.set(add_user_abjects)
                OperationLog.objects.create(
                    operator=request.user.username,
                    operate_type=OperationLog.MODIFY,
                    operate_obj=role_instance.role_name,
                    operate_summary="修改角色的用户，角色名称：[{}]，用户名称[{}]".format(
                        role_instance.role_name,
                        ",".join(chname for chname in users_dict.values()),
                    ),
                    current_ip=current_ip,
                    app_module="系统管理",
                    obj_type="角色管理",
                )

                transaction.on_commit(lambda: sync_role_permissions(add_user_names, delete_user_names))

                # 把此用户和角色加入policy
                CasbinUtils.set_role_user_policy(
                    role_name=role_instance.role_name,
                    add_user_names=add_user_names,
                    delete_user_names=delete_user_names,
                )

                transaction.savepoint_commit(sid)

            except Exception as err:
                logger.exception("设置用户角色失败！，error={}".format(err))
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                return {"data": {"detail": "设置用户角色失败! "}, "status": 500}

        # 删除角色 policy
        transaction.on_commit(
            lambda: sync_casbin_mesh_remove_policies(
                sec="g",
                ptype="g",
                rules=[[username, role_instance.role_name] for username in delete_user_names],
            )
        )
        # 新增角色policy
        transaction.on_commit(
            lambda: sync_casbin_mesh_add_policies(
                sec="g",
                ptype="g",
                rules=[[username, role_instance.role_name] for username in add_user_names],
            )
        )

        return {"data": "设置成功！"}

    @classmethod
    def open_set_casbin_mesh(cls):
        return CasbinUtils.casbin_change_workflow()


class KeycloakUserController(object):
    '''
    用户的增删改查全部借用管理员账号
    '''

    keycloak_utils: KeycloakUtils = KeycloakUtils()
    _settings = LazySettings()

    @classmethod
    def get_access_token(cls, username: str, password: str) -> str:
        token = cls.keycloak_utils.get_keycloak_openid().token(username, password).get('access_token', None)
        return token

    @classmethod
    def create_user(cls, user) -> str:
        '''
        返回的字典包含新创建用户的id
        '''
        # 该方法返回创建用户的id
        normal_role = cls.keycloak_utils.get_keycloak_admin().get_client_role(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
            'normal')
        id = cls.keycloak_utils.get_keycloak_admin().create_user(user)
        cls.keycloak_utils.get_keycloak_admin().assign_client_role(id, cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
                                                                   normal_role)
        return id

    @classmethod
    def get_user_list(cls, page, per_page, search):
        first = (page - 1) * per_page
        max = per_page
        params = {"first": first, "max": max, "search": search}
        users = cls.keycloak_utils.get_keycloak_admin().get_users(params)
        id_of_client = cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT']
        for user in users:
            user['roles'] = cls.keycloak_utils.get_keycloak_admin().get_client_roles_of_user(user['id'], id_of_client)
        return {"count": len(users), "users": users}

    @classmethod
    def get_user_in_role(cls, role_id: str, page, per_page):
        roles = cls.keycloak_utils.get_keycloak_admin().get_client_roles(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        role_name = None
        for role in roles:
            if role['id'] == role_id:
                role_name = role['name']
                break
        if not role_name:
            raise LookupError('role not found')
        first = (page - 1) * per_page
        max = per_page
        params = {"first": first, "max": max}
        users = cls.keycloak_utils.get_users_in_role(role_name, params)
        return users

    @classmethod
    def get_user_by_id(cls, id):
        user = cls.keycloak_utils.get_keycloak_admin().get_user(id)
        return user

    @classmethod
    def get_user_by_name(cls, name=None):
        params = {
            'exact': True,
            'username': name
        }
        users = cls.keycloak_utils.get_keycloak_admin().get_users(params)
        return users[0] if len(users) != 0 else None

    @classmethod
    def delete_user(cls, user_id: str):
        cls.keycloak_utils.get_keycloak_admin().delete_user(user_id)

    @classmethod
    def update_user(cls, user_id: str, payload: dict):
        cls.keycloak_utils.get_keycloak_admin().update_user(user_id, payload)

    @classmethod
    def reset_password(cls, user_id: str, password: str):
        cls.keycloak_utils.get_keycloak_admin().set_user_password(user_id, password, False)


class KeycloakRoleController:
    '''
    角色的操作(client role)，需同步policy的操作
    '''

    keycloak_utils: KeycloakUtils = KeycloakUtils()
    _settings = LazySettings()

    @classmethod
    def get_roles_by_user_id(cls, id: str):
        return cls.keycloak_utils.get_keycloak_admin().get_client_roles_of_user(id, cls._settings.KEYCLOAK_SETTINGS[
            'ID_OF_CLIENT'])

    @classmethod
    def get_user_in_role(cls, role_name: str):
        '''
        获取角色中的用户
        '''
        users = cls.keycloak_utils.get_keycloak_admin().get_client_role_members(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
            role_name)
        return users

    @classmethod
    def get_client_roles(cls):
        """
        获取所有客户端角色，把默认的角色删除
        """
        roles = cls.keycloak_utils.get_keycloak_admin().get_client_roles(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'], False)
        roles_dict = {r['name']: r for r in list(filter(lambda r: r['name'] != 'uma_protection', roles))}
        # 获取相关policy，并记录其id
        policies = cls.keycloak_utils.get_keycloak_admin().get_client_authz_policies(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        for policy in policies:
            if policy['name'] in roles_dict:
                roles_dict[policy['name']]['policy_id'] = policy['id']
        # 根据policy id查出依赖的permission
        for name, role in roles_dict.items():
            permissions = cls.keycloak_utils.get_permission_by_policy(role['policy_id'])
            role['permissions'] = permissions
        return list(roles_dict.values())

    @classmethod
    def create_client_role_and_policy(cls, role_name: str):
        """
        创建角色同时创建基于角色的策略
        返回创建的角色
        """
        role_payload = {
            'name': role_name,
            'clientRole': True
        }
        cls.keycloak_utils.get_keycloak_admin().create_client_role(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT']
                                                                   , role_payload)
        role = cls.keycloak_utils.get_keycloak_admin().get_client_role(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT']
                                                                       , role_name)
        policy_payload = {
            "type": "role",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "name": role_name,
            "roles": [
                {
                    "id": role["id"],
                    "required": True
                }
            ]
        }
        cls.keycloak_utils.get_keycloak_admin().create_client_authz_role_based_policy(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT']
            , policy_payload)
        return role

    @classmethod
    def delete_role(cls, role_id: str):
        """
        删除一个role，在keycloak中基于该role的policy会自动被删除
        """
        return cls.keycloak_utils.delete_client_role_by_id(role_id)

    @classmethod
    def assign_role_users(cls, role_id: str, user_id: str):
        """
        将一个用户纳入角色
        """
        role = cls.keycloak_utils.get_role_by_id(role_id)
        cls.keycloak_utils.get_keycloak_admin().assign_client_role(user_id, cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
                                                                   role)

    @classmethod
    def remove_role_users(cls, role_id: str, user_id: str):
        """
        将一个用户移除角色
        """
        role = cls.keycloak_utils.get_role_by_id(role_id)
        cls.keycloak_utils.get_keycloak_admin().delete_client_roles_of_user(user_id, cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
                                                                            role)

    @classmethod
    def ch_permission_role(cls, role_id: str, permission_id: str):
        """
        配置permission中的role(policy)
        """
        # 1.获取permission
        permission = None
        ps = cls.keycloak_utils.get_keycloak_admin().get_client_authz_permissions(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        for p in ps:
            if p['id'] == permission_id:
                permission = p
                break
        # 2.获取相关resources的id
        rs = cls.keycloak_utils.get_resources_by_permission(permission_id)
        resources = list(map(lambda r: r['_id'], rs))
        # 3.获取相关policy的id
        acpos = cls.keycloak_utils.get_policy_by_permission(permission_id)
        policies = list(map(lambda p: p['id'], acpos))
        # 4.通过role name获取需要被更更改的 policyid
        pos = cls.keycloak_utils.get_keycloak_admin().get_client_authz_policies(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        policy_id = None
        for po in pos:
            if po['type'] == 'role':
                if json.loads(po['config']['roles'])[0]['id'] == role_id:
                    policy_id = po['id']
                    break
        # 5.构建payload
        payload = permission
        payload['resources'] = resources
        # 6.如不存在policy则增，反之
        if policy_id in policies:
            policies.remove(policy_id)
        else:
            policies.append(policy_id)
        payload['policies'] = policies
        payload['scopes'] = []
        cls.keycloak_utils.update_permission(permission_id, payload)


class KeycloakPermissionController:
    '''
    权限操作
    '''

    keycloak_utils: KeycloakUtils = KeycloakUtils()
    _settings = LazySettings()

    @classmethod
    def get_all_permissions(cls):
        return cls.keycloak_utils.get_keycloak_admin().get_client_authz_permissions(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])

    @classmethod
    def get_permissions(cls, token: str) -> list:
        '''
        获取token持有者所拥有的权限
        '''
        # 获取所有权限
        all_permissions = cls.keycloak_utils.get_keycloak_admin().get_client_authz_permissions(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        ps = [{'name': d['name'], 'des': d['description'], 'id':d['id'], 'allow': False} for d in all_permissions if d['name'] != 'Default Permission']
        try:
            allow_p = cls.keycloak_utils.get_keycloak_openid().uma_permissions(token)
            p_list = [d['rsname'] for d in allow_p]
            for permission in ps:
                if permission['name'] in p_list:
                    permission['allow'] = True
        except Exception as e:
            pass
        return ps

    @classmethod
    def has_permissions(cls, token: str, permission_name: str) -> bool:
        try:
            cls.keycloak_utils.get_keycloak_openid().uma_permissions(token, permissions=[permission_name])
        except Exception as e:
            return False
        return True
