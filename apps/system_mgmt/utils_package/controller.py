# -*- coding: utf-8 -*-

# @File    : controller.py
# @Date    : 2022-03-25
# @Author  : windyzhao

import json

from collections import defaultdict
from datetime import datetime

from django.conf import LazySettings
from django.db import transaction

from apps.system_mgmt.models import OperationLog, SysUser
from apps.system_mgmt.utils_package.dao import UserModels
from apps.system_mgmt.utils_package.db_utils import RoleUtils, UserUtils
from apps.system_mgmt.utils_package.keycloak_utils import KeycloakUtils
from utils.app_log import logger
from utils.app_utils import AppUtils


class UserController(object):
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

        with transaction.atomic():
            sid = transaction.savepoint()
            try:
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
                transaction.savepoint_commit(sid)

            except Exception as err:
                logger.exception("设置用户角色失败！，error={}".format(err))
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                return {"result": False, "data": {}, "message": "设置用户角色失败！请联系管理员"}

        return {"result": True, "data": {}, "message": "设置用户角色成功！"}

    @classmethod
    def add_user_controller(cls, *args, **kwargs):
        """
        新增用户
        """
        self = kwargs["self"]
        request = kwargs["request"]
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
                res = {"result": True}
            except Exception as user_error:
                logger.exception("新增用户调用用户管理接口失败. message={}".format(user_error))
                res = {"result": False, 'error': str(user_error)}

            if not res["result"]:
                # 请求错误，或者创建失败 都回滚
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)

                return {"data": {"detail": f"创建用户失败! {res['error']}"}, "status": 500}

            transaction.savepoint_commit(sid)

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

                # 把此用户和角色加入policy
                add_role, delete_role = RoleUtils.get_add_role_remove_role(roles=roles_names, old_roles=old_user_role)
                transaction.savepoint_commit(sid)

            except Exception as err:
                logger.exception("设置用户角色失败！，error={}".format(err))
                transaction.savepoint_rollback(sid)
                transaction.savepoint_commit(sid)
                return {"data": {"detail": "设置用户角色失败! "}, "status": 500}

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


class KeycloakUserController(object):
    '''
    用户的增删改查全部借用管理员账号
    '''

    # keycloak_utils: KeycloakUtils = KeycloakUtils()
    _keycloak_utils = None

    @classmethod
    def keycloak_utils(cls):
        if cls._keycloak_utils is None:
            cls._keycloak_utils = KeycloakUtils()
        return cls._keycloak_utils
    _settings = LazySettings()

    @classmethod
    def get_token(cls, username: str, password: str) -> (str, str):
        token = cls.keycloak_utils().get_keycloak_openid().token(username, password)
        return token.get('access_token', None)

    @classmethod
    def create_user(cls, user) -> str:
        '''
        返回的字典包含新创建用户的id
        '''
        # 该方法返回创建用户的id
        normal_role = cls.keycloak_utils().get_keycloak_admin().get_client_role(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
            'normal')
        id = cls.keycloak_utils().get_keycloak_admin().create_user(user)
        cls.keycloak_utils().get_keycloak_admin().assign_client_role(
            id, cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'], normal_role)
        return id

    @classmethod
    def get_user_list(cls, page, per_page, search):
        first = (page - 1) * per_page
        max = per_page
        params = {"first": first, "max": max, "search": search}
        users = cls.keycloak_utils().get_keycloak_admin().get_users(params)
        id_of_client = cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT']
        for user in users:
            user['roles'] = cls.keycloak_utils().get_keycloak_admin().get_client_roles_of_user(user['id'], id_of_client)
        return {"count": len(users), "users": users}

    @classmethod
    def get_user_in_role(cls, role_id: str, page, per_page):
        roles = cls.keycloak_utils().get_keycloak_admin().get_client_roles(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
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
        users = cls.keycloak_utils().get_users_in_role(role_name, params)
        return users

    @classmethod
    def get_user_by_id(cls, id):
        user = cls.keycloak_utils().get_keycloak_admin().get_user(id)
        return user

    @classmethod
    def get_user_by_name(cls, name=None):
        params = {
            'exact': True,
            'username': name
        }
        users = cls.keycloak_utils().get_keycloak_admin().get_users(params)
        return users[0] if len(users) != 0 else None

    @classmethod
    def delete_user(cls, user_id: str):
        cls.keycloak_utils().get_keycloak_admin().delete_user(user_id)

    @classmethod
    def update_user(cls, user_id: str, payload: dict):
        cls.keycloak_utils().get_keycloak_admin().update_user(user_id, payload)

    @classmethod
    def reset_password(cls, user_id: str, password: str):
        cls.keycloak_utils().get_keycloak_admin().set_user_password(user_id, password, False)


class KeycloakRoleController:
    '''
    角色的操作(client role)，需同步policy的操作
    '''

    # keycloak_utils: KeycloakUtils = KeycloakUtils()
    _keycloak_utils = None

    @classmethod
    def keycloak_utils(cls):
        if cls._keycloak_utils is None:
            cls._keycloak_utils = KeycloakUtils()
        return cls._keycloak_utils
    _settings = LazySettings()

    @classmethod
    def get_roles_by_user_id(cls, id: str):
        return cls.keycloak_utils().get_keycloak_admin().get_client_roles_of_user(id, cls._settings.KEYCLOAK_SETTINGS[
            'ID_OF_CLIENT'])

    @classmethod
    def get_user_in_role(cls, role_name: str):
        '''
        获取角色中的用户
        '''
        users = cls.keycloak_utils().get_keycloak_admin().get_client_role_members(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
            role_name)
        return users

    @classmethod
    def get_client_roles(cls):
        """
        获取所有客户端角色，把默认的角色删除
        无权限，权限去详情接口里找
        """
        roles = cls.keycloak_utils().get_keycloak_admin().get_client_roles(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'], False)
        roles_dict = {r['name']: r for r in list(filter(lambda r: r['name'] != 'uma_protection', roles))}
        # 获取相关policy，并记录其id
        # policies = cls.keycloak_utils().get_keycloak_admin().get_client_authz_policies(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        # for policy in policies:
        #     if policy['name'] in roles_dict:
        #         roles_dict[policy['name']]['policy_id'] = policy['id']
        # # 根据policy id查出依赖的permission
        # for name, role in roles_dict.items():
        #     permissions = cls.keycloak_utils().get_permission_by_policy(role['policy_id'])
        #     role['permissions'] = permissions
        return list(roles_dict.values())

    @classmethod
    def get_client_roles_permissions_by_id(cls, role_id: str):
        """
        根据角色id获取其详情以及其所拥有的权限
        """
        role = cls.keycloak_utils().get_role_by_id(role_id)
        # 获取相关policy，并记录其id
        policies = cls.keycloak_utils().get_keycloak_admin().get_client_authz_policies(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        for policy in policies:
            if policy['name'] == role['name']:
                role['policy_id'] = policy['id']
                break
        # 获取所有permission
        all_permissions = cls.keycloak_utils().get_keycloak_admin().get_client_authz_permissions(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        ps = [{'name': d['name'], 'des': d['description'], 'id': d['id'], 'allow': False} for d in all_permissions if
              d['name'] != 'Default Permission']
        ps = {p['name']: p for p in ps}
        # 获取相关permissions
        ac_permissions = cls.keycloak_utils().get_permission_by_policy(role['policy_id'])
        for ac_p in ac_permissions:
            ps[ac_p['name']]['allow'] = True
        ps = ps.values()
        # 为permissions分层
        ps_dict = defaultdict(list)
        for p in ps:
            prefix = p['name'].split('_')[0]
            ps_dict[prefix].append(p)
        role['permissions'] = dict(ps_dict)
        return role

    @classmethod
    def create_client_role_and_policy(cls, role_name: str, des: str):
        """
        创建角色同时创建基于角色的策略
        返回创建的角色
        """
        # 获取当前时间
        current_time = datetime.now()
        formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        role_payload = {
            'name': role_name,
            'description': des,
            'attributes': {'created':[formatted_time, ]},
            'clientRole': True
        }
        cls.keycloak_utils().get_keycloak_admin().create_client_role(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT']
                                                                     , role_payload)
        role = cls.keycloak_utils().get_keycloak_admin().get_client_role(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT']
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
        cls.keycloak_utils().get_keycloak_admin().create_client_authz_role_based_policy(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT']
            , policy_payload)
        return role

    @classmethod
    def delete_role(cls, role_id: str):
        """
        删除一个role，在keycloak中基于该role的policy会自动被删除
        """
        return cls.keycloak_utils().delete_client_role_by_id(role_id)

    @classmethod
    def assign_role_users(cls, role_id: str, user_id: str):
        """
        将一个用户纳入角色
        """
        role = cls.keycloak_utils().get_role_by_id(role_id)
        cls.keycloak_utils().get_keycloak_admin().assign_client_role(user_id, cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
                                                                     role)

    @classmethod
    def remove_role_users(cls, role_id: str, user_id: str):
        """
        将一个用户移除角色
        """
        role = cls.keycloak_utils().get_role_by_id(role_id)
        cls.keycloak_utils().get_keycloak_admin().delete_client_roles_of_user(user_id, cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
                                                                              role)

    @classmethod
    def ch_permission_role(cls, role_id: str, permission_ids: list):
        """
        配置permission中的role(policy)
        """
        # 1.获取permissions
        permissions = list()
        ps = cls.keycloak_utils().get_keycloak_admin().get_client_authz_permissions(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        for p in ps:
            if p['id'] in permission_ids:
                permissions.append(p)
        # 2.获取所有permission相关的resources的id
        # resources = [[r['_id']] for p_id in permission_ids for r in
        #              cls.keycloak_utils().get_resources_by_permission(p_id)]
        resources = list()
        for p_id in permission_ids:
            resources.append(list(map(lambda r: r['_id'], cls.keycloak_utils().get_resources_by_permission(p_id))))
        # 3.获取所有permission相关policy的id
        # policies = [[p['id']] for p_id in permission_ids for p in cls.keycloak_utils().get_policy_by_permission(p_id)]
        policies = list()
        for p_id in permission_ids:
            policies.append(list(map(lambda p: p['id'], cls.keycloak_utils().get_policy_by_permission(p_id))))
        # 4.通过role id获取需要被更更改的 policyid
        policy_id = None
        pos = cls.keycloak_utils().get_keycloak_admin().get_client_authz_policies(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        for po in pos:
            if po['type'] == 'role':
                if json.loads(po['config']['roles'])[0]['id'] == role_id:
                    policy_id = po['id']
                    break
        # 5.构建payload
        for permission, resource, policy in zip(permissions, resources, policies):
            payload = permission
            payload['resources'] = resource
            # 6.如不存在policy则增，反之
            payload['policies'] = policy
            if policy_id in payload['policies']:
                payload['policies'].remove(policy_id)
            else:
                payload['policies'].append(policy_id)
            payload['scopes'] = []
            cls.keycloak_utils().update_permission(permission['id'], payload)

    @classmethod
    def edit_role(cls, role_id: str, des : str):
        """
        编辑角色的描述
        """
        roles = cls.keycloak_utils().get_keycloak_admin().get_client_roles(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        role = None
        for r in roles:
            if r['id'] == role_id:
                role = r
                break
        role['description'] = des
        cls.keycloak_utils().get_keycloak_admin().update_client_role(cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'],
                                                                     role['name'],
                                                                     role)


class KeycloakPermissionController:
    '''
    权限操作
    '''

    # keycloak_utils: KeycloakUtils = KeycloakUtils()
    _keycloak_utils = None

    @classmethod
    def keycloak_utils(cls):
        if cls._keycloak_utils is None:
            cls._keycloak_utils = KeycloakUtils()
        return cls._keycloak_utils
    _settings = LazySettings()

    @classmethod
    def get_all_permissions(cls):
        return cls.keycloak_utils().get_keycloak_admin().get_client_authz_permissions(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])

    @classmethod
    def get_permissions(cls, token: str) -> dict:
        '''
        获取token持有者所拥有的权限
        '''
        # 获取所有权限
        all_permissions = cls.keycloak_utils().get_keycloak_admin().get_client_authz_permissions(
            cls._settings.KEYCLOAK_SETTINGS['ID_OF_CLIENT'])
        ps = [{'name': d['name'], 'des': d['description'], 'id':d['id'], 'allow': False} for d in all_permissions if d['name'] != 'Default Permission']
        try:
            allow_p = cls.keycloak_utils().get_keycloak_openid().uma_permissions(token)
            p_list = [d['rsname'] for d in allow_p]
            for permission in ps:
                if permission['name'] in p_list:
                    permission['allow'] = True
            pd = dict()
            for permission in ps:
                strs = permission['name'].split("_")
                if not pd.get(strs[0], None):
                    pd[strs[0]] = [permission]
                else:
                    pd[strs[0]].append(permission)
        except Exception as e:
            pass
        return pd

    @classmethod
    def has_permissions(cls, token: str, permission_name: str) -> bool:
        try:
            cls.keycloak_utils().get_keycloak_openid().uma_permissions(token, permissions= [permission_name, ])
        except Exception as e:
            return False
        return True
