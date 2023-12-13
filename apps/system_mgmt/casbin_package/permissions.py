import re

from rest_framework.permissions import BasePermission

from apps.system_mgmt.casbin_package.cabin_inst_rbac import INST_NAMESPACE
from apps.system_mgmt.casbin_package.policy_constants import (
    manageAllArticlesAuth,
    manageDeskArticlesAuth,
    manageMyArticlesAuth,
)
from apps.system_mgmt.constants import (
    DB_APPS,
    DB_APPS_DISPLAY_NAME,
    DB_MENU_IDS,
    DB_NOT_ACTIVATION_ROLE,
    DB_OPERATE_IDS,
    DB_SUPER_USER,
)
from apps.system_mgmt.models import SysApps, SysRole, SysUser
from apps.system_mgmt.utils import BizUtils
from blueapps.account.models import User
from apps.system_mgmt.common_utils.casbin_mesh_common import CasbinMeshApiServer
from utils.exceptions import GetDateError


def get_user_super_group(user: User):
    """
    判断是否是超级管理员角色
    """
    user.is_super = False
    sys_user = SysUser.objects.get(bk_username=user.username)
    super_group = sys_user.roles.filter(role_name=DB_SUPER_USER).exists()
    user.is_super = super_group
    return super_group


def get_user_roles(user: User, activate: bool = True):
    """根据user判断是否超管 获取应用和菜单权限 设置user的应用和对应的sysuser"""

    user_super = False
    user_menus = []
    user_apps = []
    operate_ids = []

    user.role = None
    user.sys_user = None
    user.biz_ids = []

    sys_user = SysUser.objects.filter(bk_username=user.username).first()
    if not sys_user:
        raise GetDateError("用户[{}]不存在!".format(user.username))
    chname = sys_user.chname
    if not activate:
        roles = SysRole.activate_manage.filter(role_name=DB_NOT_ACTIVATION_ROLE)
        super_group = None
    else:
        roles = sys_user.roles.all()
        super_group = roles.filter(role_name=DB_SUPER_USER).first()
    if super_group is not None:
        user_super = True
        user_apps_obj = SysApps.objects.filter(app_key=DB_APPS, sys_role=super_group).first()
        if user_apps_obj is None:
            # user_apps = [i["bk_biz_id"] for i in BizUtils.get_all_biz_list()]
            SysApps.objects.create(
                **{
                    "app_name": DB_APPS_DISPLAY_NAME,
                    "app_key": DB_APPS,
                    "sys_role": super_group,
                    "app_ids": user_apps,
                }
            )

        else:
            user_apps = user_apps_obj.app_ids
    else:
        for role in roles:
            apps = role.sysapps_set.all()
            menus_list = [i.app_ids for i in apps if i.app_key == DB_MENU_IDS]
            apps_list = [i.app_ids for i in apps if i.app_key == DB_APPS]
            operate_ids_list = [i.app_ids for i in apps if i.app_key == DB_OPERATE_IDS]

            for menus in menus_list:
                user_menus.extend(menus)

            for app in apps_list:
                user_apps.extend(app)

            for operate_id in operate_ids_list:
                operate_ids.extend(operate_id)

    user_menus = list(set(user_menus))
    user_apps = list(set(user_apps))

    user.role = list(sys_user.roles.all().values_list("id", flat=True))
    user.sys_user = sys_user
    user.biz_ids = user_apps
    user.is_superuser = user_super
    user.is_super = user_super
    user.operate_ids = operate_ids

    return user_super, user_apps, user_menus, chname, operate_ids


class ManagerPermission(BasePermission):
    """
    Allows access only to authenticated users.
    管理员权限 主要作用为得到当前用户对应角色对业务
    """

    def has_permission(self, request, view):
        get_user_roles(request.user)
        return True


class UserSuperPermission(BasePermission):
    """
    给request.user新增一些超管设置
    """

    def has_permission(self, request, view):
        get_user_super_group(request.user)
        return True


class RepositoryItServerTagPermission(BasePermission):
    """
    对于服务台文章，控制此用户能否把文章设置为服务台文章
    """

    def has_permission(self, request, view):
        is_super = get_user_super_group(request.user)
        if is_super:
            return True

        apps_ids_list = SysApps.objects.filter(
            sys_role__sysuser__bk_username=request.user.username, app_key=DB_OPERATE_IDS
        ).values_list("app_ids", flat=True)
        for apps_ids in apps_ids_list:
            if not apps_ids:
                continue
            for apps_id in apps_ids:
                if manageDeskArticlesAuth in apps_id["operate_ids"]:
                    return True
        return False


class RepositoryRoleOperatePermission(BasePermission):
    """
    此用户能否操作知识库文章
    管理我的文章：只能操作自己写的文章 若存在manageMyArticlesAuth 放行到controller里管理
    管理所有文章：全部都可以
    """

    @staticmethod
    def path_match(path):
        res = re.match(r"/repository/(?P<pk>[^/.]+)/", path)
        return res is None

    def has_permission(self, request, view):

        if request.method not in ["PUT", "DELETE"] or self.path_match(request.path):
            return True

        is_super = get_user_super_group(request.user)
        if is_super:
            return True

        apps_ids_list = SysApps.objects.filter(
            sys_role__sysuser__bk_username=request.user.username, app_key=DB_OPERATE_IDS
        ).values_list("app_ids", flat=True)
        for apps_ids in apps_ids_list:
            if not apps_ids:
                continue
            for apps_id in apps_ids:
                if manageAllArticlesAuth in apps_id["operate_ids"]:
                    return True
                if manageMyArticlesAuth in apps_id["operate_ids"]:
                    if request.user.username == view.get_object().created_by:
                        return True
        return False


class BaseInstPermission(BasePermission):
    INSTANCE_TYPE = "实力类型"
    INST_PERMISSION = "权限类型"

    def has_permission(self, request, view):
        inst_id = self.get_instance_id(request, view)
        if not inst_id:
            return False
        if isinstance(inst_id, list):
            _has_permission = self.enforce_list(request, view, inst_id)
        else:
            _has_permission = self.enforce(request, view, inst_id)
        return _has_permission

    def enforce(self, request, view, inst_id):
        username = request.user.username
        if self.is_super(username):
            return True
        instance_type = self.instance_type(request, view)  # 构造过 若监控和策略，额外逻辑
        policy = [username, instance_type, self.inst_permission, str(inst_id)]
        _has_permission = CasbinMeshApiServer.enforce(namespace=self.namespace, params=policy)
        return _has_permission

    def enforce_list(self, request, view, inst_id_list):
        """
        批量操作
        一个实例没有权限 就没有权限
        全部通过才返回True
        """
        username = request.user.username
        if self.is_super(username):
            return True
        instance_type = self.instance_type(request, view)  # 构造过 若监控和策略，额外逻辑
        for inst_id in inst_id_list:
            policy = [username, instance_type, self.inst_permission, str(inst_id)]
            _has_permission = CasbinMeshApiServer.enforce(namespace=self.namespace, params=policy)
            if not _has_permission:
                return _has_permission
        return True

    def get_instance_id(self, request, view):
        """
        重写查询到实例id的方法 返回实例id
        """
        raise NotImplementedError

    def instance_type(self, request, view):
        return self.INSTANCE_TYPE

    @property
    def inst_permission(self):
        return self.INST_PERMISSION

    @property
    def namespace(self):
        return INST_NAMESPACE

    @staticmethod
    def is_super(username):
        if username == "admin":
            return True
        is_super = SysRole.objects.filter(role_name=DB_SUPER_USER, sysuser__bk_username=username).exists()
        return is_super
