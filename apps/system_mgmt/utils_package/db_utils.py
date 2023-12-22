# -*- coding: utf-8 -*-

# @File    : db_utils.py
# @Date    : 2022-02-15
# @Author  : windyzhao

from apps.system_mgmt.constants import DB_SUPER_USER
from blueapps.core.exceptions import BlueException
from utils.app_log import logger


def user_super(user):
    """
    判断此用户是否是超管角色
    """
    return user.sys_user.roles.filter(role_name=DB_SUPER_USER).first()


def get_role_menus(self, role_objs):
    """
    获取用户所在角色的菜单合集
    """
    pass


class UserUtils(object):

    @classmethod
    def formative_user_data(cls, *args, **kwargs):
        """
        格式化新增用户入库数据
        """
        user_data = {}
        data = kwargs["data"]
        normal_role = kwargs["normal_role"]
        user_data["bk_username"] = data["username"]
        user_data["chname"] = data["display_name"]
        user_data["phone"] = data.get("telephone", '000')
        user_data["email"] = data.get('email', 'example@ex.com')
        user_data["leader"] = data.get("leader", [])
        user_data["roles"] = normal_role

        return user_data

    @classmethod
    def formative_update_user_data(cls, *args, **kwargs):
        """
        格式化修改用户入库数据
        """
        update_data = {}
        data = kwargs["data"]
        bk_user_id = data.get("bk_user_id", 0)
        user_id = data.pop("id")
        update_data["chname"] = data["display_name"]
        phone = data.get('telephone', None)
        if phone:
            update_data["phone"] = phone
        email = data.get('email', None)
        if email:
            update_data['email'] = email
        update_data["leader"] = data.get("leader", [])

        return update_data, bk_user_id, user_id

    @classmethod
    def username_manage_update_user(cls, *args, **kwargs):
        """
        用户修改
        """
        data = kwargs["data"]
        cookies = kwargs["cookies"]
        bk_user_id = kwargs["bk_user_id"]
        manage_api = kwargs["manage_api"]
        manage_api.set_header(cookies)
        res = manage_api.update_bk_user_manage(data=data, id=bk_user_id)
        return res

    @classmethod
    def username_manage_get_bk_user_id(cls, *args, **kwargs):
        """
        获取bk_user_id
        """
        data = kwargs["data"]
        bk_user_id = data.pop("id")
        return data, bk_user_id

    @classmethod
    def username_manage_reset_password(cls, *args, **kwargs):
        """
        用户重置密码
        """
        data = kwargs["data"]
        cookies = kwargs["cookies"]
        bk_user_id = kwargs["bk_user_id"]
        manage_api = kwargs["manage_api"]
        manage_api.set_header(cookies)
        res = manage_api.reset_passwords(data=data, id=bk_user_id)
        return res

    @classmethod
    def username_manage_get_user_data(cls, *args, **kwargs):
        """
        删除用户取值
        """
        request = kwargs["request"]
        user_id = int(request.GET["id"])
        bk_user_id = int(request.GET["bk_user_id"])

        return user_id, bk_user_id

    @classmethod
    def username_manage_delete_user(cls, *args, **kwargs):
        """
        用户删除
        """
        data = kwargs["data"]
        cookies = kwargs["cookies"]
        manage_api = kwargs["manage_api"]
        manage_api.set_header(cookies)
        res = manage_api.delete_bk_user_manage(data=data)
        return res

    @classmethod
    def user_manage_update_status(cls, *args, **kwargs):
        data = kwargs["data"]
        cookies = kwargs["cookies"]
        manage_api = kwargs["manage_api"]
        manage_api.set_header(cookies)
        res = manage_api.update_user_status(data=data)
        return res

    @classmethod
    def username_manage_get_user_role_data(cls, *args, **kwargs):
        """
        设置角色取值
        """
        data = kwargs["data"]
        user_id = data.get("id")
        roles_ids = data.get("roles")

        return user_id, roles_ids


class RoleUtils(object):
    @classmethod
    def get_update_role_data(cls, *args, **kwargs):
        data = kwargs["data"]
        return data, data.pop("id")

    @classmethod
    def get_role_id(cls, *args, **kwargs):
        request = kwargs["request"]
        role_id = request.GET["id"]
        return role_id

    @classmethod
    def data_role_id(cls, *args, **kwargs):
        data = kwargs["data"]
        role_id = data.pop("id")
        return data, role_id

    @classmethod
    def get_add_role_remove_role(cls, *args, **kwargs):
        roles = kwargs["roles"]  # 新
        old_roles = kwargs["old_roles"]  # 旧

        add_role_set = set()
        delete_role_set = set()

        for role in roles:
            if role not in old_roles:
                add_role_set.add(role)

        for old_role in old_roles:
            if old_role not in roles:
                delete_role_set.add(old_role)

        return add_role_set, delete_role_set
