# -*- coding: utf-8 -*-

# @File    : db_utils.py
# @Date    : 2022-02-15
# @Author  : windyzhao
import json

from django.db import connection

from apps.system_mgmt.constants import DB_SUPER_USER
from blueapps.core.exceptions import BlueException
from blueapps.utils import get_client_by_user
from utils.app_log import logger
from utils.sql_utils import NativeSql


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
    @staticmethod
    def get_bk_user(bk_username):
        client = get_client_by_user("admin")
        result = client.usermanage.retrieve_user({"id": bk_username, "lookup_field": "username", "fields": "id"})
        if not result["result"]:
            logger.exception(result["message"])
            raise BlueException()
        return result["data"]

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
    def username_manage_add_user(cls, *args, **kwargs):
        data = kwargs["data"]
        cookies = kwargs["cookies"]
        manage_api = kwargs["manage_api"]
        manage_api.set_header(cookies)
        res = manage_api.add_bk_user_manage(data=data)
        if res["result"]:
            user_id = cls.get_bk_user(data["username"])
            if not user_id:
                res = {"result": False, "message": "查询用户id失败！"}
            res["data"] = user_id
        return res

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


class RolePermissionUtil(object):
    """
    权限中心 超级管理员工具类
    """

    def __init__(self, username):
        self.operator_mapping = {0: "no_change", 1: "add", 2: "delete"}
        self.bkiam_db = "bkiam"
        self.bk_iam_db = "bk_iam"
        self.username = username
        self.select_subject = "select pk from subject where id='{}';".format(username)  # 查询用户的pk
        # 用户加入权限角色表 ("super_manager","SUPER",14)
        self.insert_subject_role = "INSERT into subject_role (role_type,system_id,subject_pk) VALUES {};"

        self.select_role_role = "select id from role_role where type='super_manager';"  # 查询超管id
        self.insert_role_roleuser = (
            "INSERT into role_roleuser (role_id, username) VALUES {};"  # 用户加入页面展示权限角色表(1,"test")
        )

        self.select_role_roleusersystempermission = (
            "select content from role_roleusersystempermission where role_id={};"  # 查询超管角色的用户
        )
        self.update_role_roleusersystempermission = (
            "UPDATE role_roleusersystempermission set content='{}' where role_id={};"  # 修改超管角色的用户
        )

        # 删除
        self.delete_subject_role = "delete from subject_role where subject_pk={} and role_type='{}' and system_id='{}';"

        self.delete_role_user = "delete from role_roleuser where role_id={} and username='{}';"

        self.connection = NativeSql(**self.init_connection())

    @staticmethod
    def init_connection():
        db_config = connection.get_connection_params()
        res = {
            "user": db_config["user"],
            "password": db_config["passwd"],
            "host": db_config["host"],
            "port": db_config["port"],
        }

        return res

    def init_bkiam(self):
        """
        权限中心saas展示信息同步
        """
        try:
            self.connection.get_cursor(db=self.bkiam_db)
            select_data_list = self.connection.execute_sql_one(self.select_subject)
            assert len(select_data_list) > 0
            subject_pk = select_data_list[0]

            select_user = """select pk from subject_role
where subject_pk={} and role_type='{}' and system_id='{}';""".format(
                subject_pk, "super_manager", "SUPER"
            )

            role_bool = self.connection.execute_sql(select_user)

            if role_bool:
                return 0

            self.connection.create_sql(self.insert_subject_role.format(("super_manager", "SUPER", subject_pk)))

            self.connection.commit()
            return True

        except Exception as err:
            logger.exception("init_bkiam直连权限中心数据库修改超管执行SQL报错！, error={}".format(err))
            self.close_connection()
            return False

    def init_bk_iam(self):
        """
        权限中心 用户授权
        """
        res = True

        try:
            self.connection.get_cursor(db=self.bk_iam_db)

            data = self.connection.execute_sql_one(self.select_role_role)
            assert len(data) > 0
            role_id = data[0]

            self.connection.create_sql(self.insert_role_roleuser.format((role_id, self.username)))

            content_data = self.connection.execute_sql_one(self.select_role_roleusersystempermission.format(role_id))
            assert len(content_data) > 0
            content = content_data[0]
            content = json.loads(content)
            content["enabled_users"].append(self.username)

            self.connection.update_sql(self.update_role_roleusersystempermission.format(json.dumps(content), role_id))

            self.connection.commit()
        except Exception as err:
            logger.exception("init_bk_iam直连权限中心数据库修改超管执行SQL报错！, error={}".format(err))

            self.connection.rollback()

            res = False

        self.close_connection()

        return res

    def delete_bkiam(self):
        """
        删除subject_role
        """
        try:
            self.connection.get_cursor(db=self.bkiam_db)
            select_data_list = self.connection.execute_sql_one(self.select_subject)
            assert len(select_data_list) > 0
            subject_pk = select_data_list[0]
            self.connection.delete_sql(self.delete_subject_role.format(subject_pk, "super_manager", "SUPER"))

            self.connection.commit()
            return True

        except Exception as err:
            logger.exception("init_bkiam直连权限中心数据库删除超管执行SQL报错！, error={}".format(err))

            self.close_connection()
            return False

    def delete_bk_iam(self):
        """
        权限中心取消用户授权
        """
        res = True

        try:
            self.connection.get_cursor(db=self.bk_iam_db)

            data = self.connection.execute_sql_one(self.select_role_role)
            assert len(data) > 0
            role_id = data[0]

            self.connection.delete_sql(self.delete_role_user.format(role_id, self.username))

            content_data = self.connection.execute_sql_one(self.select_role_roleusersystempermission.format(role_id))
            assert len(content_data) > 0
            content = content_data[0]
            content = json.loads(content)

            if self.username in content["enabled_users"]:
                content["enabled_users"].remove(self.username)
                self.connection.update_sql(
                    self.update_role_roleusersystempermission.format(json.dumps(content), role_id)
                )

            self.connection.commit()
        except Exception as err:
            logger.exception("init_bk_iam直连权限中心数据库修改超管执行SQL报错！, error={}".format(err))

            self.connection.rollback()

            res = False

        self.close_connection()

        return res

    def add_main(self):
        """
        0表示权限中心已经存在此角色 不走新增
        """
        bkiam_res = self.init_bkiam()
        if bkiam_res == 0:
            self.close_connection()
            return True
        if not bkiam_res:
            self.close_connection()
            return bkiam_res
        return self.init_bk_iam()

    def delete_main(self):
        bkiam_res = self.delete_bkiam()
        if not bkiam_res:
            self.close_connection()
            return bkiam_res
        return self.delete_bk_iam()

    def close_connection(self):
        try:
            self.connection.close_cursor()
            self.connection.close_connection()
        except Exception as err:
            logger.exception("关闭mysql连接失败！error={}".format(err))
