import importlib
import json
import os
from inspect import isfunction

from django.conf import LazySettings
from django.conf import settings as conf_settings
from django.db import transaction
from keycloak import KeycloakAdmin

from apps.system_mgmt.constants import (
    DB_APPS,
    DB_APPS_DISPLAY_NAME,
    DB_NORMAL_USER,
    DB_NOT_ACTIVATION_ROLE,
    DB_SUPER_USER,
    DOMAIN,
    MENU_DATA,
    init_templates,
)
from apps.system_mgmt.models import MenuManage, OperationLog, SysApps, SysRole, SysUser
from apps.system_mgmt.utils_package.casbin_utils import CasBinInstUtils, CasbinUtils
from apps.system_mgmt.utils_package.db_utils import RolePermissionUtil
from blueking.component.shortcuts import get_client_by_user
from apps.system_mgmt.common_utils.bk_api_utils.cc import BkApiCCUtils
from apps.system_mgmt.common_utils.bk_api_utils.usermanager import BKUserApiCCUtils
from apps.system_mgmt.common_utils.casbin_inst_service import CasBinInstService
from apps.system_mgmt.common_utils.utils import split_list
from utils import constants, exceptions
from utils.app_log import celery_logger as logger
from utils.decorators import catch_exception, time_consuming


class BizUtils(object):
    @staticmethod
    def get_all_biz_list():
        """获取所有业务列表"""
        client = get_client_by_user("admin")
        all_biz_list = BkApiCCUtils.search_business(client, fields=["bk_biz_name", "bk_biz_id"])
        [biz.pop("default") for biz in all_biz_list]
        return all_biz_list

    @staticmethod
    def get_biz_by_user(user):
        all_biz = BizUtils.get_all_biz_list()
        # 获取用户的业务权限
        if user.is_super:
            return all_biz
        return [biz for biz in all_biz if biz.get("bk_biz_id", 0) in user.biz_ids]

    @classmethod
    def get_user_biz(cls, username):
        """
        获取用户下的角色的全部业务
        """
        sys_user = SysUser.objects.filter(bk_username=username).first()
        if not sys_user:
            return {"result": False, "message": "此用户不存在！"}

        roles = sys_user.roles.all()
        super_group = roles.filter(role_name=DB_SUPER_USER).exists()
        if super_group:
            # all_biz_list = BizUtils.get_all_biz_list()
            biz_list = BizUtils.get_all_biz_list()
        else:
            biz_set = set()
            for role in roles:
                apps = role.sysapps_set.all()
                role_biz = {j for i in apps if i.app_key == DB_APPS for j in i.app_ids}
                biz_set.update(role_biz)

            all_biz_list = BizUtils.get_all_biz_list()
            biz_mapping = {i["bk_biz_id"]: i["bk_biz_name"] for i in all_biz_list}
            biz_list = [{"bk_biz_id": i, "bk_biz_name": biz_mapping[i]} for i in biz_set]

        return {"result": True, "data": biz_list}


class UserUtils(object):
    @staticmethod
    @catch_exception
    @transaction.atomic
    def init_sys_role(**kwargs):
        """
        初始化超管和普通用户
        """
        logger.info("开始初始化超管和普通用户")

        for init_data in init_templates:
            obj, created = SysRole.activate_manage.get_or_create(role_name=init_data["role_name"], defaults=init_data)
            if init_data["role_name"] == DB_SUPER_USER:
                # 先初始化admin, 再去同步用户管理时, 查询看看是否存在admin
                # 若用户管理存在admin，则修改本地admin
                # 若不存在admin，则同步到远端到用户管理
                client = get_client_by_user("admin")
                params = {
                    "id": "admin",
                    "lookup_field": "username",
                    "fields": "email,telephone",
                }

                retrieve_user_data = BKUserApiCCUtils.retrieve_user(client, **params)
                init_user_data = {
                    "bk_username": "admin",
                    "chname": "admin",
                    "phone": retrieve_user_data["telephone"],
                    "email": retrieve_user_data["email"],
                }
                user_obj, _ = SysUser.objects.get_or_create(bk_username="admin", defaults=init_user_data)
                user_obj.roles.add(obj)
                user_apps_obj = SysApps.objects.filter(app_key=DB_APPS, sys_role=obj).first()
                if user_apps_obj is None:
                    apps_dict = {
                        "app_name": DB_APPS_DISPLAY_NAME,
                        "app_key": DB_APPS,
                        "sys_role": obj,
                        "app_ids": [i["bk_biz_id"] for i in BizUtils.get_all_biz_list()],
                    }
                    SysApps.objects.create(**apps_dict)

        logger.info("初始化角色完成")

    @staticmethod
    def init_bk_iam_role(**kwargs):
        # 把超管组的用户 加入到权限中心
        role_users = SysUser.objects.filter(roles__role_name=DB_SUPER_USER).values_list("bk_username", flat=True)
        for bk_username in role_users:
            try:
                role_permission = RolePermissionUtil(username=bk_username)
                role_permission.add_main()
            except Exception as err:
                logger.error("部署时初始化用户到权限中心超管角色失败: bk_username={}, error={}".format(bk_username, err))

    @staticmethod
    @catch_exception
    @transaction.atomic
    def pull_sys_user(**kwargs):
        """拉取系统用户"""
        logger.info("开始同步用户")

        client = get_client_by_user("admin")
        try:
            page_size = constants.BK_USER_MAX_PAGE_SIZE
            count, users = BKUserApiCCUtils.list_users(
                client,
                page_size=page_size,
                fields="id,username,display_name,email,telephone,wx_userid,domain,departments,leader,status",
            )
            page = count // page_size if count % page_size == 0 else count // page_size + 1
            for current_page in range(2, page + 1):
                users.extend(
                    BKUserApiCCUtils.list_users(
                        client,
                        page_size=page_size,
                        page=current_page,
                        fields="id,username,display_name,email,telephone,wx_userid,domain,departments,leader,status",
                    )[1]
                )
            logger.info(f"[拉取蓝鲸用户管理的用户] 总人数:{count},总页数:{page}")
        except exceptions.GetDateError as e:
            logger.error(f"[拉取蓝鲸用户管理的用户] 失败 {e.MESSAGE}")
            return False

        db_sys_user = SysUser.objects.all()
        db_sys_user_mapping = {user.bk_username: user for user in db_sys_user}
        sys_user_list = db_sys_user_mapping.keys()

        # 取用户管理的用户名集合
        users_set = {i["username"] for i in users}  # 拉去用户
        # 取weops用户表的用户名集合
        sys_users_set = set(sys_user_list)
        # 用户管理中不存在的用户名集合，删除
        del_set = sys_users_set - users_set
        logger.info(f"[拉取蓝鲸用户管理的用户] 删除的用户:{del_set}")
        SysUser.objects.filter(bk_username__in=del_set).delete()

        all_biz_list = BizUtils.get_all_biz_list()  # 获取业务权限id全部列表
        all_biz_ids = [i["bk_biz_id"] for i in all_biz_list]
        exist_sysusers = []
        add_sysusers = []
        add_sysusers_log = []
        fields = ["bk_user_id", "phone", "email", "chname", "wx_userid", "local", "departments", "leader", "status"]
        normal_role = SysRole.objects.get(role_name=DB_NORMAL_USER)  # 普通角色
        super_role = SysRole.objects.get(role_name=DB_SUPER_USER)  # 超管角色
        for user_info in users:
            username = user_info.get("username")
            if not username:
                logger.warning("[拉取蓝鲸用户管理的用户] 用户无用户名!user_info={}".format(user_info))
                continue

            wx_user_id = user_info.get("wx_userid", "")
            domain = user_info.pop("domain", DOMAIN)
            local = domain == DOMAIN
            user_dict = dict(
                bk_user_id=user_info.get("id"),
                phone=user_info.get("telephone", ""),
                email=user_info.get("email", ""),
                chname=user_info.get("display_name", ""),
                departments=user_info.get("departments", []),
                leader=user_info.get("leader", []),
                status=user_info.get("status", SysUser.NORMAL),
                # sexuality=SEX_MAPPING.get(user_info.get("display_name", ""), SysUser.MAN),
                wx_userid=wx_user_id,
                local=local,
            )

            # 查看sysuser是否拥有,没有则添加进未创建列表
            if username not in sys_user_list:
                user_dict["bk_username"] = username
                if username in constants.ADMIN_USERNAME_LIST:
                    sys_user = SysUser.objects.create(**user_dict)
                    sys_user.roles.add(super_role)
                else:
                    user_obj = SysUser(**user_dict)
                    add_sysusers.append(user_obj)
                    add_sysusers_log.append(username)
            else:
                user = db_sys_user_mapping.get(username, None)
                if not user:
                    continue
                for k, v in user_dict.items():
                    setattr(user, k, v)

                exist_sysusers.append(user)

        # 为新增对用户设置普通用户的角色
        logger.info(f"[拉取蓝鲸用户管理的用户] 新增的用户:{add_sysusers_log}")
        user_objs = SysUser.objects.bulk_create(add_sysusers, batch_size=100)
        add_users = SysUser.objects.filter(bk_user_id__in=[i.bk_user_id for i in user_objs])
        normal_role.sysuser_set.add(*add_users)

        # 批量创更新sys_user的用户
        SysUser.objects.bulk_update(exist_sysusers, fields=fields, batch_size=100)

        # 批量修改没有角色的用户为普通角色
        not_role_user = SysUser.objects.filter(roles=None)
        if not_role_user.exists():
            normal_role.sysuser_set.add(*not_role_user)

        # 批量修改超管的业务权限为最新
        super_role.sysapps_set.filter(app_key=DB_APPS).update(app_ids=all_biz_ids)

        # 更新其余角色(非超管)的业务为最新的业务
        for sysuser in SysApps.objects.exclude(sys_role=super_role).filter(app_key=DB_APPS):
            sysuser.app_ids = sorted(list(set(sysuser.app_ids) & set(all_biz_ids)))
            sysuser.save()

        # casbin_mesh 新增用户
        if add_sysusers_log:
            from apps.system_mgmt.celery_tasks import sync_casbin_mesh_add_policies

            transaction.on_commit(
                lambda: sync_casbin_mesh_add_policies.delay(
                    sec="g", ptype="g", rules=[[name, DB_NORMAL_USER] for name in add_sysusers_log]
                )
            )

        logger.info("同步用户结束")
        return True


@time_consuming
@catch_exception
def post_migrate_init(**kwargs):
    """
    数据库迁移时，初始化顺序 前后有依赖
    """
    init_menu()  # 初始化菜单
    UserUtils.init_sys_role()  # 初始化超管和普通用户
    UserUtils.pull_sys_user()  # 同步用户
    UserUtils.init_bk_iam_role()  # 把超管组的用户 加入到权限中心
    CasbinUtils.init_operate_ids()  # v3.9 初始化页面权限到操作权限
    CasbinUtils.menu_operator()  # 页面变化操作


    CasbinUtils.casbin_change_workflow()
    CasBinInstUtils.casbin_inst_workflow()

    # 旧数据同步到casbin mesh
    InstPermissionsInitData().main()

    from apps.system_mgmt.sys_setting import sys_setting

    sys_setting.init_config()
    sys_setting.init_verify_json()


def get_user_biz_list(request):
    if not request.user.is_super:
        # 非超管 只返回此角色拥有的业务
        user_biz_list = getattr(request.user, "biz_ids", [])
        if not user_biz_list:
            return []

        biz_info = BkApiCCUtils.search_business_biz_list(user_biz_list)
    else:
        biz_info = BizUtils.get_all_biz_list()

    return biz_info


def create_log(operator, current_ip, app_module, obj_type, operate_obj, operate_type, summary_detail):
    """记录操作类API日志"""
    OperationLog.objects.create(
        operator=operator,
        current_ip=current_ip,
        app_module=app_module,
        obj_type=obj_type,
        operate_obj=operate_obj,
        operate_type=operate_type,
        operate_summary=summary_detail,
    )


def batch_create_log(log_list):
    """记录操作类API日志"""
    operation_log_objs = [
        OperationLog(
            operator=i["operator"],
            current_ip=i["current_ip"],
            app_module=i["app_module"],
            obj_type=i["obj_type"],
            operate_obj=i["operate_obj"],
            operate_type=i["operate_type"],
            operate_summary=i["operate_summary"],
        )
        for i in log_list
    ]
    OperationLog.objects.bulk_create(operation_log_objs, batch_size=100)


@catch_exception
def init_menu():
    """
    初始化默认的菜单
    """
    _, created = MenuManage.objects.get_or_create(menu_name=MENU_DATA["menu_name"], defaults=MENU_DATA)
    logger.info("初始化默认菜单完成. create={}".format(created))


class InstPermissionsInitData(object):
    """
    实例权限
    旧数据同步到casbin mesh
    """

    @staticmethod
    def get_user_roles():
        result = {}
        exclude_roles = [DB_SUPER_USER, DB_NOT_ACTIVATION_ROLE]
        sys_users = SysUser.objects.exclude(bk_username="admin").prefetch_related("roles")
        for user in sys_users:
            role_list = [role.role_name for role in user.roles.all() if role.role_name not in exclude_roles]
            result[user.bk_username] = role_list
        return result

    @classmethod
    def models(cls):
        inst_models = {}
        apps = {"apps": os.listdir("apps"), "apps_other": os.listdir("apps_other")}
        for app_group, app_list in apps.items():
            for app_name in app_list:
                if app_name in ["__pycache__", "system_mgmt", "__init__.py"]:
                    continue
                app_path = f"{app_group}.{app_name}.inst_permission_conf"
                try:
                    module = importlib.import_module(app_path)
                except ModuleNotFoundError:
                    continue

                for _class in module.__dict__.values():
                    if not isinstance(_class, type):
                        continue
                    if not _class.__name__.endswith("InstPermissions"):
                        continue
                    for model_map in _class.search_inst_list:
                        inst_models.update(model_map)

        return inst_models

    @classmethod
    def get_models_policies(cls):
        policies = []
        user_roles_dict = cls.get_user_roles()
        for model_dict in cls.models():
            for instance_type, model in model_dict.items():
                if isfunction(model):
                    instances = model()
                else:
                    instances = model.objects.all().values("id", "created_by")
                for instance in instances:
                    operation = "use" if instance_type == "运维工具" else "view"
                    roles = user_roles_dict.get(instance["created_by"], [])
                    for role_name in roles:
                        policies.append([role_name, instance_type, operation, str(instance["id"]), "0"])
                        policies.append([role_name, instance_type, "manage", str(instance["id"]), "0"])

        return policies

    # @staticmethod
    # def get_monitor_policy():
    #     """
    #     监控策略
    #     """
    #     sql_client = MonitorSQLClient()
    #     sql = "SELECT id,created_by from home_application_monitorstrategy where is_deleted=0;"
    #     data = sql_client.execute_mysql_sql(sql)
    #     return data

    # @staticmethod
    # def get_precess():
    #     """
    #     进程采集
    #     """
    #     sql_client = MonitorSQLClient()
    #     sql = "SELECT id,created_by from home_application_collectprocesstask where is_deleted=0;"
    #     data = sql_client.execute_mysql_sql(sql)
    #     return data

    # @staticmethod
    # def get_monitors():
    #     """
    #     监控任务
    #     """
    #     sql_client = MonitorSQLClient()
    #     sql = "SELECT id,created_by from home_application_collectplugintask where is_deleted=0;"
    #     data = sql_client.execute_mysql_sql(sql)
    #     return data

    # @staticmethod
    # def get_log_monitor_policy():
    #     """
    #     查询log的监控策略任务
    #     """
    #     instances = AlarmStrategy.objects.all().values("event_definition_id", "created_by")
    #     return [{"id": instance["event_definition_id"], "created_by": instance["created_by"]} for instance in instances]

    @classmethod
    def main(cls):
        try:
            policies = cls.get_models_policies()
            split_policies = split_list(policies, 500)
            delete_policy = CasBinInstService.remove_filter_policies(
                sec="p", ptype="p", field_index=4, field_values="0"
            )
            if not delete_policy:
                logger.warning("清除casbin mesh旧数据失败！")

            for split_policy in split_policies:
                result = CasBinInstService.create_policies(split_policy, "p", "p")
                logger.info("同步旧数据到casbin mesh. result={}".format(result))
        except Exception as err:
            logger.warning("初始化实例权限数据到casbin失败！error={}".format(err))

def init_keycloak(**kwargs):
    """
    初始化keycloak
    """
    settings = LazySettings()
    keycloak_admin = KeycloakAdmin(
        server_url=f'http://{settings.KEYCLOAK_SETTINGS["HOST"]}:{settings.KEYCLOAK_SETTINGS["PORT"]}/',
        username=settings.KEYCLOAK_SETTINGS["ADMIN_USERNAME"],
        password=settings.KEYCLOAK_SETTINGS["ADMIN_PASSWORD"],
        realm_name='master',
        client_id="admin-cli")
    # 读realm配置文件
    realm_config_file_path = os.path.join(settings.BASE_DIR, 'config', 'realm-export-weops.json')
    with open(realm_config_file_path, 'r', encoding='utf8') as realm_config_file:
        realm_config = json.load(realm_config_file)
    if realm_config['realm'] != settings.KEYCLOAK_SETTINGS["REALM_NAME"]:
        raise ValueError(f'keycloak initialization error: realm name in file {realm_config_file_path} should '
                         f'be the same in settings')
    # 如果不存在则创建realm
    realms = keycloak_admin.get_realms()
    realm_exist = False
    for realm in realms:
        if realm['realm'] == realm_config['realm']:
            realm_exist = True
            break
    if not realm_exist:
        keycloak_admin.create_realm(payload=realm_config, skip_exists=True)
    # 登录新域账号创建两个用户，并分配角色
    keycloak_admin = KeycloakAdmin(
        server_url=f'http://{settings.KEYCLOAK_SETTINGS["HOST"]}:{settings.KEYCLOAK_SETTINGS["PORT"]}/',
        username=settings.KEYCLOAK_SETTINGS["ADMIN_USERNAME"],
        password=settings.KEYCLOAK_SETTINGS["ADMIN_PASSWORD"],
        realm_name=settings.KEYCLOAK_SETTINGS["REALM_NAME"],
        client_id="admin-cli",
        user_realm_name="master")

    #动态获取client配置
    clients = keycloak_admin.get_clients()
    for client in clients:
        if client['clientId'] == settings.KEYCLOAK_SETTINGS["CLIENT_ID"]:
            settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"] = client['id']
            settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"] = client['secret']
    # 创建admin用户和普通用户
    admin_role = keycloak_admin.get_client_role(settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"], 'admin')
    admin_user = {
        'username': 'admin',
        'credentials': [{"value": 'admin', "type": 'password', }],
        'email': 'admin@kc.com',
        'lastName': '管理员',
        'enabled': True
    }
    admin_id = keycloak_admin.create_user(admin_user, exist_ok=True)
    keycloak_admin.assign_client_role(admin_id, settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"], admin_role)

    normal_role = keycloak_admin.get_client_role(settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"], 'normal')
    normal_user = {
        'username': 'normal_user',
        'credentials': [{"value": 'normal_user', "type": 'password', }],
        'email': 'normal@kc.com',
        'lastName': '普通用户',
        'enabled': True
    }
    normal_id = keycloak_admin.create_user(normal_user, exist_ok=True)
    keycloak_admin.assign_client_role(normal_id, settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"], normal_role)
