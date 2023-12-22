import json
import os

from django.conf import LazySettings
from keycloak import KeycloakAdmin

from apps.system_mgmt.models import OperationLog


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
