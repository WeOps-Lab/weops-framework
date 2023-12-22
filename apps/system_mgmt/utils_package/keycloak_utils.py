import json
import tempfile
import os
import requests
from django.conf import LazySettings
from keycloak import KeycloakOpenID, KeycloakOpenIDConnection, KeycloakAdmin


class KeycloakUtils:
    '''
    单例模式，维护Keycloak管理员链接
    '''

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(KeycloakUtils, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.__get_client_settings__()
        self.__settings = LazySettings()
        self.__keycloak_admin = KeycloakAdmin(
            server_url=f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/',
            username=self.__settings.KEYCLOAK_SETTINGS["ADMIN_USERNAME"],
            password=self.__settings.KEYCLOAK_SETTINGS["ADMIN_PASSWORD"],
            realm_name=self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"],
            user_realm_name='master',
            client_id="admin-cli")
        self.__keycloak_openid = KeycloakOpenID(
            server_url=f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/',
            client_id=f'{self.__settings.KEYCLOAK_SETTINGS["CLIENT_ID"]}',
            realm_name=f'{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}',
            client_secret_key=f'{self.__settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"]}')
        # self.__keycloak_openid.load_authorization_config(self.__settings.KEYCLOAK_SETTINGS["AUTH_INFO_FILE_PATH"])
        self.__admin_token: str = self.__keycloak_admin.token['access_token']
        # self.__keycloak_admin: KeycloakAdmin = None
        # self.__refresh_keycloak_admin__()
        # 获取权限配置文件
        auth_json = self.__keycloak_admin.get_client_authz_settings(self.__settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"])
        # # 为没有applyPolicies的添加一个空列表，否则会报错
        # for p in auth_json['policies']:
        #     if p['config'].get('applyPolicies', None) is None:
        #         p['config']['applyPolicies'] = '[]'
        json_str = json.dumps(auth_json)
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            temp_file.write(json_str)
            temp_file_path = temp_file.name
        self.__keycloak_openid.load_authorization_config(temp_file_path)
        os.remove(temp_file_path)

    def __get_client_settings__(self):
        """
        获取客户端的ID和SECRET，写入settings配置内
        """
        settings = LazySettings()
        keycloak_admin = KeycloakAdmin(
            server_url=f'http://{settings.KEYCLOAK_SETTINGS["HOST"]}:{settings.KEYCLOAK_SETTINGS["PORT"]}/',
            username=settings.KEYCLOAK_SETTINGS["ADMIN_USERNAME"],
            password=settings.KEYCLOAK_SETTINGS["ADMIN_PASSWORD"],
            user_realm_name='master',
            realm_name=settings.KEYCLOAK_SETTINGS["REALM_NAME"],
            client_id="admin-cli")
        clients = keycloak_admin.get_clients()
        for client in clients:
            if client['clientId'] == settings.KEYCLOAK_SETTINGS["CLIENT_ID"]:
                settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"] = client['id']
                settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"] = client['secret']

    def __refresh_keycloak_admin__(self):
        '''
        更新keycloak_admin
        '''
        self.__admin_token = self.__keycloak_openid.token(self.__settings.KEYCLOAK_SETTINGS["ADMIN_USERNAME"],
                                                          self.__settings.KEYCLOAK_SETTINGS["ADMIN_PASSWORD"]).get(
            'access_token', None)
        keycloak_connection = KeycloakOpenIDConnection(
            server_url=f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/',
            realm_name=f'{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}',
            client_id=f'{self.__settings.KEYCLOAK_SETTINGS["CLIENT_ID"]}',
            user_realm_name='master',
            client_secret_key=f'{self.__settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"]}',
            custom_headers={
                "Authorization": f"Bearer {self.__admin_token}"
            },
            verify=True)
        self.__keycloak_admin: KeycloakAdmin = KeycloakAdmin(connection=keycloak_connection)

    def get_keycloak_openid(self) -> KeycloakOpenID:
        '''
        获取公开的keycloak操作
        '''
        return self.__keycloak_openid

    def get_keycloak_admin(self) -> KeycloakAdmin:
        '''
        获取keycloak_admin
        如果失效了重新获取
        '''
        # try:
        #     if not self.__keycloak_openid.introspect(self.__admin_token).get('active', False):
        #         raise Exception('invalid admin token')
        # except Exception as e:
        #     self.__refresh_keycloak_admin__()
        return self.__keycloak_admin

    def update_permission(self, permission_id: str, payload: dict):
        '''
        更新permission
        payload example
        {
          "id":"12c24a52-16bb-47d0-a645-a88988db4a6e",
          "name":"users_delete",
          "description":"删除用户",
          "type":"resource",
          "logic":"POSITIVE",
          "decisionStrategy":"AFFIRMATIVE",
          "resources":[
            "15f893a3-5c4a-417e-aab7-e5f74048f0cb"
          ],
          "policies":[
            "7ff8ec53-35e6-4756-a150-0877f4021ad4",
            "9b8721f4-2fb7-450e-aa7f-200e9a305876"
            ],
          "scopes":[]
        }
        '''
        url = f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/' \
              f'admin/realms/{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}/clients/{self.__settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"]}/' \
              f'authz/resource-server/permission/resource/{permission_id}'
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.__admin_token}"
        }
        response = requests.put(url, json=payload, headers=headers)
        if int(response.status_code / 100) == 2:
            return response.content
        else:
            raise Exception(str({'code': response.status_code, 'msg': response.content}))

    def get_resources_by_permission(self, permission_id: str):
        '''
        通过permission获取相关的resources
        response like
        [{"name":"users_create","_id":"a456585f-7f53-40f2-867f-f439f5f1a0d4"}]
        '''
        url = f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/' \
              f'admin/realms/{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}/clients/{self.__settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"]}/' \
              f'authz/resource-server/policy/{permission_id}/resources'
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.__admin_token}"
        }
        response = requests.get(url, headers=headers)
        if int(response.status_code / 100) == 2:
            return response.json()
        else:
            raise Exception(str({'code': response.status_code, 'msg': response.content}))

    def get_policy_by_permission(self, permission_id: str):
        '''
        policy
        response like
        [
            {
                "id": "7ff8ec53-35e6-4756-a150-0877f4021ad4",
                "name": "admin",
                "description": "",
                "type": "role",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "config": {}
            }
        ]
        '''
        url = f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/' \
              f'admin/realms/{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}/clients/{self.__settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"]}/' \
              f'authz/resource-server/policy/{permission_id}/associatedPolicies'
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.__admin_token}"
        }
        response = requests.get(url, headers=headers)
        if int(response.status_code / 100) == 2:
            return response.json()
        else:
            raise Exception(str({'code': response.status_code, 'msg': response.content}))

    def get_permission_by_policy(self, policy_id: str):
        '''
        response like
        [
            {
                "id": "8ecb9e5f-e692-46cc-b4ba-0053b59a8ecc",
                "name": "users_view",
                "type": "resource",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "config": {}
            },
            {
                "id": "ddf25fb9-f7e4-4671-a1a7-6ce1095fbf83",
                "name": "users_edit",
                "type": "resource",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "config": {}
            }
        ]
        '''
        url = f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/' \
              f'admin/realms/{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}/clients/{self.__settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"]}/' \
              f'authz/resource-server/policy/{policy_id}/dependentPolicies'
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.__admin_token}"
        }
        response = requests.get(url, headers=headers)
        if int(response.status_code / 100) == 2:
            return response.json()
        else:
            raise Exception(str({'code': response.status_code, 'msg': response.content}))

    def get_users_in_role(self, role_name: str, params: dict):
        '''
        获取某角色中的所有用户
        '''
        url = f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/' \
              f'admin/realms/{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}/clients/{self.__settings.KEYCLOAK_SETTINGS["ID_OF_CLIENT"]}/' \
              f'roles/{role_name}/users'
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.__admin_token}"
        }
        response = requests.get(url, headers=headers, params=params)
        if int(response.status_code / 100) == 2:
            return response.json()
        else:
            raise Exception(str({'code': response.status_code, 'msg': response.content}))

    def get_role_by_id(self, role_id: str):
        '''
        通过role id获取role
        response like
        {
            "id": "85efb45a-a866-43ab-892a-85a6836ab1a7",
            "name": "admin",
            "description": "",
            "composite": false,
            "clientRole": true,
            "containerId": "a72a5bed-8673-48e1-ac0a-97ba3c06c88f",
            "attributes": {}
        }
        '''
        url = f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/' \
              f'admin/realms/{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}/' \
              f'roles-by-id/{role_id}'
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.__admin_token}"
        }
        response = requests.get(url, headers=headers)
        if int(response.status_code / 100) == 2:
            return response.json()
        else:
            raise Exception(str({'code': response.status_code, 'msg': response.content}))

    def delete_client_role_by_id(self, role_id: str):
        url = f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/' \
              f'admin/realms/{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}/roles-by-id/{role_id}'
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.__admin_token}"
        }
        response = requests.delete(url, headers=headers)
        if int(response.status_code / 100) == 2:
            return response.content
        else:
            raise Exception(str({'code': response.status_code, 'msg': response.content}))

    def get_user_detail(self, user_id):
        url = f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/' \
              f'admin/realms/{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}/users/{user_id}'
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.__admin_token}"
        }
        response = requests.get(url, headers=headers, params={'userProfileMetadata': True})
        if int(response.status_code / 100) == 2:
            return response.json()
        else:
            raise Exception(str({'code': response.status_code, 'msg': response.content}))

    def refresh_token(self, refresh_token: str) -> (str, str):
        token = self.__keycloak_openid.refresh_token(refresh_token)
        return token.get('access_token', None), token.get('refresh_token', None)
