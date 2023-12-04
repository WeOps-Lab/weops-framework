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
        self.__settings = LazySettings()
        self.__keycloak_openid = KeycloakOpenID(
            server_url=f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/',
            client_id=f'{self.__settings.KEYCLOAK_SETTINGS["CLIENT_ID"]}',
            realm_name=f'{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}',
            client_secret_key=f'{self.__settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"]}')
        self.__keycloak_openid.load_authorization_config(self.__settings.KEYCLOAK_SETTINGS["AUTH_INFO_FILE_PATH"])
        self.__admin_token = None
        self.__keycloak_admin = None
        self.__refresh_keycloak_admin__()
    
    def __refresh_keycloak_admin__(self):
        '''
        更新keycloak_admin
        '''
        self.__admin_token = self.__keycloak_openid.token(self.__settings.KEYCLOAK_SETTINGS["ADMIN_USERNAME"],
                                                          self.__settings.KEYCLOAK_SETTINGS["ADMIN_PASSWORD"]).get('access_token', None)
        keycloak_connection = KeycloakOpenIDConnection(
            server_url=f'http://{self.__settings.KEYCLOAK_SETTINGS["HOST"]}:{self.__settings.KEYCLOAK_SETTINGS["PORT"]}/',
            realm_name=f'{self.__settings.KEYCLOAK_SETTINGS["REALM_NAME"]}',
            client_id=f'{self.__settings.KEYCLOAK_SETTINGS["CLIENT_ID"]}',
            client_secret_key=f'{self.__settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"]}',
            custom_headers={
                "Authorization": f"Bearer {self.__admin_token}"
            },
            verify=True)
        self.__keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

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
        try:
            if not self.__keycloak_openid.introspect(self.__admin_token).get('active', False):
                raise Exception('invalid admin token')
        except Exception as e:
            self.__refresh_keycloak_admin__()
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
            "Authoritarian": f"Bearer {self.__admin_token}"
        }
        response = requests.put(url, json=payload, headers=headers)
        if response.status_code / 100 == 2:
            return str({'code':response.status_code, 'msg':response.content})
        else:
            raise Exception(str({'code':response.status_code, 'msg':response.content}))

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
            "Authoritarian": f"Bearer {self.__admin_token}"
        }
        response = requests.get(url, headers=headers)
        if response.status_code / 100 == 2:
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
            "Authoritarian": f"Bearer {self.__admin_token}"
        }
        response = requests.get(url, headers=headers)
        if response.status_code / 100 == 2:
            return response.json()
        else:
            raise Exception(str({'code': response.status_code, 'msg': response.content}))