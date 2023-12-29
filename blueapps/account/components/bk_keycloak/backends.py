import logging

# UserModel是 blueapps.account.models.User
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

import settings
import requests
logger = logging.getLogger("component")

ROLE_TYPE_ADMIN = "1"


class KeycloakBackend(ModelBackend):
    '''
    无论是哪一种方式，authenticate()``都应该检查所获得的凭证，并当凭证有效时返回一个用户对象。当凭证无效时，应该返回``None
    不用该方法，随便返回
    '''
    def authenticate(self, request, username=None, password=None, bk_token=None):

        return get_user_model()

    def authenticate_with_bk_token(self, bk_token):
        # 在此处实现验证 bk_token 的逻辑，您需要使用 bk_token 与 Keycloak 交互并验证用户
        # 如果验证成功，返回包含用户数据的字典；否则返回 None
        # 例如，您可以使用 requests 库来向 Keycloak 发送验证请求
        # 示例验证逻辑：

        keycloak_server = settings.KEYCLOAK_SERVER
        keycloak_port = settings.KEYCLOAK_PORT
        keycloak_url = f"http://{keycloak_server}:{keycloak_port}/admin/realms/master/users"
        headers = {'Authorization': f'Bearer {bk_token}'}

        response = requests.get(keycloak_url, headers=headers)

        if response.status_code == 200:
            user_data = response.json()
            return user_data

        return None
