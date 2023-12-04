from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from django.core.handlers.wsgi import WSGIRequest
from keycloak import KeycloakOpenID
from django.conf import LazySettings
from django.contrib.auth import get_user_model

from apps.system_mgmt.models import SysUser
from apps.system_mgmt.utils_package.keycloak_utils import KeycloakUtils
from apps.system_mgmt.utils_package.controller import KeycloakUserController
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

settings = LazySettings()


class KeycloakTokenAuthentication(BaseAuthentication):

    def __init__(self):
        self.__keycloak_util = KeycloakUtils()

    def authenticate(self, request: WSGIRequest):
        '''
        该函数返回的信息会被塞到request的属性user和auth中
        '''
        auth_header : str = request.headers.get('Authorization', None)
        if not auth_header:
            raise AuthenticationFailed('Authorization header needed')
        header_seps = auth_header.split(' ')
        if len(header_seps) != 2:
            raise AuthenticationFailed('Authorization header format error')
        token = header_seps[1]
        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token: str):
        tokeninfo = KeycloakUserController.keycloak_utils.get_keycloak_openid().introspect(token)
        if not tokeninfo.get('active', False):
            raise AuthenticationFailed('Token exp or invalid')
        # 根据token找对应的user
        user_id = tokeninfo['sub']
        user = KeycloakUserController.get_user_by_id(user_id)
        return user, token
