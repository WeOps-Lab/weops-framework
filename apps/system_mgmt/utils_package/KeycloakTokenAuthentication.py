from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from django.core.handlers.wsgi import WSGIRequest
from django.conf import LazySettings

from apps.system_mgmt.utils_package.keycloak_utils import KeycloakUtils


settings = LazySettings()


class KeycloakTokenAuthentication(BaseAuthentication):

    def __init__(self):
        self.__keycloak_util = KeycloakUtils()

    def authenticate(self, request: WSGIRequest):
        '''
        该函数返回的信息会被塞到request的属性user和auth中
        '''
        auth_header: str = request.headers.get('Authorization', None)
        if not auth_header:
            raise AuthenticationFailed('Authorization header needed')
        header_seps = auth_header.split(' ')
        if len(header_seps) != 2:
            raise AuthenticationFailed('Authorization header format error')
        token = header_seps[1]
        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token: str):
        tokeninfo = self.__keycloak_util.get_keycloak_openid().introspect(token)
        if not tokeninfo.get('active', False):
            raise AuthenticationFailed('Token exp or invalid')
        user = self.__keycloak_util.get_user_detail(tokeninfo['sub'])
        user['resource_access'] = tokeninfo['resource_access']
        user_obj = User(user['username'], True, user)
        return user_obj, token


class User:
    def __init__(self, username, is_authenticated, data):
        self.username = username
        self.is_authenticated = is_authenticated
        self.data = data

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)
