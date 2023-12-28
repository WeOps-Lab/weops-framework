from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from django.core.handlers.wsgi import WSGIRequest
from django.conf import LazySettings
from apps.system_mgmt.utils_package.keycloak_utils import KeycloakUtils
from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied

settings = LazySettings()

"""
存放Keycloak身份验证和权限验证的组件
"""


class KeycloakTokenAuthentication(BaseAuthentication):
    """
    认证Keycloak token
    """

    def __init__(self):
        self.__keycloak_util = KeycloakUtils()

    def authenticate(self, request: WSGIRequest):
        '''
        该函数返回的信息会被塞到request的属性user和auth中
        '''
        token: str = request.COOKIES.get('token', None)
        if not token:
            raise AuthenticationFailed('token cookie is needed')
        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token: str):
        tokeninfo = self.__keycloak_util.get_keycloak_openid().introspect(token)
        if not tokeninfo.get('active', False):
            raise AuthenticationFailed('Token exp or invalid')
        user = self.__keycloak_util.get_user_detail(tokeninfo['sub'])
        user['resource_access'] = tokeninfo['resource_access']
        user_obj = User(user['username'], True, user)
        return user_obj, token


class KeycloakIsAuthenticated(BasePermission):
    """
    权限验证，认证了就可以通过
    """
    message = 'Authentication failed.'

    def has_permission(self, request, view):
        # 如果认证失败，抛出 PermissionDenied 异常
        if request.user is None:
            raise PermissionDenied(self.message)
        # 认证成功
        return True


class User:
    def __init__(self, username, is_authenticated, data):
        self.username = username
        self.is_authenticated = is_authenticated
        self.data = data

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)
