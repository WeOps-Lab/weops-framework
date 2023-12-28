from django.conf import LazySettings
from django.shortcuts import redirect
from django.http import request
from django.urls import reverse
from keycloak import KeycloakOpenID

from apps.system_mgmt.utils_package.keycloak_utils import KeycloakUtils


class KeycloakMiddleware:
    _keycloak_utils = None

    @classmethod
    def keycloak_utils(cls):
        if cls._keycloak_utils is None:
            cls._keycloak_utils = KeycloakUtils()
        return cls._keycloak_utils
    _settings = LazySettings()

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: request.HttpRequest):
        # 检查是否需要登录的视图
        if not self._is_public_url(request.path_info) and not self._is_authenticated(request):
            # 重定向到 Keycloak 登录页 redirect_uri 填获取根据code获取token的接口
            return redirect(
                f'http://{request.get_host().split(":")[0]}:{self._settings.KEYCLOAK_SETTINGS["PORT"]}/realms/{self._settings.KEYCLOAK_SETTINGS["REALM_NAME"]}'
                #             f'http://dev.weops.com:8081/realms/{self._settings.KEYCLOAK_SETTINGS["REALM_NAME"]}'
                            f'/protocol/openid-connect/auth'
                            f'?client_id={self._settings.KEYCLOAK_SETTINGS["CLIENT_ID"]}'
                            f'&response_type=code'
                            f'&scope=openid'
                            f'&redirect_uri={request.build_absolute_uri(reverse("keycloak_code_login"))}'
                            # f'&redirect_uri=http://dev.weops.com:8081{reverse("keycloak_code_login")}'
            )

        response = self.get_response(request)
        return response

    def _is_authenticated(self, request: request.HttpRequest):
        # 检查用户是否已经通过 Keycloak 登录
        token = request.COOKIES.get('token', None)
        if token is None:
            return False
        tokeninfo = self.keycloak_utils().get_keycloak_openid().introspect(token)
        if not tokeninfo.get('active', False):
            print(f'invalid token from middleware: {token}')
            return False
        return True

    def _is_public_url(self, path_info):
        # 检查是否是公开的URL，不需要登录的URL
        public_urls = [reverse("keycloak_login"), reverse("keycloak_code_login")]
        return any(path_info.startswith(url) for url in public_urls)
