from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from django.core.handlers.wsgi import WSGIRequest
from keycloak import KeycloakOpenID
from django.conf import LazySettings
from django.contrib.auth import get_user_model
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

settings = LazySettings()


class KeycloakTokenAuthentication(BaseAuthentication):

    keycloak_openid = KeycloakOpenID(
        server_url=f'http://{settings.KEYCLOAK_SETTINGS["KEYCLOAK_SERVER"]}:{settings.KEYCLOAK_SETTINGS["KEYCLOAK_PORT"]}/',
        client_id=f'{settings.KEYCLOAK_SETTINGS["CLIENT_ID"]}',
        realm_name=f'{settings.KEYCLOAK_SETTINGS["REALM_NAME"]}',
        client_secret_key=f'{settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"]}')


    def authenticate(self, request: WSGIRequest):
        '''
        该函数返回的信息会被塞到request的属性user和auth中
        '''
        token = request.COOKIES.get("token", None)
        if not token:
            return None, None
        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token: str):
        tokeninfo = self.keycloak_openid.introspect(token)
        if not tokeninfo.get('active', False):
            raise AuthenticationFailed('Invalid token')
        user = get_user_model()()
        return user, token