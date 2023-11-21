from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied


class KeycloakIsAuthenticated(BasePermission):
    message = 'Authentication failed.'

    def has_permission(self, request, view):
        # 在这里进行 KeycloakTokenAuthentication 的认证逻辑

        # 如果认证失败，抛出 PermissionDenied 异常
        if request.user is None:
            raise PermissionDenied(self.message)

        # 认证成功
        return True
