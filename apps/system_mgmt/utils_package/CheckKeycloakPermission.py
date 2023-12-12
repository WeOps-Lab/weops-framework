from functools import wraps
from rest_framework.response import Response
from rest_framework import status
from apps.system_mgmt.utils_package.controller import KeycloakPermissionController
from apps.system_mgmt.utils_package.keycloak_utils import KeycloakUtils
import inspect


def check_keycloak_permission(permission_name, check_user_itself: bool = True):
    '''
    permission_name:权限名
    check_user_itself:用户本人是否可以绕过权限检查，如果该参数为False,可以绕过权限检查,通过检查函数的pk参数实现
    检查权限的装饰器，写在被请求的方法上
    '''

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            if not check_user_itself:
                # 获取函数的参数信息
                signature = inspect.signature(view_func)
                parameters = signature.parameters
                args_dict = dict(zip(parameters, args))
                args_dict.update(kwargs)
                if 'pk' not in args_dict:
                    raise ValueError('function parameter "pk" should appear with check_user_itself=False in the same time!')
                # 参数中的主键
                pk = args_dict['pk']
                keycloak_util = KeycloakUtils()
                KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_util.get_keycloak_openid().public_key() + "\n-----END PUBLIC KEY-----"
                options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}
                token_info = keycloak_util.get_keycloak_openid().decode_token(request.auth, key=KEYCLOAK_PUBLIC_KEY,
                                                          options=options)
                if pk != token_info['sub']:
                    return Response({'error': f'Not user itself'},
                                    status=status.HTTP_403_FORBIDDEN)
            else:
                token = request.auth
                if not KeycloakPermissionController.has_permissions(token, permission_name):
                    return Response({'error': f'Permission denied by {permission_name}'}, status=status.HTTP_403_FORBIDDEN)
            return view_func(self, request, *args, **kwargs)

        return wrapper

    return decorator
