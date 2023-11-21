from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.contrib import auth
from django.core.handlers.wsgi import WSGIRequest
from django.urls import resolve

try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    MiddlewareMixin = object


class KeycloakMiddleware(MiddlewareMixin):
    '''
    拦截器？？
    '''

    def process_view(self, request : WSGIRequest, view, args, kwargs):
        # 验证当前用户是否登录
        # if not request.user.is_authenticated:
        #     request.session['next_url'] = request.get_full_path()
        #     bk_token = request.COOKIES.get('bk_token', None)
        #     # 此处丢给后端进行验证，如果后端验证有效，则返回一个 :class:`~django.contrib.auth.models.User 对象。如果后端引发 PermissionDenied 错误，将返回 None
        #     user = auth.authenticate(request=request, bk_token=bk_token)
        #     if user is not None:
        #         # 验证通过，加入session
        #         auth.login(request, user)
        pass

    def process_response(self, request, response):
        return response
