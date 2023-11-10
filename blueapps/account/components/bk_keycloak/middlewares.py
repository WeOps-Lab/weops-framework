from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.contrib import auth
try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    MiddlewareMixin = object


class KeycloakMiddleware(MiddlewareMixin):
    def process_view(self, request, view, args, kwargs):
        # #验证当前用户是否登录
        if not request.user.is_authenticated:
            request.session['next_url'] = request.get_full_path()
            bk_token = request.COOKIES.get('bk_token', None)
            user = auth.authenticate(request=request,bk_token = bk_token)
            if user is not None:
                auth.login(request, user)

        return None

    def process_response(self, request, response):
        return response