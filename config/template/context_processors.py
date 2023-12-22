# -*- coding: utf-8 -*-

from django.conf import settings


def custom_settings(request):
    """
    :summary: 这里可以返回前端需要的公共变量
    :param request:
    :return:
    """
    context = {
        "CSRF_COOKIE_NAME": settings.CSRF_COOKIE_NAME,
        # weops app code
        "WEOPS_APP_CODE": settings.APP_CODE,
        # 当前环境变量（o/t）
        "CURRENT_ENV": f"/{settings.CURRENT_ENV}",
        "IS_3D_SCREEN": settings.IS_3D_SCREEN,
        "BK_PAAS_HOST": settings.BK_PAAS_HOST,
    }
    return context
