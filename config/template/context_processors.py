# -*- coding: utf-8 -*-

from django.conf import settings

from apps.system_mgmt.common_utils.bk_api_utils.main import SiteConfig


def custom_settings(request):
    """
    :summary: 这里可以返回前端需要的公共变量
    :param request:
    :return:
    """
    context = {
        "CSRF_COOKIE_NAME": settings.CSRF_COOKIE_NAME,
        # cmdb 访问地址
        "CMDB_HREF": settings.CMDB_URL,
        # JOB 访问地址
        "JOB_HREF": settings.JOB_URL,
        # weops app code
        "WEOPS_APP_CODE": SiteConfig.WEOPS,
        # 统一告警中心 app code
        "UAC_APP_CODE": SiteConfig.UAC,
        # 统一监控中心 app code
        "MONITOR_APP_CODE": SiteConfig.MONITOR,
        # 流程管理 app code
        "FLOW_APP_CODE": SiteConfig.FLOW,
        # 一键补丁安装 app code
        "PATCH_APP_CODE": SiteConfig.PATCH,
        # 数字运营中心 app code
        "OPS_APP_CODE": SiteConfig.OPS,
        # weops微信端事件匹配名
        "WX_ENVENT_NAME": settings.WX_ENVENT_NAME,
        # 控制台绑定微信的类型(wx微信,qywx企业微信)
        "CONSOLE_BIND_WX_TYPE": settings.CONSOLE_BIND_WX_TYPE,
        # 当前环境变量（o/t）
        "CURRENT_ENV": f"/{settings.CURRENT_ENV}",
        "IS_3D_SCREEN": settings.IS_3D_SCREEN,
        "BK_PAAS_HOST": settings.BK_PAAS_HOST,
        "OPSPLIOT_URL": settings.OPSPLIOT_URL,
        "OPSPLIOT_SOCKET_PATH": settings.OPSPLIOT_SOCKET_PATH,
        "OPSPLIOT_JS_URL": settings.OPSPLIOT_JS_URL,
    }
    return context