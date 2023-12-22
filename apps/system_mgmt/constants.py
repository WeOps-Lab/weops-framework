# 系统默认Logo路径
import base64
import copy
import os

from django.conf import settings

from utils.common_models import VtypeMixin

USER_CACHE_KEY = "USER_BK_USERNAME_CHNAME"

checkAuth = "checkAuth"  # 查看
operateAuth = "operateAuth"  # 操作

# 查看
QUERY = "query"

# 操作
CREATE = "create"
MODIFY = "modify"
DELETE = "delete"
UPLOAD = "upload"
DOWNLOAD = "download"
RESET = "reset"
EXEC = "exec"
COLLECT = "collect"
IMPORT = "import"
LONG_DISTANCE = "long_distance"
OUTPUT = "output"


DEFAULT_LOGO_PATH = os.path.join(settings.BASE_DIR, "static/img/default-logo.png")
# 系统设置表中提前置入的设置项
with open(DEFAULT_LOGO_PATH, "rb") as logo_file:
    SYSTEM_LOGO_INFO = {
        "key": "system_logo",
        "value": base64.b64encode(logo_file.read()).decode("utf8"),
        "vtype": VtypeMixin.STRING,
        "desc": "系统默认Logo",
    }

"""
用户 角色的常量
"""
# 角色
DB_NORMAL_USER = "normal_group"
DB_NORMAL_USER_DISPLAY_NAME = "普通用户"

DB_SUPER_USER = "admin_group"
DB_SUPER_USER_DISPLAY_NAME = "超级管理员"

DB_NOT_ACTIVATION_ROLE = "not_activation"
DB_NOT_ACTIVATION_ROLE_DISPLAY_NAME = "未激活角色"


# 可选的app的path
MENUS_CHOOSE_MAPPING = {
    # 健康扫描
    "health_advisor": ["health_advisor/resource", "health_advisor/scan_package", "health_advisor/scan_task"],
    # 监控告警
    "monitor_mgmt": [
        "monitor_mgmt/monitor",
        "monitor_mgmt/uac",
        "monitor_mgmt/cloud",
        "monitor_mgmt/dashboard",
        "monitor_mgmt/metric_view",
        "monitor_mgmt/metric_group",
        "monitor_mgmt/metric_obj",
        "monitor_mgmt/k8s_collect",
        "monitor_mgmt/monitor_collect",
        "monitor_mgmt/network_collect",
        "monitor_mgmt/network_classification",
        "monitor_mgmt/cloud_monitor_task",
        "monitor_mgmt/hardware_monitor_task",
    ],
    # 运维工具
    "operational_tools": [
        "operational_tools/tools",
        "operational_tools/tools_manage",
        "operational_tools/network_tool/template",
        "operational_tools/network_tool/template_march",
    ],
    # 知识库
    "repository": ["repository", "repository/labels", "repository/templates"],
    # 大屏
    "big_screen": ["big_screen", "big_screen/v2"],
    # 资产（进阶）
    "senior_resource": ["senior_resource/v2/obj", "senior_resource/subscribe"],
    # 补丁管理
    "patch_mgmt": ["patch_mgmt/patchtask", "patch_mgmt/patchfile"],
    # 自动化编排
    "auto_process": [],
    # 日志
    "syslog": ["syslog", "syslog/probe", "syslog/collectors_config"],
    # 拓扑图
    "custom_topology": ["custom_topology"],
}

#  默认页面权限
MENUS_DEFAULT = {
    "index": ["index"],  # 首页
    "big_screen": ["big_screen"],  # 数据大屏
    "system_manage": [
        "system/mgmt/sys_users",
        "system/mgmt/operation_log",
        "system/mgmt/user_manage",
        "system/mgmt/role_manage",
        "system/mgmt/sys_setting",
    ],  # 系统管理
    "resource": [
        "resource/v2/host/inst",
        "resource/v2/profile",
        "resource",
        "resource/v2/service_instance",
        "resource/v2/biz/inst",
        "resource/v2/other_obj",
        "resource/v2/obj",
        "resource/objects",
    ],  # 资源记录
}

# 菜单管理常量
MENU_DATA = {
    "menu_name": "默认菜单",
    "default": True,
    "use": True,
    "menu": list,
    "created_by": "admin",
    "updated_by": "admin",
}

