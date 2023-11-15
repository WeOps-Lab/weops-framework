# -- coding: utf-8 --

# @File : policy_constants.py
# @Time : 2023/3/2 11:21
# @Author : windyzhao

# -*- coding: utf-8 -*-

# @File    : policy_constants.py
# @Date    : 2022-07-01
# @Author  : windyzhao
from apps.system_mgmt.constants import CREATE, DELETE, MODIFY, QUERY, checkAuth, operateAuth

OPERATE_ENDSWITH = "Manage"
CONFIG_IDS = "configFile"

OPERATE_IDS_MAPPING = {
    "AssetRecordsHost": ["host", "serviceInstance", "configFile"],
}

# 内嵌通过
PASS_MENUS = {
    "AlarmManage",  # 告警管理
    "ServiceDeskManage",  # 服务台管理
    "NoticeWays",  # 通知渠道
    "CreditManage",  # 许可管理
    "Digital",  # 数据大屏
}

# 根据版本动态进行增加新版本的接口 每个版本都需要修改
POLICY_VERSION = "v4.1"

# 菜单操作 合并 拆分 新增 删除
MENU_OPERATOR = {
    "merge": {
        "v3.12": [("AutoManage", ["SysTool", "PackageManage"])],
        "v3.14": [("CloudMonitorVMware", ["VirtualMonitorVM", "VirtualMonitorESXI", "VirtualMonitorStorage"])],
    },
    "split": {
        "v3.12": [("MonitorManage", ["MonitorManage"])],
        "v3.16": [
            ("AutoManage", ["PackageManage", "OperationToolsManage", "AutoProcessManage", "WebEquipmentlManage"])
        ],
    },
    "add": {},
    "remove": {},
}
# 静态路由白名单
PASS_PATH = {
    ("/", "GET"),
    ("/mobile/", "GET"),
    ("/mobile/login/user/info/", "GET"),
    ("/admin/login/", "GET"),
    # 回调函数
    ("/operational_tools/job_call_back/", "POST"),
    ("/auto_mate/auto_mate_exec_ansible_call_back/", "POST"),
    ("/health/advisor/job_call_back/", "POST"),
    ("/open_api/user/get_user_role/", "GET"),
    ("/get_admins/", "GET"),
    ("/verify_user_auth/", "GET"),
    ("/get_application_overview/", "GET"),
    ("/create_remote_log/", "GET"),
    ("/get_biz_list/", "GET"),
    ("/system/mgmt/reset_policy_init/", "POST"),
    ("/system/mgmt/sys_users/", "GET"),
    ("/system/mgmt/user_manage/get_users/", "GET"),
    ("/login_info/", "GET"),
    ("/system/mgmt/logo/", "GET"),
    ("/system/mgmt/role_manage/menus/", "GET"),
    ("/system/mgmt/sys_users/bizs/", "GET"),
    ("/monitor_mgmt/monitor/get_monitor_all_tab/", "GET"),
    ("/monitor_mgmt/monitor/get_biz_list/", "GET"),
    ("/resource/v2/biz/inst/attributes/", "GET"),
    ("/resource/v2/biz/inst/attributes/", "PUT"),
    ("/resource/v2/host/inst/attributes/", "GET"),
    ("/resource/v2/host/inst/attributes/", "PUT"),
    ("/resource/v2/profile/get_object_association/", "GET"),
    ("/resource/v2/biz/inst/list_objects_relation/", "GET"),
    ("/resource/v2/biz/inst/biz_list/", "GET"),
    ("/system/mgmt/role_manage/get_all_roles/", "GET"),
    ("/node/management/meta/filter_conditiong/", "GET"),
    ("/node/management/cloud/", "GET"),
    ("/node/management/ap/", "GET"),
    ("/resource/v2/obj/asst/list/", "GET"),
    ("/resource/v2/obj/label/", "GET"),
    ("/resource/business/", "GET"),
    ("/resource/v2/other_obj/host/inst/attributes/", "GET"),
    ("/resource/v2/host/inst/relation_attributes/", "PUT"),
    ("/resource/v2/other_obj/log/detail/", "GET"),
    ("/bk_sops/common_template", "GET"),
    ("/bk_sops/taskflow", "POST"),
    ("/monitor_mgmt/uac/add_execute/", "POST"),
    ("/monitor_mgmt/uac/delete_execute/", "POST"),
    ("/monitor_mgmt/uac/search_uac_users/", "GET"),
    ("/monitor_mgmt/monitor/get_obj_attrs/", "GET"),
    ("/monitor_mgmt/monitor/get_monitor_detail_by_obj/", "GET"),
    ("/account/login_success/", "GET"),
    ("/patch_mgmt/distribute_file_callback/", "POST"),
    ("/patch_mgmt/patch_file_callback/", "POST"),
    ("/resource/v2/obj/mainline/obj_topo/", "GET"),
    ("/auto_mate/open_oid/", "POST"),
    ("/resource/open_access_point/", "GET"),
    ("/system/mgmt/sys_setting/wx_app_id/", "POST"),
    # 手动初始化网络设备模版
    ("/monitor_mgmt/init_network_template/", "GET"),
    ("/system/mgmt/open_create_user/", "POST"),
    ("/system/mgmt/open_set_user_roles/", "POST"),
    ("/system/mgmt/access_points/", "GET"),
    ("/health_advisor/resource/business/", "GET"),
    ("/monitor_mgmt/monitor_object/sync_monitor_object_to_monitor_and_uac/", "GET"),
}

# 动态路由白名单
MATCH_PASS_PATH = {
    (r"/bk_sops/common_template/(?P<template_id>\d+)", "DELETE"),
    (r"/resource/v2/other_obj/(?P<bk_obj_id>.+?)/inst/attributes/", "PUT"),
    (r"/resource/v2/other_obj/(?P<bk_obj_id>.+?)/inst/relation_attributes/", "PUT"),
    (r"/resource/v2/other_obj/(?P<bk_obj_id>.+?)/inst/relation_attributes/", "PUT"),
    (r"/api/cc/*", "PUT"),
    (r"/api/cc/*", "GET"),
    (r"/api/cc/*", "POST"),
}

POLICY = {
    # 管理-系统管理-角色管理
    "SysRole": {
        checkAuth: {
            ("/system/mgmt/role_manage/get_roles/", "GET", QUERY, "v3.9"),
            ("/system/mgmt/role_manage/get_role_applications/", "GET", QUERY, "v3.9"),
            ("/system/mgmt/inst_permissions/", "GET", QUERY, "v4.3"),
            ("/system/mgmt/inst_permissions/get_monitor_attrs/", "GET", QUERY, "v4.3"),
            ("/system/mgmt/inst_permissions/get_instances/", "GET", QUERY, "v4.3"),
            ("/system/mgmt/inst_permissions/get_instance_types/", "GET", QUERY, "v4.3"),
        },
        operateAuth: {
            ("/system/mgmt/role_manage/create_role/", "POST", CREATE, "v3.9"),
            ("/system/mgmt/role_manage/delete_role/", "DELETE", DELETE, "v3.9"),
            ("/system/mgmt/role_manage/edit_role/", "PUT", MODIFY, "v3.9"),
            ("/system/mgmt/role_manage/get_role_menus/", "GET", QUERY, "v3.9"),
            ("/system/mgmt/role_manage/set_role_menus/", "POST", MODIFY, "v3.9"),
            ("/system/mgmt/role_manage/set_app_permissions/", "POST", MODIFY, "v3.9"),
            ("/system/mgmt/inst_permissions/", "POST", CREATE, "v4.3"),
            ("/system/mgmt/inst_permissions/?P<pk>[^/.]+)/", "PUT", MODIFY, "v4.3"),
            ("/system/mgmt/inst_permissions/?P<pk>[^/.]+)/", "DELETE", DELETE, "v4.3"),
        },
    },
    # 管理-系统管理-用户管理
    "SysUser": {
        checkAuth: {
            ("/system/mgmt/user_manage/get_users/", "GET", QUERY, "v3.9"),
            ("/system/mgmt/sys_setting/get_login_set/", "GET", QUERY, "v3.10"),
            ("/system/mgmt/role_manage/search_role_list/", "GET", QUERY, "v3.10"),
            ("/system/mgmt/user_manage/search_user_list/", "GET", QUERY, "v3.10"),
            ("/system/mgmt/sys_setting/get_domain/", "GET", QUERY, "v3.13"),
        },
        operateAuth: {
            ("/system/mgmt/user_manage/(?P<pk>[^/.]+)/update_user_status/", "PATCH", MODIFY, "v4.2"),
            ("/system/mgmt/user_manage/create_user/", "POST", CREATE, "v3.9"),
            ("/system/mgmt/user_manage/edit_user/", "PATCH", MODIFY, "v3.9"),
            ("/system/mgmt/user_manage/set_user_roles/", "POST", CREATE, "v3.9"),
            ("/system/mgmt/user_manage/reset_password/", "PATCH", MODIFY, "v3.9"),
            ("/system/mgmt/user_manage/delete_users/", "DELETE", DELETE, "v3.9"),
            ("/system/mgmt/sys_users/pull_bk_user/", "POST", CREATE, "v3.9"),
            ("/system/mgmt/sys_setting/update_login_set/", "POST", QUERY, "v3.10"),
            ("/system/mgmt/sys_setting/send_validate_code/", "POST", QUERY, "v3.10"),
            ("/system/mgmt/sys_setting/set_domain/", "POST", QUERY, "v3.13"),
        },
    },
    # 管理-系统管理-自愈流程
    "SelfCureProcess": {
        checkAuth: {
            ("/uac/search_execute_list/", "GET", QUERY, "v3.9"),
            ("/uac/get_execute_template_list/", "GET", QUERY, "v3.9"),
        },
        operateAuth: {
            ("/uac/add_execute/", "POST", CREATE, "v3.9"),
            ("/uac/modify_execute/", "PUT", MODIFY, "v3.9"),
            ("/uac/set_execute_status/", "PATCH", MODIFY, "v3.9"),
            ("/uac/delete_execute/", "POST", DELETE, "v3.9"),
        },
    },
    # 管理-系统管理-操作日志
    "SysLog": {checkAuth: {("/system/mgmt/operation_log/", "GET", QUERY, "v3.9")}},
    # 管理-系统管理-Logo设置
    "SysLogo": {
        checkAuth: {("/system/mgmt/logo/", "GET", QUERY, "v3.9")},
        operateAuth: {
            ("/system/mgmt/logo/", "PUT", MODIFY, "v3.9"),
            ("/system/mgmt/logo/reset/", "POST", MODIFY, "v3.9"),
        },
    },
    # 管理-系统管理-系统设置(SysLogo 改名 先合并 到时候版本GA后直接删除SysLogo)
    "SysSetting": {
        checkAuth: {
            ("/system/mgmt/logo/", "GET", QUERY, "v3.9"),
            ("system/mgmt/menu_manage/", "GET", QUERY, "v4.1"),
            ("system/mgmt/menu_manage/get_use_menu/", "GET", QUERY, "v4.1"),
        },
        operateAuth: {
            ("/system/mgmt/logo/", "PUT", MODIFY, "v3.9"),
            ("/system/mgmt/logo/reset/", "POST", MODIFY, "v3.9"),
            ("system/mgmt/menu_manage/", "POST", CREATE, "v4.1"),
            ("system/mgmt/menu_manage/(?P<pk>[^/.]+)/", "PUT", MODIFY, "v4.1"),
            ("system/mgmt/menu_manage/(?P<pk>[^/.]+)/", "DELETE", DELETE, "v4.1"),
            ("system/mgmt/menu_manage/(?P<pk>[^/.]+)/use_menu/", "PATCH", MODIFY, "v4.1"),
        },
    },
}
