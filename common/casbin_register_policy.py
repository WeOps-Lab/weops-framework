# -- coding: utf-8 --

# @File : casbin_register_policy.py
# @Time : 2023/2/27 11:46
# @Author : windyzhao
"""
对每个app下的 casbin_policy下的policy_constants文件内的POLICY_DICT进行收集
"""
import importlib
import os

from constants.sys_manage_constants import checkAuth, operateAuth

policy_file_name = "policy_constants"


class CasbinRegisterPolicy(object):
    def __init__(self):
        self.policy_dict = dict()  # 权限接口
        self._pass_policy = set()  # 白名单
        self._match_pass_policy = set()  # 动态白名单
        # TODO 后续优化 等对接新的casbin server
        # 激活可选的app 由于导入不了apps/system_mgmt下的静态对象 所以只能写死再次
        # self.MENUS = {
        #     "health_advisor",
        #     "monitor_mgmt",
        #     "operational_tools",
        #     "repository",
        #     "big_screen",
        #     "senior_resource",
        #     "itsm",
        #     "patch_mgmt",
        #     "auto_process",
        # }

    def register_policy(self, apps, policy):
        self.policy_dict.update({apps: policy})

    def policy(self):
        return self.policy_dict

    def pass_policy(self):
        return self._pass_policy

    def match_pass_policy(self):
        return self._match_pass_policy

    # def activation_app_set(self):
    #     from apps.activation.models import Activation
    #     activation_obj = Activation.objects.last()
    #     if activation_obj is None:
    #         raise Exception("请先激活weops!")
    #     return set(activation_obj.applications)

    def register_home_application(self):
        home_application_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "home_application"
        )
        if not os.path.exists(home_application_path):
            return
        casbin_policy_path = os.path.join(home_application_path, "casbin_policy")
        if not os.path.isdir(casbin_policy_path):
            return

        policy_file = os.path.join("home_application", "casbin_policy", policy_file_name)
        if not os.path.exists(f"{policy_file}.py"):
            return

        self._get_attrs(policy_file)

    def register_apps_policy(self):
        apps_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "apps")
        for app_path in os.listdir(apps_path):
            app_abs_path = os.path.join(apps_path, app_path)
            if not os.path.isdir(app_abs_path):
                continue
            # if app_path in self.MENUS and app_path not in self.ACTIVATION_APP_SET:
            #     continue
            casbin_policy_path = os.path.join(app_abs_path, "casbin_policy")
            if not os.path.isdir(casbin_policy_path):
                continue
            policy_file = os.path.join("apps", app_path, "casbin_policy", policy_file_name)
            if not os.path.exists(f"{policy_file}.py"):
                continue
            self._get_attrs(policy_file)

        self.register_home_application()

    def _get_attrs(self, policy_file):
        policy_file = policy_file.replace("/", ".").replace("\\", ".")
        policy_constants = importlib.import_module(policy_file)
        policy = getattr(policy_constants, "POLICY", {})
        menus_policy = getattr(policy_constants, "MENUS_POLICY", {})
        self.menus_policy(policy, menus_policy)  # app_name
        self._pass_policy.update(getattr(policy_constants, "PASS_PATH", set()))
        self._match_pass_policy.update(getattr(policy_constants, "MATCH_PASS_PATH", set()))

    def menus_policy(self, menus_policy_dict, menus_other_policy):  # app_name
        """
        可能出现页面key一致的情况 需要进行合并
        """
        for menus_id, policy_dict in menus_policy_dict.items():
            # 合并
            if menus_id in self.policy_dict:
                check_auth = policy_dict.get(checkAuth, {})
                operate_auth = policy_dict.get(operateAuth, {})
                self.policy_dict.get(menus_id).get(checkAuth).update(check_auth)
                self.policy_dict.get(menus_id).get(operateAuth).update(operate_auth)
            else:
                self.policy_dict.update({menus_id: policy_dict})

            # menus_other_policy 和 menus_policy_dict的合并
            menus_other_policy_dict = menus_other_policy.get(menus_id, {})
            for _app_name, _policy_dict in menus_other_policy_dict.items():
                # if _app_name in self.MENUS and _app_name not in self.ACTIVATION_APP_SET:
                #     continue
                _check_auth = _policy_dict.get(checkAuth, {})
                _operate_auth = _policy_dict.get(operateAuth, {})
                self.policy_dict.get(menus_id).get(checkAuth).update(_check_auth)
                self.policy_dict.get(menus_id).get(operateAuth).update(_operate_auth)


casbin_policy = CasbinRegisterPolicy()
casbin_policy.register_apps_policy()
POLICY_DICT = casbin_policy.policy()
PASS_PATH = casbin_policy.pass_policy()
MATCH_PASS_PATH = casbin_policy.match_pass_policy()
