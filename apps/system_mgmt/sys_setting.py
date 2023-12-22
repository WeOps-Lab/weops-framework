from __future__ import absolute_import, unicode_literals

import datetime
import json
import random
import string
import typing

from apps.system_mgmt.models import SysSetting, UserSysSetting
from utils.locals import current_request


def serializer_value(value, vtype):
    return SysSetting.VTYPE_FIELD_MAPPING.get(
        vtype, SysSetting.VTYPE_FIELD_MAPPING[SysSetting.DEFAULT]
    )().prepare_value(value)


class SysSettingOp(object):
    models = SysSetting

    def init_verify_json(self):
        registration_code = self.create_registration_code()
        start_time = datetime.datetime.now()
        expiration_time = start_time + datetime.timedelta(days=30)
        start_date = str(start_time.date())
        expiration_time = str(expiration_time.date())
        obj_data = {
            "registration_code": registration_code,
            "start_date": start_date,
            "expiration_date": expiration_time,
            "activation_status": "试用期",
            "agent_num": 50,
            "applications": [
                "health_advisor",
                "monitor_mgmt",
                "operational_tools",
                "repository",
                "big_screen",
                "senior_resource",
                "patch_mgmt",
                "auto_process",
            ],
        }
        self.models.objects.get_or_create(key="activation_data", vtype="json", defaults={"value": json.dumps(obj_data)})

    @staticmethod
    def create_registration_code():
        str_list = ["".join(random.sample(string.ascii_uppercase + string.digits, 5)) for _ in range(5)]
        registration_code = "-".join(str_list)
        return registration_code

    def __getattr__(self, key: str) -> str:
        """
        获取值
        example:  sys_setting.system_logo
        :param key: string, CUSTOM_SYSTEM_SETTINGS的key
        :return:string,
        """

        _setting = self.models.objects.filter(key=key).first()
        return _setting.real_value if _setting else None

    def __setattr__(self, key: str, value: typing.Any):
        """
        设置值
        example: sys_setting.system_logo="123"
        :param key:  string
        :param value:
        :return:
        """

        _setting = self.models.objects.filter(key=key).first()
        if _setting:
            value = serializer_value(value, _setting.vtype)
            _setting.value = value
            _setting.save()

    def set_many(self, mapping: typing.Dict[str, typing.Any]):
        """
        设置多个值
        :param mapping: {key1:value1,key2:value2}
        :return:
        """
        for key, value in mapping.items():
            setattr(self, key, value)

    def get_many(self, keys: typing.List[str]) -> typing.Dict[str, str]:
        """
        获取多个值
        :param keys: [key1,key2]
        :return:
        """
        settings = self.models.objects.filter(key__in=keys).all()
        return {setting.key: setting.real_value for setting in settings}


class UserSysSettingOp(object):
    default_models = SysSetting
    models = UserSysSetting

    def get(self, key: str, user=None) -> str:
        """
        获取值
        example:  sys_setting.system_logo
        :param key: string, CUSTOM_SYSTEM_SETTINGS的key
        :return:string,
        """
        user = user or (current_request.user.sys_user if current_request else None)
        _setting = self.models.objects.filter(key=key, user=user).first()
        if not _setting:
            _setting = self.default_models.objects.filter(key=key).first()
        return _setting.real_value if _setting else None

    def set(self, key: str, value: typing.Any, vtype=UserSysSetting.STRING, user=None):
        """
        设置值
        example: user_sys_setting.system_logo="123"
        :param key:  string, CUSTOM_SYSTEM_SETTINGS的key
        :param value:
        :return:
        """
        user = user or (current_request.user.sys_user if current_request else None)
        if not user:
            return
        value = serializer_value(value, vtype)
        self.models.objects.update_or_create(defaults=dict(value=value, vtype=vtype), user=user, key=key)


sys_setting = SysSettingOp()
user_sys_setting = UserSysSettingOp()
