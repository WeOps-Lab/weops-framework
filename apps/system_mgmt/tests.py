# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云PaaS平台社区版 (BlueKing PaaS Community
Edition) available.
Copyright (C) 2017-2020 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import os
import time
import random
import string
from django import test
from django.conf import LazySettings
from keycloak import KeycloakOpenID, KeycloakOpenIDConnection, KeycloakAdmin

from apps.system_mgmt.models import SysRole

from .user_manages import UserManageApi
from .utils_package.db_utils import UserUtils

class PythonKeycloakTest(test.TestCase):
    def setUp(self):
        settings = LazySettings()
        self.username = 'admin'
        self.password = 'admin'
        self.keycloak_openid = KeycloakOpenID(
            server_url=f'http://{settings.KEYCLOAK_SETTINGS["KEYCLOAK_SERVER"]}:{settings.KEYCLOAK_SETTINGS["KEYCLOAK_PORT"]}/',
            client_id=f'{settings.KEYCLOAK_SETTINGS["CLIENT_ID"]}',
            realm_name=f'{settings.KEYCLOAK_SETTINGS["REALM_NAME"]}',
            client_secret_key=f'{settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"]}')
        self.token = self.keycloak_openid.token(self.username, self.password)

        self.keycloak_connection = KeycloakOpenIDConnection(
            server_url=f'http://{settings.KEYCLOAK_SETTINGS["KEYCLOAK_SERVER"]}:{settings.KEYCLOAK_SETTINGS["KEYCLOAK_PORT"]}/',
            username=self.username,
            password=self.password,
            realm_name=f'{settings.KEYCLOAK_SETTINGS["REALM_NAME"]}',
            client_id=f'{settings.KEYCLOAK_SETTINGS["CLIENT_ID"]}',
            client_secret_key=f'{settings.KEYCLOAK_SETTINGS["CLIENT_SECRET_KEY"]}',
            verify=True)
        self.keycloak_admin = KeycloakAdmin(connection=self.keycloak_connection)

    def test_method(self):
        rpt = self.keycloak_openid.entitlement(self.token['access_token'], 'cc698101-935f-40b5-94ff-e46d71b69b37')
        print(rpt)
        pass


class TestUserManages(test.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = UserManageApi()
        self.cookies = os.getenv("BKAPP_BK_TEST_COOKIES", "")
        self.user_id = None

    def setUp(self) -> None:
        print("user test start")
        SysRole.objects.create(role_name="normal_role")
        self.user_util = UserUtils()
        self.assertTrue(self.cookies)

    def tearDown(self) -> None:
        print("user test end")

    def test_user_manage(self):
        """
        先初始化cookies
        再进行创建，修改，重置密码，最后删除用户
        """
        self.set_header()
        self.add_bk_user_manage()
        self.update_bk_user_manage()
        self.reset_passwords()
        self.delete_bk_user_manage()

    def set_header(self):
        self.user.set_header(self.cookies)
        self.assertTrue(self.user.header)

    def add_bk_user_manage(self):
        self.user.header["Cookie"] = self.cookies
        data = {
            "username": "test_{}".format(int(time.time())),
            "display_name": "测试创建用户{}".format(int(time.time())),
            "email": "123@qq.com",
            "telephone": "13234567832",
        }
        res = self.user.add_bk_user_manage(data)
        self.assertTrue(res["result"])
        self.user_id = res["data"]["id"]

    def update_bk_user_manage(self):
        data = {
            "display_name": "测试创建用户{}".format(int(time.time())),
            "email": "123@qq.com",
            "telephone": "13234567832",
        }
        res = self.user.update_bk_user_manage(data=data, id=self.user_id)
        self.assertTrue(res["result"])

    def reset_passwords(self):
        password = "".join(random.sample(string.ascii_letters + string.digits, 16))  # 生成随机密码16位
        data = {"password": password}
        res = self.user.reset_passwords(id=self.user_id, data=data)
        self.assertTrue(res["result"])

    def delete_bk_user_manage(self):
        data = [{"id": self.user_id}]
        res = self.user.delete_bk_user_manage(data=data)
        self.assertTrue(res["result"])

    def test_formative_user_data(self):
        data = {
            "username": "test_{}".format(int(time.time())),
            "display_name": "测试创建用户{}".format(int(time.time())),
            "email": "123@qq.com",
            "telephone": "13234567832",
        }
        normal_role = SysRole.objects.last()
        user_data = self.user_util.formative_user_data(**{"data": data, "normal_role": normal_role})
        self.assertTrue(user_data)
