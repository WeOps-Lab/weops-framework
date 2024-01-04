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
from keycloak import KeycloakOpenID, KeycloakOpenIDConnection, KeycloakAdmin
from types import SimpleNamespace

import unittest
import uuid
import json

class PythonKeycloakTest(unittest.TestCase):
    def setUp(self):
        self.username = 'admin'
        self.password = 'admin'
        self.id_of_client = 'a72a5bed-8673-48e1-ac0a-97ba3c06c88f'
        self.keycloak_openid = KeycloakOpenID(
            server_url=f'http://localhost:8081/',
            client_id=f'weops_lite',
            realm_name=f'weops',
            client_secret_key=f'**********')
        self.token = self.keycloak_openid.token(self.username, self.password)

        self.keycloak_connection = KeycloakOpenIDConnection(
            server_url=f'http://localhost:8081/',
            username=self.username,
            password=self.password,
            user_realm_name='master',
            realm_name=f'weops',
            client_id=f'admin-cli')
        self.keycloak_admin = KeycloakAdmin(connection=self.keycloak_connection)
        print("Setting up the test environment")

    def test_method(self):
        userinfo = self.keycloak_openid.userinfo(self.token['access_token'])
        tokeninfo = self.keycloak_openid.introspect(self.token['access_token'])
        print(userinfo)
        KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + self.keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
        options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}
        decoded = self.keycloak_openid.decode_token(self.token['access_token'], key=KEYCLOAK_PUBLIC_KEY, options=options)
        self.keycloak_openid.load_authorization_config(r"D:\Projectes\weops-framework\auth_info.json")
        policies = self.keycloak_openid.get_policies(self.token['access_token'], method_token_info='decode',
                                                key=KEYCLOAK_PUBLIC_KEY, options=options)
        permissions = self.keycloak_openid.get_permissions(self.token['access_token'], method_token_info='introspect')
        # all_p = self.keycloak_admin.get_client_authz_permissions(self.id_of_client)
        # 获取所有有权限的资源名
        permissions = self.keycloak_openid.uma_permissions(self.token['access_token'])
        # 填入资源名，有权限有返回，没有权限返回403 exception
        permission = self.keycloak_openid.uma_permissions(self.token['access_token'], permissions=['users_view'])
        has = self.keycloak_openid.has_uma_access(self.token['access_token'], permissions=['users_delete'])
        token_info = self.keycloak_openid.decode_token(self.token['access_token'], key=KEYCLOAK_PUBLIC_KEY, options=options)
        # rpt = self.keycloak_openid.entitlement(self.token['access_token'], 'cc698101-935f-40b5-94ff-e46d71b69b37')
        # print(rpt)
        pass

    def test_get(self):
        c=  self.keycloak_admin.get_clients()
        print(c)
        r = self.keycloak_admin.get_client_roles_of_user('e1db5599-69e2-4b42-81d6-7b698a88f9eb', 'a72a5bed-8673-48e1-ac0a-97ba3c06c88f')
        print(r)

    def test_get_permission(self):
        r = self.keycloak_admin.get_client_role(self.id_of_client, 'normal')
        rs = self.keycloak_admin.get_client_roles(self.id_of_client)
        p = self.keycloak_admin.get_client_authz_permissions(self.id_of_client)
        po = self.keycloak_admin.get_client_authz_policies(self.id_of_client)
        us = self.keycloak_admin.get_client_role_members(self.id_of_client,'admin')
        print(p)
        pass

    def test_get_client_info(self):
        # 用这种方式在新realm登录
        keycloak_admin = KeycloakAdmin(server_url="http://localhost:8081/",
                                       username="admin",
                                       password="admin",
                                       realm_name="weops",
                                       client_id="admin-cli",
                                       user_realm_name='master')
        token = keycloak_admin.token
        # with open(r'D:\Projectes\weops-framework\config\realm-export.json', 'r', encoding='utf8') as realm_config_file:
        #     realm_config = json.load(realm_config_file)
        # clients = keycloak_admin.get_clients()
        pass

    def test_create_role(self):
        role_name='test'
        role_payload = {
            'name': role_name,
            'clientRole': True
        }
        self.keycloak_admin.create_client_role(self.id_of_client, role_payload)
        role = self.keycloak_admin.get_client_role(self.id_of_client, role_name)
        policy_payload = {
            "type": "role",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "name": role_name,
            "roles": [
                {
                    "id": role['id'],
                    "required": True
                }
            ]
        }
        self.keycloak_admin.create_client_authz_role_based_policy(
            self.id_of_client
            , policy_payload)

    def test_get(self):
        ps = self.keycloak_openid.get_permissions('eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3SWktZWRvTktpaU1ZMmR2eU1VcGVTd0tjU1BpeGVqM0JSaEVJZE9sSWhzIn0.eyJleHAiOjE3MDQzNDcyOTIsImlhdCI6MTcwNDI2MDg5MiwianRpIjoiYjgwYThiMmItN2U5NC00ZmU5LTkwZWItNTE4Y2ZlMTQwZTA4IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL3JlYWxtcy93ZW9wcyIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI0ZTdiZTc5Ny0yNzBkLTRkOTItOGYyMy04OTIzZWZhODFhMzEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3ZW9wc19saXRlIiwic2Vzc2lvbl9zdGF0ZSI6IjVhOGQ4NmZhLWNmMTItNGEyZS1hNTFlLWUxN2ZlY2IxZDhkZiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1tYXN0ZXIiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCIsInNpZCI6IjVhOGQ4NmZhLWNmMTItNGEyZS1hNTFlLWUxN2ZlY2IxZDhkZiIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IueuoeeQhuWRmCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFkbWluIiwiZmFtaWx5X25hbWUiOiLnrqHnkIblkZgiLCJlbWFpbCI6ImFkbWluQGtjLmNvbSJ9.k0LOl_yyY_PpvUA3LTCmGEEhfrUrsClfB6mBnrN1Igec9XOz_qAG4Cl5YU4zw06pVTpmyyZKc6KPyhYXpcQy6BrseiHYxXKKFdgPu_hVtey_m9oidqUdCHhkaoKgUWnHGHnID6A0--6pb0gOsrgAPLaubzoI8EjO3V866evyXHrr52spLR_1jlg6I1qT35hjjoE8oh4F_gqnAgcMuvNW_-pvI_6fz7UKTi1gco8FQxksZWuPOA7daJjrc5bGgBd6j-Wtudsgq84CM-YQYUT9fwQw2MonCIx85PMrO5qmAuXFXlCuRnzHbs0EEpkfBMslZBCOTm3CkAvh9bo5VF-kLQ')
        pass

    def test_simple_namespace(self):
        obj = SimpleNamespace(name='ddd')
        print(obj.name)
        realms = self.keycloak_admin.get_realms()
        pass

    def test_login_code(self):
        tk = self.keycloak_openid.token(
            grant_type='authorization_code',
            code='eb08fd1e-a50f-4108-a831-6625701a0ee9.da1edc58-e3ce-4e0c-899b-597c7d7c65a7.a72a5bed-8673-48e1-ac0a-97ba3c06c88f',
            redirect_uri='http://localhost:8000'
        )
        pass

    def test_groups(self):
        g_query = {
            'search':'555',
            'first':0,
            'max':20
        }
        groups = self.keycloak_admin.get_groups(g_query)
        m_query = {
            'first':0,
            'max':20
        }
        group = self.keycloak_admin.get_group(groups[0]['id'])
        roles = self.keycloak_admin.get_group_client_roles(groups[0]['id'], self.id_of_client)
        members = self.keycloak_admin.get_group_members(groups[0]['id'],m_query)
        # self.keycloak_admin.assign_group_client_roles('fc1c70a8-b159-47e0-97e1-1396433438fc',
        #                                               'a72a5bed-8673-48e1-ac0a-97ba3c06c88f',
        #                                               [{
        #                                                   'name': 'normal',
        #                                                   'id':'8d1600a5-a785-4d18-a815-44049210968b'
        #                                               }])
        # group_payload = {
        #     'name':'hhg'
        # }
        # self.keycloak_admin.create_group()
        pass

if __name__ == '__main__':
    unittest.main()

# class TestUserManages(test.TestCase):
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.user = UserManageApi()
#         self.cookies = os.getenv("BKAPP_BK_TEST_COOKIES", "")
#         self.user_id = None
#
#     def setUp(self) -> None:
#         print("user test start")
#         SysRole.objects.create(role_name="normal_role")
#         self.user_util = UserUtils()
#         self.assertTrue(self.cookies)
#
#     def tearDown(self) -> None:
#         print("user test end")
#
#     def test_user_manage(self):
#         """
#         先初始化cookies
#         再进行创建，修改，重置密码，最后删除用户
#         """
#         self.set_header()
#         self.add_bk_user_manage()
#         self.update_bk_user_manage()
#         self.reset_passwords()
#         self.delete_bk_user_manage()
#
#     def set_header(self):
#         self.user.set_header(self.cookies)
#         self.assertTrue(self.user.header)
#
#     def add_bk_user_manage(self):
#         self.user.header["Cookie"] = self.cookies
#         data = {
#             "username": "test_{}".format(int(time.time())),
#             "display_name": "测试创建用户{}".format(int(time.time())),
#             "email": "123@qq.com",
#             "telephone": "13234567832",
#         }
#         res = self.user.add_bk_user_manage(data)
#         self.assertTrue(res["result"])
#         self.user_id = res["data"]["id"]
#
#     def update_bk_user_manage(self):
#         data = {
#             "display_name": "测试创建用户{}".format(int(time.time())),
#             "email": "123@qq.com",
#             "telephone": "13234567832",
#         }
#         res = self.user.update_bk_user_manage(data=data, id=self.user_id)
#         self.assertTrue(res["result"])
#
#     def reset_passwords(self):
#         password = "".join(random.sample(string.ascii_letters + string.digits, 16))  # 生成随机密码16位
#         data = {"password": password}
#         res = self.user.reset_passwords(id=self.user_id, data=data)
#         self.assertTrue(res["result"])
#
#     def delete_bk_user_manage(self):
#         data = [{"id": self.user_id}]
#         res = self.user.delete_bk_user_manage(data=data)
#         self.assertTrue(res["result"])
#
#     def test_formative_user_data(self):
#         data = {
#             "username": "test_{}".format(int(time.time())),
#             "display_name": "测试创建用户{}".format(int(time.time())),
#             "email": "123@qq.com",
#             "telephone": "13234567832",
#         }
#         normal_role = SysRole.objects.last()
#         user_data = self.user_util.formative_user_data(**{"data": data, "normal_role": normal_role})
#         self.assertTrue(user_data)
