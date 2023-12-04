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

from django.conf.urls import url

from apps.system_mgmt import views
from rest_framework.routers import DefaultRouter

urlpatterns = [
    url(r"^test_get/$", views.test_get),
    url(r"^test_post/$", views.test_post),
    url(r"^logo/$", views.LogoViewSet.as_view({"get": "retrieve", "put": "update"})),
    url(r"^logo/reset/$", views.LogoViewSet.as_view({"post": "reset"})),
    url(r"reset_policy_init/$", views.reset_policy_init),
    url(r"open_create_user/$", views.open_create_user),
    url(r"open_set_user_roles/$", views.open_set_user_roles),
    url(r"get_is_need_two_factor/$", views.get_is_need_two_factor),
    url(r"send_validate_code_exempt/$", views.send_validate_code_exempt),
    url(r"login_info/$", views.LoginInfoView.as_view()),
    # 用户登录
    url(r"keycloak_login/$", views.KeyCloakLoginView.as_view()),
]

router = DefaultRouter()
router.register(r'users', views.KeyCloakUserViewSet, basename='user')
router.register(r'roles', views.KeyCloakRoleViewSet, basename='role')
# 用户管理API
urlpatterns.extend(router.urls)
