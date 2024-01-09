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

from django.conf import settings
from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    url(r"^admin/", admin.site.urls),
    url(r"^account/", include("blueapps.account.urls")),
    # 如果你习惯使用 Django 模板，请在 home_application 里开发你的应用，
    # 这里的 home_application 可以改成你想要的名字
    url(r"^", include("base_index.urls")),
    # 如果你习惯使用 mako 模板，请在 mako_application 里开发你的应用，
    # 这里的 mako_application 可以改成你想要的名字
    url(r"^i18n/", include("django.conf.urls.i18n")),
    url(r"^version_log/", include("version_log.urls", namespace="version_log")),
]
apps = {"apps": os.listdir("apps"), "apps_other": os.listdir("apps_other")}
for key, app_list in apps.items():
    dir_list = [
        i
        for i in app_list
        if os.path.isdir(f"{key}/{i}")
        and "urls.py" in os.listdir(f"{key}/{i}")
        and not i.startswith("__")
        and i not in ["system_mgmt"]
    ]  # noqa
    for i in dir_list:
        urlpatterns.append(url(r"^{}/".format(i), include(f"{key}.{i}.urls")))  # noqa

if settings.RUN_MODE == "DEVELOP":
    """
    开发时添加SWAGGER API DOC
    访问地址: http://dev.cwbk.com:8000/docs/
    """
    from django.urls import path
    from rest_framework import permissions
    from drf_yasg.views import get_schema_view
    from drf_yasg import openapi
    schema_view = get_schema_view(
        openapi.Info(
            title="API文档",
            default_version='v1',
            description="API接口文档",
            terms_of_service="https://www.example.com/policies/terms/",
            contact=openapi.Contact(email="contact@example.com"),
            license=openapi.License(name="BSD License"),
        ),
        public=True,
        permission_classes=(permissions.AllowAny,),
    )
    urlpatterns += [
        path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
        path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    ]
try:
    from custom_urls import urlpatterns as custom_url

    urlpatterns += custom_url
except ImportError:
    pass
