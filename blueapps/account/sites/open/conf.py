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

class ConfFixture(object):
    BACKEND_TYPE = "bk_token"
    if settings.LOGIN_METHOD == "local":
        # 如果是本地登录，使用当前LoginBackend
        USER_BACKEND = 'bk_local.backends.LoginBackend'
        LOGIN_REQUIRED_MIDDLEWARE = "bk_local.middlewares.LocalLoginRequiredMiddleware"
    elif settings.LOGIN_METHOD == "blueking":
        # 如果是蓝鲸登录，使用TokenBackend
        USER_BACKEND = 'bk_token.backends.TokenBackend'
        LOGIN_REQUIRED_MIDDLEWARE = "bk_token.middlewares.LoginRequiredMiddleware"
    else:
        USER_BACKEND = 'bk_keycloak.backends.KeycloakBackend'
        LOGIN_REQUIRED_MIDDLEWARE = "bk_keycloak.middlewares.KeycloakMiddleware"

    USER_MODEL = "bk_token.models.UserProxy"

    CONSOLE_LOGIN_URL = settings.BK_PAAS_HOST
    LOGIN_URL = settings.BK_PAAS_HOST + "/login/"
    LOGIN_PLAIN_URL = settings.BK_PAAS_HOST + "/login/plain/"
    VERIFY_URL = settings.BK_PAAS_INNER_HOST + "/login/accounts/is_login/"
    USER_INFO_URL = settings.BK_PAAS_INNER_HOST + "/login/accounts/get_user/"
    HAS_PLAIN = False
    ADD_CROSS_PREFIX = False
    ADD_APP_CODE = True

    IFRAME_HEIGHT = 490
    IFRAME_WIDTH = 460

    # WEIXIN_BACKEND_TYPE = 'null'
    # WEIXIN_MIDDLEWARE = 'null.NullMiddleware'
    # WEIXIN_BACKEND = 'null.NullBackend'
    #
    # 登录模块 weixin
    WEIXIN_BACKEND_TYPE = "weixin"
    # 用户认证中间件 bk_ticket.middlewares.LoginRequiredMiddleware
    WEIXIN_MIDDLEWARE = "weixin.middlewares.WeixinLoginRequiredMiddleware"
    # 用户认证 Backend bk_ticket.backends.TicketBackend
    WEIXIN_BACKEND = "weixin.backends.WeixinBackend"

    # 用户信息链接 http://xxx.com/user/weixin/get_user_info/
    # WEIXIN_INFO_URL = "https://api.weixin.qq.com/sns/userinfo"
    WEIXIN_INFO_URL = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo"
    # WEIXIN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token"
    WEIXIN_URL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"

    # 用户 OAUTH 认证链接 https://xxx.com/connect/oauth2/authorize
    WEIXIN_OAUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize"
    WEIXIN_APP_EXTERNAL_HOST = os.environ.get("BKAPP_WEIXIN_APP_EXTERNAL_HOST", "http://paas.weops.com")
    # WEIXIN_LOGIN_URL = settings.SITE_URL + "account/weixin/login/"
    WEIXIN_LOGIN_URL = settings.SITE_URL + "mobile/"

    # 微信公众号的app id/企业微信corp id
    WEIXIN_APP_ID = os.environ.get("BKAPP_WEIXIN_APP_ID", "")
    # 微信公众号的app secret/企业微信应用的secret
    WEIXIN_APP_SECRET = os.environ.get("BKAPP_WEIXIN_APP_SECRET", "")

    SMS_CLIENT_MODULE = "cmsi"
    SMS_CLIENT_FUNC = "send_sms"
    SMS_CLIENT_USER_ARGS_NAME = "receiver__username"
    SMS_CLIENT_CONTENT_ARGS_NAME = "content"

    RIO_BACKEND_TYPE = "null"
    RIO_MIDDLEWARE = "null.NullMiddleware"
    RIO_BACKEND = "null.NullBackend"

    BK_JWT_MIDDLEWARE = "bk_jwt.middlewares.BkJwtLoginRequiredMiddleware"
    BK_JWT_BACKEND = "bk_jwt.backends.BkJwtBackend"
