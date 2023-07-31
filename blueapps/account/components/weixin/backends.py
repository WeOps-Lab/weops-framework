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

import logging
import traceback

from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.core.cache import caches
from django.db import IntegrityError

from blueapps.account import get_user_model
from blueapps.account.components.weixin.weixin_utils import WechatUtils
from blueapps.account.conf import ConfFixture
from blueapps.account.utils.http import send
from blueapps.core.exceptions import BlueException
from blueapps.utils import client
from blueking.component.shortcuts import get_client_by_user

logger = logging.getLogger("component")

ROLE_TYPE_ADMIN = "1"

cache = caches["login_db"]


class WeixinBackend(ModelBackend):
    def authenticate(self, request=None, code=None, is_wechat=True):
        """
        is_wechat 参数是为了使得 WeixinBackend 与其他 Backend 参数个数不同，在框架选择
        认证 backend 时，快速定位
        """
        bk_token = request.COOKIES.get("bk_token", "")
        if bk_token:
            user = self.authenticate_user(bk_token, request)
            if user:
                return user
        if not code:
            return 0

        # result, user_info = self.verify_weixin_code(code)
        result, user_info = self.get_weixin_user(code)

        if not result:
            return 0

        user_model = get_user_model()
        try:
            user, _ = user_model.objects.get_or_create(username=user_info["username"])
            user.nickname = user_info["display_name"]
            user.save()
            # user.avatar_url = user_info["avatar"]
        except Exception:
            logger.exception("自动创建 & 更新 User Model 失败")
        else:
            return user

    def get_user(self, user_id):
        user_model = get_user_model()
        try:
            return user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist:
            return None

    def get_weixin_user(self, code):
        result, query_param = WechatUtils.check_login_code(code)
        if not result:
            return False, None
        try:
            data = send(ConfFixture.WEIXIN_INFO_URL, "GET", query_param)
            if data.get("errcode") and data.get("errcode") != 0:
                logger.error("通过微信授权码，获取用户信息失败，errcode={}，errmsg={}".format(data["errcode"], data["errmsg"]))
                return False, None
            weixin_user_id = data["UserId"]
            user = self.get_bk_user(weixin_user_id)
            return True, user
        except BlueException:
            logger.exception("通过微信授权码，获取用户信息异常")
            return False, None

    def get_bk_user(self, weixin_user_id):
        client = get_client_by_user("admin")
        result = client.usermanage.retrieve_user(
            {"id": weixin_user_id, "lookup_field": "wx_userid", "fields": "username,display_name"}
        )
        if not result["result"]:
            logger.exception(result["message"])
            raise BlueException()
        return result["data"]

    def get_user_by_bk_token(self, bk_token):
        api_params = {"bk_token": bk_token}
        try:
            response = send(ConfFixture.VERIFY_URL, "GET", api_params, verify=False)
        except Exception:
            logger.exception(u"Abnormal error in verify_bk_token...")
            return None
        if not response.get("result"):
            error_msg = response.get("message", "")
            error_data = response.get("data", "")
            logger.error(u"Fail to verify bk_token, error={}, ret={}".format(error_msg, error_data))
            return
        data = response.get("data")
        username = data.get("username")
        user_model = get_user_model()
        try:
            user, _ = user_model.objects.get_or_create(username=username)
            get_user_info_result, user_info = self.get_user_info(bk_token)
            # 判断是否获取到用户信息,获取不到则返回None
            if not get_user_info_result:
                return None
            user.set_property(key="qq", value=user_info.get("qq", ""))
            user.set_property(key="language", value=user_info.get("language", ""))
            user.set_property(key="time_zone", value=user_info.get("time_zone", ""))
            user.set_property(key="role", value=user_info.get("role", ""))
            user.set_property(key="phone", value=user_info.get("phone", ""))
            user.set_property(key="email", value=user_info.get("email", ""))
            user.set_property(key="wx_userid", value=user_info.get("wx_userid", ""))
            user.set_property(key="chname", value=user_info.get("chname", ""))

            # 用户如果不是管理员，则需要判断是否存在平台权限，如果有则需要加上
            if not user.is_superuser and not user.is_staff:
                role = user_info.get("role", "")
                is_admin = True if str(role) == ROLE_TYPE_ADMIN else False
                user.is_superuser = is_admin
                user.is_staff = is_admin
                user.save()
            return user
        except IntegrityError:
            logger.exception(traceback.format_exc())
            logger.exception(u"get_or_create UserModel fail or update_or_create UserProperty")
            return None
        except Exception:
            logger.exception(traceback.format_exc())
            logger.exception(u"Auto create & update UserModel fail")
            return None

    @staticmethod
    def get_user_info(bk_token):
        api_params = {"bk_token": bk_token}
        try:
            response = client.bk_login.get_user(api_params)
        except Exception as e:
            logger.exception(u"Abnormal error in get_user_info...:%s" % e)
            return False, {}

        if response.get("result") is True:
            # 由于v1,v2的get_user存在差异,在这里屏蔽字段的差异,返回字段相同的字典
            origin_user_info = response.get("data", "")
            user_info = dict()
            # v1,v2字段相同的部分
            user_info["wx_userid"] = origin_user_info.get("wx_userid", "")
            user_info["language"] = origin_user_info.get("language", "")
            user_info["time_zone"] = origin_user_info.get("time_zone", "")
            user_info["phone"] = origin_user_info.get("phone", "")
            user_info["chname"] = origin_user_info.get("chname", "")
            user_info["email"] = origin_user_info.get("email", "")
            user_info["qq"] = origin_user_info.get("qq", "")
            # v2版本特有的字段
            if settings.DEFAULT_BK_API_VER == "v2":
                user_info["username"] = origin_user_info.get("bk_username", "")
                user_info["role"] = origin_user_info.get("bk_role", "")
            # v1版本特有的字段
            elif settings.DEFAULT_BK_API_VER == "":
                user_info["username"] = origin_user_info.get("username", "")
                user_info["role"] = origin_user_info.get("role", "")
            return True, user_info
        else:
            error_msg = response.get("message", "")
            error_data = response.get("data", "")
            logger.error(u"Failed to Get User Info: error={err}, ret={ret}".format(err=error_msg, ret=error_data,))
            return False, {}

    def authenticate_user(self, bk_token, request):
        session_key = request.session.session_key
        if session_key:
            # 确认 cookie 中的 ticket 和 cache 中的是否一致
            cache_session = cache.get(session_key)
            is_match = cache_session and bk_token == cache_session.get("bk_token")
            if is_match and request.user.is_authenticated:
                return 0
        user = self.get_user_by_bk_token(bk_token)

        return user
