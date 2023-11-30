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

# from django.db import models

# Create your models here.
import copy
from collections import Iterable

from django.db import models
from django.db.models import Q
from django_mysql.models import JSONField

from apps.system_mgmt.constants import DB_NOT_ACTIVATION_ROLE, DB_SUPER_USER
from utils.common_models import MaintainerInfo, TimeInfo, VtypeMixin


class SysRoleManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().exclude(role_name=DB_NOT_ACTIVATION_ROLE)


class SysRole(TimeInfo, MaintainerInfo):
    class Meta:
        verbose_name = "系统角色"

    role_name = models.CharField(max_length=128, unique=True, verbose_name="角色名称")
    describe = models.CharField(max_length=256, default="", null=True, blank=True, verbose_name="角色描述")
    built_in = models.BooleanField(default=False, verbose_name="是否内置(内置不允许修改)")

    objects = SysRoleManager()
    activate_manage = models.Manager()

    def get_ins_summary(self):
        return "{}[角色名称: {}]".format(self._meta.verbose_name, self.role_name)

    @classmethod
    def get_user_roles(cls, username):
        roles = cls.objects.filter(~Q(role_name=DB_SUPER_USER), sysuser__bk_username=username).values_list(
            "role_name", flat=True
        )
        return list(roles)


class SysApps(TimeInfo, MaintainerInfo):
    class Meta:
        verbose_name = "角色资源"

    sys_role = models.ForeignKey(SysRole, on_delete=models.CASCADE)
    app_name = models.CharField(max_length=128, verbose_name="资源名称")
    app_key = models.CharField(max_length=64, verbose_name="资源标识")
    app_ids = JSONField(verbose_name="资源列表")


class SysUser(TimeInfo, MaintainerInfo):
    class Meta:
        verbose_name = "系统用户"

    MAN = 0
    WOMAN = 1
    SEX_CHOICES = ((MAN, "男"), (WOMAN, "女"))

    NORMAL = "NORMAL"
    DISABLED = "DISABLED"
    STATUS_CHOICES = ((NORMAL, "正常"), (DISABLED, "禁用"))

    bk_user_id = models.SmallIntegerField(default=0, verbose_name="用户id(用户管理处的id)")
    bk_username = models.CharField(max_length=128, unique=True, verbose_name="用户名称")
    chname = models.CharField(max_length=128, default="", verbose_name="中文名称")
    phone = models.CharField(max_length=20, verbose_name="电话号码")
    email = models.CharField(max_length=100, verbose_name="邮箱地址")
    sexuality = models.PositiveSmallIntegerField(default=MAN, choices=SEX_CHOICES, verbose_name="性别")
    wx_userid = models.CharField(max_length=200, default="", verbose_name="微信openId")
    local = models.BooleanField(default=True, verbose_name="是否为默认目录用户")
    roles = models.ManyToManyField(SysRole, verbose_name="角色")
    departments = JSONField(default=list, verbose_name="组织架构")
    leader = JSONField(default=list, verbose_name="上级")
    status = models.CharField(max_length=32, default=NORMAL, choices=STATUS_CHOICES, verbose_name="用户状态")

    def get_ins_summary(self):
        return "{}[用户名称: {}, 中文名称: {}]".format(self._meta.verbose_name, self.bk_username, self.chname)

    def copy(self):
        """深拷贝"""
        return copy.deepcopy(self)

    @property
    def username(self) -> str:
        return self.bk_username

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def _super(self):
        """
        判断当前用户是否是weops超管
        """
        if self.bk_username == "admin":
            return True
        is_super = self.roles.filter(role_name=DB_SUPER_USER).exists()
        return is_super


class SysSetting(TimeInfo, MaintainerInfo, VtypeMixin):
    key = models.CharField(verbose_name="设置项", max_length=100, unique=True)
    value = models.TextField(verbose_name="设置值")
    desc = models.CharField(verbose_name="设置描述", max_length=200, default="")

    class Meta:
        verbose_name = "系统设置"

    @property
    def real_value(self):
        try:
            func = self.VTYPE_FIELD_MAPPING.get(self.vtype, self.VTYPE_FIELD_MAPPING[self.DEFAULT])
            value = func().to_python(self.value)
            return value
        except Exception:
            return self.value

    def get_ins_summary(self):
        return "{}[系统设置: {}]".format(self._meta.verbose_name, self.desc)


class UserSysSetting(TimeInfo, VtypeMixin):
    """系统设置"""

    key = models.CharField(max_length=100, verbose_name="key值")
    value = models.TextField(default="", verbose_name="系统设置值")
    desc = models.TextField(verbose_name="描述", blank=True)
    user = models.ForeignKey("SysUser", on_delete=models.CASCADE, db_constraint=False)

    class Meta:
        verbose_name = "用户系统设置"

    @property
    def real_value(self):
        try:
            func = self.VTYPE_FIELD_MAPPING.get(self.vtype, self.VTYPE_FIELD_MAPPING[self.DEFAULT])
            value = func().to_python(self.value)
            return value
        except Exception:
            return self.value

    def get_ins_summary(self):
        return "{}[用户系统设置: {}{}]".format(self._meta.verbose_name, self.user.chname, self.desc)


class OperationLog(models.Model):
    class Meta:
        verbose_name = "使用记录"

    ADD = "add"
    MODIFY = "modify"
    EXEC = "exec"
    DELETE = "delete"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    LOGIN = "login"
    IMPORT = "import"
    EXPORT = "export"
    OPERATE_TYPE_CHOICES = (
        (ADD, "新增"),
        (MODIFY, "修改"),
        (EXEC, "执行"),
        (DELETE, "删除"),
        (DOWNLOAD, "下载"),
        (UPLOAD, "上传"),
        (LOGIN, "登陆"),
    )
    OPERATE_TYPE_DICT = dict(OPERATE_TYPE_CHOICES)

    operator = models.CharField(max_length=128, null=True, db_index=True)  # 操作者
    operate_type = models.CharField(max_length=10, choices=OPERATE_TYPE_CHOICES, db_index=True)  # 操作类型
    created_at = models.DateTimeField("添加时间", auto_now_add=True, db_index=True)
    operate_obj = models.CharField(max_length=200, default="", db_index=True)  # 操作对象
    operate_summary = models.TextField(default="")  # 操作概要
    current_ip = models.CharField(max_length=50, default="127.0.0.1", db_index=True)  # 操作者IP
    app_module = models.CharField(max_length=20, default="", db_index=True)  # 模块
    obj_type = models.CharField(max_length=30, default="", db_index=True)  # 对象类型

    def to_dict(self):
        return_dict = {f.name: getattr(self, f.name) for f in self._meta.fields}
        return_dict["operate_type_display"] = self.get_operate_type_display()
        return return_dict

    @classmethod
    def create_log(cls, operate_instances, operate_type, operator, summary_detail="", **kwargs):
        """批量创建操作日志"""
        create_list = []
        operate_instance_list = operate_instances if isinstance(operate_instances, Iterable) else [operate_instances]
        for operate_instance in operate_instance_list:
            summary_detail = "[详情: %s]" % summary_detail if summary_detail else ""
            operate_summary = "{}{}{}".format(
                cls.OPERATE_TYPE_DICT[operate_type], operate_instance.get_ins_summary(), summary_detail
            )
            # noinspection  PyProtectedMember
            create_list.append(
                cls(
                    operator=operator,
                    operate_type=operate_type,
                    operate_obj=operate_instance._meta.verbose_name,
                    operate_summary=operate_summary,
                    **kwargs
                )
            )

        cls.objects.bulk_create(create_list)


class MenuManage(TimeInfo, MaintainerInfo):
    menu_name = models.CharField(max_length=64, unique=True, help_text="菜单名称")
    default = models.BooleanField(default=False, help_text="是否是内置菜单")
    use = models.BooleanField(default=False, help_text="是否启用(只能有一个)")
    menu = JSONField(help_text="菜单内容")

    class Meta:
        verbose_name = "菜单管理"


class InstancesPermissions(TimeInfo, MaintainerInfo):
    """
    实例(模块任务)权限
    """

    instance_type = models.CharField(max_length=64, help_text="实例类型")
    permissions = JSONField(help_text="权限类型")
    instances = JSONField(default=list, help_text="实例id")
    role = models.ForeignKey(SysRole, on_delete=models.CASCADE)
